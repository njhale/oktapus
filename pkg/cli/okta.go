package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pageSize   = 200
	maxRetries = 5

	// providerPageSize is the page size the Okta auth provider uses for its own group calls
	// (oktaPageSize in okta-auth-provider/pkg/profile/profile.go). The rate-limit probe has to
	// match it, since page size decides how many requests one group fetch costs.
	providerPageSize = 200
)

// requiredScopes are requested on every token. okta.groups.manage covers creating and deleting
// groups and changing their membership; okta.groups.read and okta.users.read cover listing them
// and looking users up. All three must be granted to the app, or the grant fails as invalid_scope.
var requiredScopes = []string{"okta.groups.manage", "okta.groups.read", "okta.users.read"}

type Group struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type,omitempty"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	} `json:"profile"`
}

type User struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login string `json:"login"`
		Email string `json:"email"`
	} `json:"profile"`
}

func (u User) label() string {
	if u.Profile.Email != "" {
		return u.Profile.Email
	}
	return u.Profile.Login
}

// APIError carries what Okta actually said. okta-sdk-golang discards the body of a failed token
// request and reports "Empty access token" instead, which is why this tool talks to the API
// directly rather than through the SDK.
type APIError struct {
	Status  int
	Code    string
	Summary string
	Causes  []string
	Raw     string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("HTTP %d", e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Summary != "" {
		msg += ": " + e.Summary
	}
	if len(e.Causes) > 0 {
		msg += " (" + strings.Join(e.Causes, "; ") + ")"
	}
	if e.Code == "" && e.Summary == "" && e.Raw != "" {
		msg += ": " + e.Raw
	}
	return msg
}

func newAPIError(status int, body []byte) *APIError {
	e := &APIError{Status: status, Raw: strings.TrimSpace(string(body))}

	var parsed struct {
		ErrorCode    string `json:"errorCode"`
		ErrorSummary string `json:"errorSummary"`
		OAuthError   string `json:"error"`
		OAuthDesc    string `json:"error_description"`
		ErrorCauses  []struct {
			ErrorSummary string `json:"errorSummary"`
		} `json:"errorCauses"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		e.Code = cmp(parsed.ErrorCode, parsed.OAuthError)
		e.Summary = cmp(parsed.ErrorSummary, parsed.OAuthDesc)
		for _, c := range parsed.ErrorCauses {
			e.Causes = append(e.Causes, c.ErrorSummary)
		}
	}

	return e
}

func cmp(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

type Client struct {
	orgURL   string
	clientID string
	key      *rsa.PrivateKey
	http     *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func NewClient(orgURL, clientID, keyPEM string) (*Client, error) {
	orgURL = strings.TrimSuffix(strings.TrimSpace(orgURL), "/")

	u, err := url.Parse(orgURL)
	switch {
	case err != nil:
		return nil, fmt.Errorf("org URL %q does not parse: %w", orgURL, err)
	case u.Scheme == "" || u.Host == "":
		return nil, fmt.Errorf("org URL %q needs a scheme and host, e.g. https://your-org.okta.com", orgURL)
	case u.Path != "":
		return nil, fmt.Errorf("org URL %q must have no path: okta.* scopes come from the org authorization server, not a custom one", orgURL)
	}

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	return &Client{
		orgURL:   orgURL,
		clientID: strings.TrimSpace(clientID),
		key:      key,
		http:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// parsePrivateKey accepts PKCS#1 or PKCS#8 PEM, with real newlines or the escaped \n that Obot
// stores in the provider credential.
func parsePrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	keyPEM = strings.TrimSpace(strings.ReplaceAll(keyPEM, `\n`, "\n"))

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("private key is not valid PEM")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, want RSA", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
	}
}

func clientAssertion(key *rsa.PrivateKey, clientID, aud string) (string, error) {
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": strconv.FormatInt(now.UnixNano(), 36),
	})

	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}

	tokenURL := c.orgURL + "/oauth2/v1/token"
	assertion, err := clientAssertion(c.key, c.clientID, tokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to sign client assertion: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", strings.Join(requiredScopes, " "))
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("client_credentials grant failed: %w", newAPIError(resp.StatusCode, body))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("okta returned no access token")
	}

	c.token = tok.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - time.Minute)

	return c.token, nil
}

// send performs one request with no retry policy, returning the status even for failures so
// callers can react to a 429 themselves.
func (c *Client) send(ctx context.Context, method, ref string, payload []byte) (int, []byte, http.Header, error) {
	target := ref
	if !strings.HasPrefix(ref, "http") {
		target = c.orgURL + ref
	}

	tok, err := c.accessToken(ctx)
	if err != nil {
		return 0, nil, nil, err
	}

	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	return resp.StatusCode, body, resp.Header, nil
}

// do is send plus the retry policy every ordinary call wants: back off and try again on a 429.
func (c *Client) do(ctx context.Context, method, ref string, body any) ([]byte, http.Header, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, nil, err
		}
	}

	for attempt := 0; ; attempt++ {
		status, respBody, hdr, err := c.send(ctx, method, ref, payload)
		if err != nil {
			return nil, nil, err
		}

		if status == http.StatusTooManyRequests && attempt < maxRetries {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(rateLimitWait(hdr, attempt)):
			}
			continue
		}

		if status >= 300 {
			return nil, hdr, newAPIError(status, respBody)
		}

		return respBody, hdr, nil
	}
}

func rateLimitWait(h http.Header, attempt int) time.Duration {
	if v := h.Get("X-Rate-Limit-Reset"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(sec, 0)); d > 0 && d < 2*time.Minute {
				return d + time.Second
			}
		}
	}
	if v := h.Get("Retry-After"); v != "" {
		if sec, err := strconv.Atoi(v); err == nil && sec > 0 {
			return time.Duration(sec)*time.Second + time.Second
		}
	}

	return time.Duration(1<<attempt) * time.Second
}

var nextLinkRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		if m := nextLinkRe.FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// listAll walks Okta's Link-header cursor to the end. limit caps the result; 0 means no cap.
func listAll[T any](ctx context.Context, c *Client, path string, limit int) ([]T, error) {
	var all []T

	for next := path; next != ""; {
		body, hdr, err := c.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}

		var page []T
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("failed to decode response from %s: %w", path, err)
		}
		if len(page) == 0 {
			break
		}

		all = append(all, page...)
		if limit > 0 && len(all) >= limit {
			return all[:limit], nil
		}

		next = nextLink(hdr)
	}

	return all, nil
}

func (c *Client) CreateGroup(ctx context.Context, name, description string) (Group, error) {
	var payload Group
	payload.Profile.Name = name
	payload.Profile.Description = description

	body, _, err := c.do(ctx, http.MethodPost, "/api/v1/groups", payload)
	if err != nil {
		return Group{}, err
	}

	var created Group
	if err := json.Unmarshal(body, &created); err != nil {
		return Group{}, fmt.Errorf("failed to decode created group: %w", err)
	}

	return created, nil
}

// GroupsByPrefix returns every group whose name starts with prefix, following the cursor to the
// end. An empty prefix lists the whole org.
//
// The filter is search rather than q. Okta caps q at 200 matches and sends no cursor along with
// them, so any prefix covering more groups than that came back truncated with nothing to say it
// had been -- a bulk assign would quietly reach the first 200 and stop. search paginates like the
// rest of the API.
//
// The catch is that search reads an index that lags writes by a few seconds, so groups created
// moments earlier may not be here yet. Give a create a moment to settle before assigning against
// it.
func (c *Client) GroupsByPrefix(ctx context.Context, prefix string) ([]Group, error) {
	path := fmt.Sprintf("/api/v1/groups?limit=%d", pageSize)
	if prefix != "" {
		path += "&search=" + url.QueryEscape(fmt.Sprintf("profile.name sw %q", prefix))
	}

	groups, err := listAll[Group](ctx, c, path, 0)
	if err != nil {
		return nil, err
	}

	// search is a starts-with match on Okta's side, but re-filter locally so callers can trust
	// that every group returned really carries the prefix.
	filtered := groups[:0]
	for _, g := range groups {
		if strings.HasPrefix(g.Profile.Name, prefix) {
			filtered = append(filtered, g)
		}
	}

	return filtered, nil
}

func (c *Client) DeleteGroup(ctx context.Context, groupID string) error {
	_, _, err := c.do(ctx, http.MethodDelete, "/api/v1/groups/"+url.PathEscape(groupID), nil)
	return err
}

func (c *Client) AddMember(ctx context.Context, groupID, userID string) error {
	_, _, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/api/v1/groups/%s/users/%s", url.PathEscape(groupID), url.PathEscape(userID)), nil)
	return err
}

func (c *Client) RemoveMember(ctx context.Context, groupID, userID string) error {
	_, _, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/groups/%s/users/%s", url.PathEscape(groupID), url.PathEscape(userID)), nil)
	return err
}

func (c *Client) UserGroups(ctx context.Context, userID string) ([]Group, error) {
	return listAll[Group](ctx, c, fmt.Sprintf("/api/v1/users/%s/groups?limit=%d", url.PathEscape(userID), pageSize), 0)
}

// FindUsers resolves a user ID directly, or searches by name and email prefix.
func (c *Client) FindUsers(ctx context.Context, q string) ([]User, error) {
	q = strings.TrimSpace(q)

	if strings.HasPrefix(q, "00u") && !strings.Contains(q, "@") {
		body, _, err := c.do(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(q), nil)
		if err != nil {
			return nil, err
		}

		var u User
		if err := json.Unmarshal(body, &u); err != nil {
			return nil, fmt.Errorf("failed to decode user: %w", err)
		}

		return []User{u}, nil
	}

	return listAll[User](ctx, c, fmt.Sprintf("/api/v1/users?limit=%d&q=%s", pageSize, url.QueryEscape(q)), 50)
}

// RequestStat is one HTTP call's outcome plus what Okta said about the rate-limit bucket it came
// out of. Okta reports bucket state on every response, so these numbers are measured.
type RequestStat struct {
	Status     int
	Groups     int
	Limit      int // X-Rate-Limit-Limit: requests allowed per window
	Remaining  int // X-Rate-Limit-Remaining: requests left in this window
	Reset      time.Time
	RetryAfter string
	Elapsed    time.Duration
}

// Limited reports whether Okta rejected this request for exceeding the rate limit.
func (r RequestStat) Limited() bool {
	return r.Status == http.StatusTooManyRequests
}

// FetchUserGroupsOnce walks a user's group memberships the way the Okta auth provider does --
// GET /api/v1/users/{id}/groups, following the Link cursor to the end, the same shape as
// FetchUserGroupInfos -- and returns one RequestStat per HTTP call.
//
// It deliberately skips the 429 retry that do() applies: a caller measuring rate limits needs to
// see the rejection rather than have it absorbed. pageSize is a parameter rather than a constant so
// the cost of the provider's own choice can be compared against alternatives.
func (c *Client) FetchUserGroupsOnce(ctx context.Context, userID string, pageSize int) ([]RequestStat, int, error) {
	var (
		stats []RequestStat
		total int
	)

	next := fmt.Sprintf("/api/v1/users/%s/groups?limit=%d", url.PathEscape(userID), pageSize)
	for next != "" {
		start := time.Now()
		status, body, hdr, err := c.send(ctx, http.MethodGet, next, nil)
		elapsed := time.Since(start)
		if err != nil {
			return stats, total, err
		}

		stat := RequestStat{
			Status:     status,
			Limit:      headerInt(hdr, "X-Rate-Limit-Limit"),
			Remaining:  headerInt(hdr, "X-Rate-Limit-Remaining"),
			Reset:      headerTime(hdr, "X-Rate-Limit-Reset"),
			RetryAfter: hdr.Get("Retry-After"),
			Elapsed:    elapsed,
		}

		if status >= 300 {
			stats = append(stats, stat)
			return stats, total, newAPIError(status, body)
		}

		var page []Group
		if err := json.Unmarshal(body, &page); err != nil {
			return stats, total, fmt.Errorf("failed to decode user groups: %w", err)
		}

		stat.Groups = len(page)
		stats = append(stats, stat)
		total += len(page)

		if len(page) == 0 {
			break
		}

		next = nextLink(hdr)
	}

	return stats, total, nil
}

func headerInt(h http.Header, name string) int {
	n, err := strconv.Atoi(h.Get(name))
	if err != nil {
		return -1
	}
	return n
}

func headerTime(h http.Header, name string) time.Time {
	sec, err := strconv.ParseInt(h.Get(name), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}
