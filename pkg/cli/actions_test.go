package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunConcurrent(t *testing.T) {
	tests := []struct {
		name         string
		n            int
		workers      int
		err          error
		wantOK       int
		wantAttempts int // 0 means "fewer than n", i.e. the run stopped early
	}{
		{
			name:         "all succeed",
			n:            50,
			workers:      4,
			err:          nil,
			wantOK:       50,
			wantAttempts: 50,
		},
		{
			name:         "forbidden halts the run",
			n:            50,
			workers:      4,
			err:          &APIError{Status: http.StatusForbidden, Code: "E0000006"},
			wantOK:       0,
			wantAttempts: 0,
		},
		{
			name:         "other errors do not halt the run",
			n:            50,
			workers:      4,
			err:          &APIError{Status: http.StatusConflict, Code: "E0000001"},
			wantOK:       0,
			wantAttempts: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int64
			ok, errs := runConcurrent(context.Background(), tt.n, tt.workers, "tested", func(context.Context, int) error {
				attempts.Add(1)
				return tt.err
			})

			if ok != tt.wantOK {
				t.Errorf("ok = %d, want %d", ok, tt.wantOK)
			}
			if got := int(attempts.Load()); tt.wantAttempts == 0 {
				if got >= tt.n {
					t.Errorf("attempts = %d, want fewer than %d", got, tt.n)
				}
			} else if got != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", got, tt.wantAttempts)
			}
			if tt.err != nil && len(errs) == 0 {
				t.Error("expected errors, got none")
			}
		})
	}
}

// TestGroupsByPrefixPaginates covers the two things that decide whether a bulk assign reaches
// every group: the request has to carry a filter Okta paginates, and the cursor has to be followed
// to the end. Both are checked, because either one alone still stops at 200 -- q sends no cursor
// to follow, and a followed cursor on a capped filter runs out after the first page.
func TestGroupsByPrefixPaginates(t *testing.T) {
	// 503 is deliberately not a multiple of the page size, so the run ends on a short page rather
	// than an empty one and a cursor dropped at the last hop would show up as missing groups.
	const (
		prefix = "obot-test-"
		total  = 503
	)

	// Stands in for Okta's group list, paging on ?after= the way the real cursor does.
	var paths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.String())

		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		end := min(after+pageSize, total)

		page := make([]Group, 0, end-after)
		for i := after; i < end; i++ {
			var g Group
			g.ID = fmt.Sprintf("id-%04d", i)
			g.Profile.Name = fmt.Sprintf("%s%04d", prefix, i)
			page = append(page, g)
		}

		// More to come, so hand back a cursor. The last page carries no Link, which is what stops
		// the walk.
		if end < total {
			next := *r.URL
			q := next.Query()
			q.Set("after", strconv.Itoa(end))
			next.RawQuery = q.Encode()
			w.Header().Set("Link", fmt.Sprintf(`<%s%s>; rel="next"`, "http://"+r.Host, next.RequestURI()))
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()

	// Seed a live token so accessToken returns early instead of trying to sign an assertion with
	// a key this client doesn't have.
	c := &Client{
		orgURL:   srv.URL,
		http:     srv.Client(),
		token:    "test-token",
		tokenExp: time.Now().Add(time.Hour),
	}

	groups, err := c.GroupsByPrefix(context.Background(), prefix)
	if err != nil {
		t.Fatalf("GroupsByPrefix: %v", err)
	}

	if len(groups) != total {
		t.Errorf("got %d groups, want %d", len(groups), total)
	}

	if len(paths) == 0 {
		t.Fatal("no requests made")
	}
	first, err := url.Parse(paths[0])
	if err != nil {
		t.Fatalf("parse %q: %v", paths[0], err)
	}
	if q := first.Query(); q.Get("q") != "" {
		t.Errorf("request used q=%q, which Okta caps at 200 and does not paginate", q.Get("q"))
	} else if want := `profile.name sw "` + prefix + `"`; q.Get("search") != want {
		t.Errorf("search = %q, want %q", q.Get("search"), want)
	}
}
