package cli

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

type Create struct {
	GroupFilter
	Start int `usage:"Number the first group from here" default:"1"`

	root *Oktapus
}

func (c *Create) Customize(cc *cobra.Command) {
	cc.Use = "create COUNT"
	cc.Short = "Create COUNT groups named <prefix>NNNN"

	// Validating here rather than in Run means a bad COUNT is rejected before the root's
	// PersistentPre authenticates, so a typo costs nothing.
	cc.Args = func(cc *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cc, args); err != nil {
			return err
		}
		if count, err := strconv.Atoi(args[0]); err != nil || count < 1 {
			return fmt.Errorf("COUNT must be a positive number, got %q", args[0])
		}
		return nil
	}
}

func (c *Create) Run(cc *cobra.Command, args []string) error {
	count, _ := strconv.Atoi(args[0]) // already validated by Args
	createGroups(cc.Context(), c.root.client, c.Prefix, count, c.Start, c.root.Workers)

	return nil
}

type List struct {
	GroupFilter

	root *Oktapus
}

func (l *List) Customize(c *cobra.Command) {
	c.Use = "list"
	c.Short = "List groups matching the prefix"
	c.Args = cobra.NoArgs
}

func (l *List) Run(c *cobra.Command, _ []string) error {
	listGroups(c.Context(), l.root.client, l.Prefix)
	return nil
}

type Assign struct {
	GroupFilter

	root *Oktapus
}

func (a *Assign) Customize(c *cobra.Command) {
	c.Use = "assign USER"
	c.Short = "Add a user to every group matching the prefix"
	c.Args = cobra.ExactArgs(1)
}

func (a *Assign) Run(c *cobra.Command, args []string) error {
	user, ok := resolveUser(c.Context(), a.root.client, args[0])
	if !ok {
		return errUserNotResolved
	}

	assignPrefix(c.Context(), a.root.client, user, a.Prefix, a.root.Workers)

	return nil
}

type Remove struct {
	GroupFilter

	root *Oktapus
}

func (r *Remove) Customize(c *cobra.Command) {
	c.Use = "remove USER"
	c.Short = "Remove a user from every group matching the prefix"
	c.Args = cobra.ExactArgs(1)
}

func (r *Remove) Run(c *cobra.Command, args []string) error {
	user, ok := resolveUser(c.Context(), r.root.client, args[0])
	if !ok {
		return errUserNotResolved
	}

	removeFromGroups(c.Context(), r.root.client, user, r.Prefix, r.root.Workers)

	return nil
}

type Groups struct {
	root *Oktapus
}

func (g *Groups) Customize(c *cobra.Command) {
	c.Use = "groups USER"
	c.Short = "Show the groups a user belongs to"
	c.Args = cobra.ExactArgs(1)
}

func (g *Groups) Run(c *cobra.Command, args []string) error {
	user, ok := resolveUser(c.Context(), g.root.client, args[0])
	if !ok {
		return errUserNotResolved
	}

	showUserGroups(c.Context(), g.root.client, user)

	return nil
}

type Limits struct {
	PageSize     int    `usage:"Groups per page; the auth provider uses 200" default:"200"`
	Concurrency  int    `usage:"Group fetches to run in parallel" default:"1"`
	Repeat       int    `usage:"Full fetches to perform; 0 runs until interrupted" default:"1"`
	For          string `usage:"Run for this long instead of a fixed count, e.g. 30s"`
	UntilLimited bool   `usage:"Keep going until Okta returns a 429"`

	root *Oktapus
}

func (l *Limits) Customize(c *cobra.Command) {
	c.Use = "limits USER"
	c.Short = "Measure, or deliberately exhaust, the rate limit on the provider's group fetch"
	c.Long = `Replay the Okta auth provider's own group fetch for a user and report what Okta says
about the rate-limit bucket.

With the defaults this is one quiet fetch, printed page by page. Raising --concurrency, lowering
--page-size, or passing --until-limited drives it hard enough to hit the limit, which is the point:
the provider has no backoff of its own, so a 429 during a login surfaces as a failed group check.

The probe skips the 429 retry the rest of this tool uses, so rejections are observed rather than
absorbed.`
	c.Args = cobra.ExactArgs(1)
}

func (l *Limits) Run(c *cobra.Command, args []string) error {
	cfg := ProbeConfig{
		PageSize:     l.PageSize,
		Concurrency:  l.Concurrency,
		Repeat:       l.Repeat,
		UntilLimited: l.UntilLimited,
	}

	if l.For != "" {
		d, err := time.ParseDuration(l.For)
		if err != nil {
			return fmt.Errorf("invalid --for: %w", err)
		}
		cfg.Duration = d
	}

	// Okta caps this endpoint at 1000 per page; anything larger is rejected by the API rather
	// than clamped, so catch it here.
	switch {
	case cfg.PageSize < 1 || cfg.PageSize > 1000:
		return fmt.Errorf("--page-size must be between 1 and 1000, got %d", cfg.PageSize)
	case cfg.Concurrency < 1:
		return fmt.Errorf("--concurrency must be at least 1, got %d", cfg.Concurrency)
	case cfg.Repeat < 0:
		return fmt.Errorf("--repeat cannot be negative, got %d", cfg.Repeat)
	}

	user, ok := resolveUser(c.Context(), l.root.client, args[0])
	if !ok {
		return errUserNotResolved
	}

	showRateLimits(c.Context(), l.root.client, user, cfg)

	return nil
}

type Delete struct {
	GroupFilter
	Yes bool `usage:"Skip the confirmation prompt"`

	root *Oktapus
}

func (d *Delete) Customize(c *cobra.Command) {
	c.Use = "delete"
	c.Short = "Delete every group matching the prefix"
	c.Args = cobra.NoArgs
}

func (d *Delete) Run(c *cobra.Command, _ []string) error {
	deleteGroups(c.Context(), d.root.client, d.Prefix, d.root.Workers, d.Yes)
	return nil
}

type Menu struct {
	GroupFilter

	root *Oktapus
}

func (m *Menu) Customize(c *cobra.Command) {
	c.Use = "menu"
	c.Short = "Work through the same operations interactively"
	c.Args = cobra.NoArgs
}

func (m *Menu) Run(c *cobra.Command, _ []string) error {
	menu(c.Context(), m.root.client, m.Prefix, m.root.Workers)
	return nil
}

// errUserNotResolved reports a lookup that already explained itself on stdout, so the command exits
// non-zero without printing a second, vaguer message.
var errUserNotResolved = errors.New("no user selected")
