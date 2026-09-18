package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

// ProbeConfig describes a rate-limit experiment: what shape the provider's group fetch takes, and
// how hard to drive it. The defaults reproduce exactly one provider fetch.
type ProbeConfig struct {
	PageSize     int
	Concurrency  int
	Repeat       int           // full fetches to perform; 0 means keep going
	Duration     time.Duration // stop after this long; 0 means no time limit
	UntilLimited bool          // stop as soon as Okta returns a 429
}

// singleFetch reports whether the config describes one quiet measurement rather than a load run,
// in which case the per-page breakdown is worth printing.
func (cfg ProbeConfig) singleFetch() bool {
	return cfg.Concurrency <= 1 && cfg.Repeat == 1 && cfg.Duration == 0 && !cfg.UntilLimited
}

// probeResult accumulates what an experiment observed across all workers.
type probeResult struct {
	mu sync.Mutex

	fetches   int
	requests  int
	limited   int
	groups    int
	latencies []time.Duration

	limit        int
	minRemaining int
	reset        time.Time
	retryAfter   string

	firstLimitAfter int
	firstLimitAt    time.Duration

	errs    []error
	elapsed time.Duration
}

func (r *probeResult) record(stats []RequestStat, groups int, at time.Duration) (sawLimit bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.fetches++
	r.groups = max(r.groups, groups)

	for _, st := range stats {
		r.requests++
		r.latencies = append(r.latencies, st.Elapsed)

		if st.Limit > r.limit {
			r.limit = st.Limit
		}
		if st.Remaining >= 0 && (r.minRemaining < 0 || st.Remaining < r.minRemaining) {
			r.minRemaining = st.Remaining
		}
		if !st.Reset.IsZero() {
			r.reset = st.Reset
		}

		if st.Limited() {
			sawLimit = true
			r.limited++
			if r.firstLimitAfter == 0 {
				r.firstLimitAfter = r.requests
				r.firstLimitAt = at
				r.retryAfter = st.RetryAfter
			}
		}
	}

	return sawLimit
}

func (r *probeResult) addErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

// runProbe drives the provider's group fetch under the configured load and reports what Okta did.
func runProbe(ctx context.Context, c *Client, user User, cfg ProbeConfig) *probeResult {
	res := &probeResult{limit: -1, minRemaining: -1}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if cfg.Duration > 0 {
		timer := time.AfterFunc(cfg.Duration, cancel)
		defer timer.Stop()
	}

	var (
		claimed atomic.Int64
		wg      sync.WaitGroup
		start   = time.Now()
	)

	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for ctx.Err() == nil {
				// Reserve a fetch up front so workers never overshoot the requested total.
				if cfg.Repeat > 0 && claimed.Add(1) > int64(cfg.Repeat) {
					return
				}

				stats, groups, err := c.FetchUserGroupsOnce(ctx, user.ID, cfg.PageSize)
				sawLimit := res.record(stats, groups, time.Since(start))

				// A 429 arrives as an error too; it is the measurement, not a failure. So is the
				// cancellation the stop conditions cause.
				if err != nil && !sawLimit && !errors.Is(err, context.Canceled) {
					res.addErr(err)
				}

				if sawLimit && cfg.UntilLimited {
					cancel()
					return
				}
			}
		}()
	}

	wg.Wait()
	res.elapsed = time.Since(start)

	return res
}

func showRateLimits(ctx context.Context, c *Client, user User, cfg ProbeConfig) {
	fmt.Printf("\nGET /api/v1/users/{id}/groups?limit=%d for %s", cfg.PageSize, user.label())
	if cfg.PageSize != providerPageSize {
		fmt.Printf("   (the provider uses %d)", providerPageSize)
	}
	fmt.Println()

	if cfg.singleFetch() {
		showSingleFetch(ctx, c, user, cfg)
		return
	}

	fmt.Printf("concurrency %d, %s\n\n", cfg.Concurrency, stopCondition(cfg))

	res := runProbe(ctx, c, user, cfg)
	reportProbe(cfg, res)
}

func stopCondition(cfg ProbeConfig) string {
	switch {
	case cfg.UntilLimited:
		return "running until rate limited"
	case cfg.Duration > 0:
		return "running for " + cfg.Duration.String()
	case cfg.Repeat > 0:
		return fmt.Sprintf("%d fetches", cfg.Repeat)
	default:
		return "running until interrupted"
	}
}

// showSingleFetch prints the per-page breakdown of one fetch, which is legible only because there
// is exactly one of them.
func showSingleFetch(ctx context.Context, c *Client, user User, cfg ProbeConfig) {
	stats, total, err := c.FetchUserGroupsOnce(ctx, user.ID, cfg.PageSize)
	if err != nil {
		fmt.Printf("  failed after %d request(s): %v\n", len(stats), err)
		if len(stats) == 0 {
			return
		}
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  page\tgroups\tlimit\tremaining\tresets in\telapsed")
	for i, st := range stats {
		fmt.Fprintf(w, "  %d\t%d\t%s\t%s\t%s\t%s\n",
			i+1, st.Groups, count(st.Limit), count(st.Remaining), until(st.Reset), st.Elapsed.Round(time.Millisecond))
	}
	w.Flush()

	if len(stats) == 0 {
		return
	}

	last := stats[len(stats)-1]
	fmt.Printf("\n  %d groups over %d request(s)\n", total, len(stats))

	if last.Limit < 0 {
		fmt.Println("  Okta returned no X-Rate-Limit headers for this endpoint")
		return
	}

	fmt.Printf("  bucket allows %d requests per window, %d left, window resets in %s\n",
		last.Limit, last.Remaining, until(last.Reset))

	// The provider fetches a user's groups once per login, so the per-window ceiling on logins is
	// the bucket divided by what one fetch costs.
	fmt.Printf("  one fetch for this user costs %d request(s), so this window has room for about %d more\n",
		len(stats), last.Remaining/len(stats))
	fmt.Printf("  a user in %d groups would cost %d request(s) per login at this page size\n",
		total, pagesFor(total, cfg.PageSize))
}

func reportProbe(cfg ProbeConfig, res *probeResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	rate := float64(res.requests) / res.elapsed.Seconds()
	fmt.Fprintf(w, "  elapsed\t%s\n", res.elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "  fetches\t%d\n", res.fetches)
	fmt.Fprintf(w, "  requests\t%d\t(%.0f/s)\n", res.requests, rate)
	fmt.Fprintf(w, "  429s\t%d\n", res.limited)
	fmt.Fprintf(w, "  groups\t%d\t(%d request(s) per fetch)\n", res.groups, pagesFor(res.groups, cfg.PageSize))

	if p50, p95, hi, ok := percentiles(res.latencies); ok {
		fmt.Fprintf(w, "  latency\tp50 %s\tp95 %s\tmax %s\n",
			p50.Round(time.Millisecond), p95.Round(time.Millisecond), hi.Round(time.Millisecond))
	}

	if res.limit >= 0 {
		fmt.Fprintf(w, "  bucket\t%d per window\n", res.limit)
	}
	if res.minRemaining >= 0 {
		fmt.Fprintf(w, "  low-water\t%d remaining\n", res.minRemaining)
	}
	if !res.reset.IsZero() {
		fmt.Fprintf(w, "  resets in\t%s\n", until(res.reset))
	}
	w.Flush()

	fmt.Println()
	if res.limited == 0 {
		fmt.Printf("  No 429 observed. Raise --concurrency, lower --page-size, or use --until-limited to push harder.\n")
	} else {
		fmt.Printf("  First 429 after %d requests (%s).\n", res.firstLimitAfter, res.firstLimitAt.Round(time.Millisecond))
		if res.retryAfter != "" {
			fmt.Printf("  Okta returned Retry-After: %s\n", res.retryAfter)
		} else {
			fmt.Printf("  Okta returned no Retry-After; the client falls back to X-Rate-Limit-Reset.\n")
		}
		fmt.Printf("  The provider has no backoff of its own, so a login during this window fails the group check.\n")
	}

	reportErrors(res.errs)
}

// percentiles returns p50, p95 and the maximum. It sorts a copy: the caller's slice is the record
// of what happened, in order.
func percentiles(latencies []time.Duration) (p50, p95, hi time.Duration, ok bool) {
	if len(latencies) == 0 {
		return 0, 0, 0, false
	}

	sorted := slices.Clone(latencies)
	slices.Sort(sorted)

	at := func(q float64) time.Duration {
		i := int(q * float64(len(sorted)))
		return sorted[min(i, len(sorted)-1)]
	}

	return at(0.50), at(0.95), sorted[len(sorted)-1], true
}

// pagesFor estimates how many requests a fetch spends on a user in n groups. A cursor cannot tell
// that a full page was the last one, so an exact multiple of the page size costs one extra request
// that comes back empty.
func pagesFor(n, pageSize int) int {
	if pageSize < 1 {
		pageSize = providerPageSize
	}

	pages := (n + pageSize - 1) / pageSize
	if n%pageSize == 0 {
		pages++
	}

	return pages
}

func count(n int) string {
	if n < 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}

func until(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	d := time.Until(t).Round(time.Second)
	if d < 0 {
		d = 0
	}

	return d.String()
}
