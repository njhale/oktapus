package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

func menu(ctx context.Context, c *Client, prefix string, workers int) {
	for ctx.Err() == nil {
		fmt.Printf(`
  1) Create groups
  2) List groups by prefix
  3) Assign groups to a user
  4) Show a user's groups
  5) Remove a user from groups
  6) Delete groups by prefix
  7) Rate limits for a user's group fetch
  q) Quit
`)

		switch strings.ToLower(ask("Choose", "")) {
		case "1":
			prefix = ask("Group name prefix", prefix)
			count := askInt("How many groups", 10)
			start := askInt("Start numbering at", 1)
			createGroups(ctx, c, prefix, count, start, workers)
		case "2":
			prefix = ask("Group name prefix", prefix)
			listGroups(ctx, c, prefix)
		case "3":
			user, ok := resolveUser(ctx, c, ask("User email or ID", ""))
			if !ok {
				continue
			}
			prefix = ask("Group name prefix", prefix)
			assignPrefix(ctx, c, user, prefix, workers)
		case "4":
			if user, ok := resolveUser(ctx, c, ask("User email or ID", "")); ok {
				showUserGroups(ctx, c, user)
			}
		case "5":
			user, ok := resolveUser(ctx, c, ask("User email or ID", ""))
			if !ok {
				continue
			}
			prefix = ask("Group name prefix", prefix)
			removeFromGroups(ctx, c, user, prefix, workers)
		case "6":
			prefix = ask("Group name prefix", prefix)
			deleteGroups(ctx, c, prefix, workers, false)
		case "7":
			if user, ok := resolveUser(ctx, c, ask("User email or ID", "")); ok {
				cfg := ProbeConfig{
					PageSize:    askInt("Page size", providerPageSize),
					Concurrency: askInt("Parallel fetches", 1),
					Repeat:      askInt("Fetches to run (0 runs until interrupted)", 1),
				}
				cfg.UntilLimited = confirm("Stop at the first 429")
				showRateLimits(ctx, c, user, cfg)
			}
		case "q", "quit", "exit":
			return
		default:
			fmt.Println("  pick 1-7 or q")
		}
	}
}

func createGroups(ctx context.Context, c *Client, prefix string, count, start, workers int) {
	if count <= 0 {
		return
	}

	fmt.Printf("Creating %d groups, %s%04d through %s%04d\n", count, prefix, start, prefix, start+count-1)

	var (
		mu      sync.Mutex
		skipped int
	)
	ok, errs := runConcurrent(ctx, count, workers, "created", func(ctx context.Context, i int) error {
		_, err := c.CreateGroup(ctx, fmt.Sprintf("%s%04d", prefix, start+i), "created by okta-group-tool")

		// A name that already exists means a previous run made it, so re-running is idempotent.
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
			mu.Lock()
			skipped++
			mu.Unlock()
			return nil
		}

		return err
	})

	fmt.Printf("  %d created", ok-skipped)
	if skipped > 0 {
		fmt.Printf(", %d already existed", skipped)
	}
	fmt.Println()
	reportErrors(errs)
}

func listGroups(ctx context.Context, c *Client, prefix string) {
	groups, err := c.GroupsByPrefix(ctx, prefix)
	if err != nil {
		fmt.Printf("  failed to list groups: %v\n", err)
		return
	}

	fmt.Printf("  %d groups match %q\n", len(groups), prefix)
	for i, g := range groups {
		if i == 10 {
			fmt.Printf("  ... and %d more\n", len(groups)-10)
			break
		}
		fmt.Printf("  %-40s %s\n", g.Profile.Name, g.ID)
	}
}

func assignPrefix(ctx context.Context, c *Client, user User, prefix string, workers int) {
	groups, err := c.GroupsByPrefix(ctx, prefix)
	if err != nil {
		fmt.Printf("  failed to list groups: %v\n", err)
		return
	}
	if len(groups) == 0 {
		fmt.Printf("  no groups match %q\n", prefix)
		return
	}

	fmt.Printf("Assigning %d groups to %s\n", len(groups), user.label())
	ok, errs := runConcurrent(ctx, len(groups), workers, "assigned", func(ctx context.Context, i int) error {
		return c.AddMember(ctx, groups[i].ID, user.ID)
	})

	fmt.Printf("  %d assigned\n", ok)
	reportErrors(errs)
}

func removeFromGroups(ctx context.Context, c *Client, user User, prefix string, workers int) {
	groups, err := c.GroupsByPrefix(ctx, prefix)
	if err != nil {
		fmt.Printf("  failed to list groups: %v\n", err)
		return
	}
	if len(groups) == 0 {
		fmt.Printf("  no groups match %q\n", prefix)
		return
	}

	fmt.Printf("Removing %s from %d groups\n", user.label(), len(groups))
	ok, errs := runConcurrent(ctx, len(groups), workers, "removed", func(ctx context.Context, i int) error {
		return c.RemoveMember(ctx, groups[i].ID, user.ID)
	})

	fmt.Printf("  %d removed\n", ok)
	reportErrors(errs)
}

func showUserGroups(ctx context.Context, c *Client, user User) {
	groups, err := c.UserGroups(ctx, user.ID)
	if err != nil {
		fmt.Printf("  failed to list user groups: %v\n", err)
		return
	}

	fmt.Printf("  %s belongs to %d groups\n", user.label(), len(groups))
	for i, g := range groups {
		if i == 10 {
			fmt.Printf("  ... and %d more\n", len(groups)-10)
			break
		}
		fmt.Printf("  %-40s %s\n", g.Profile.Name, g.ID)
	}
}

func deleteGroups(ctx context.Context, c *Client, prefix string, workers int, skipConfirm bool) {
	if strings.TrimSpace(prefix) == "" {
		fmt.Println("  refusing to delete with an empty prefix")
		return
	}

	groups, err := c.GroupsByPrefix(ctx, prefix)
	if err != nil {
		fmt.Printf("  failed to list groups: %v\n", err)
		return
	}

	// Only ever delete groups this tool could have made. Built-in and app-sourced groups are
	// not ours to remove, whatever they happen to be called.
	var target []Group
	for _, g := range groups {
		if g.Type == "OKTA_GROUP" && g.Profile.Name != "Everyone" {
			target = append(target, g)
		}
	}
	if len(target) == 0 {
		fmt.Printf("  no deletable groups match %q\n", prefix)
		return
	}

	fmt.Printf("  %d groups match %q, starting with %s\n", len(target), prefix, target[0].Profile.Name)
	if !skipConfirm && !confirm(fmt.Sprintf("Permanently delete all %d", len(target))) {
		fmt.Println("  cancelled")
		return
	}

	ok, errs := runConcurrent(ctx, len(target), workers, "deleted", func(ctx context.Context, i int) error {
		return c.DeleteGroup(ctx, target[i].ID)
	})

	fmt.Printf("  %d deleted\n", ok)
	reportErrors(errs)
}

func resolveUser(ctx context.Context, c *Client, query string) (User, bool) {
	if strings.TrimSpace(query) == "" {
		return User{}, false
	}

	users, err := c.FindUsers(ctx, query)
	if err != nil {
		fmt.Printf("  failed to find user: %v\n", err)
		return User{}, false
	}

	switch len(users) {
	case 0:
		fmt.Printf("  no user matches %q\n", query)
		return User{}, false
	case 1:
		return users[0], true
	}

	for i, u := range users {
		fmt.Printf("  %2d) %-40s %s %s\n", i+1, u.label(), u.ID, u.Status)
	}
	choice := askInt("Which user", 1)
	if choice < 1 || choice > len(users) {
		fmt.Println("  out of range")
		return User{}, false
	}

	return users[choice-1], true
}

// runConcurrent applies fn to indices 0..n-1 over a pool of workers, printing progress as it goes.
func runConcurrent(ctx context.Context, n, workers int, verb string, fn func(context.Context, int) error) (int, []error) {
	if workers < 1 {
		workers = 1
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		ok     int
		errs   []error
		halted bool
	)

	progress := func() {
		if len(errs) > 0 {
			fmt.Printf("\r  %s %d/%d, %d failed", verb, ok, n, len(errs))
		} else {
			fmt.Printf("\r  %s %d/%d", verb, ok, n)
		}
	}

	jobs := make(chan int)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				err := fn(ctx, i)

				mu.Lock()
				if err != nil {
					errs = append(errs, err)
					halted = halted || denied(err)
				} else {
					ok++
				}
				if done := ok + len(errs); done%10 == 0 || done == n || halted {
					progress()
				}
				mu.Unlock()
			}
		}()
	}

	for i := range n {
		mu.Lock()
		stop := halted
		mu.Unlock()
		if stop {
			break
		}

		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			fmt.Println()
			return ok, append(errs, ctx.Err())
		case jobs <- i:
		}
	}

	close(jobs)
	wg.Wait()
	fmt.Println()

	if halted {
		fmt.Println("  stopped early: the credential is not permitted to do this, so the rest would fail the same way.")
		fmt.Println("  Creating and deleting groups needs Organization Administrator or Super Administrator on the")
		fmt.Println("  API Services app. Group Administrator only covers membership and will fail here.")
	}

	return ok, errs
}

// denied reports whether err is an authorization failure. Those do not fix themselves on the next
// item, so a bulk run abandons the remaining work rather than repeating the same rejection.
func denied(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && (apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden)
}

// reportErrors prints a few distinct failures rather than one line per item, since a bulk run that
// goes wrong usually goes wrong the same way every time.
func reportErrors(errs []error) {
	if len(errs) == 0 {
		return
	}

	fmt.Printf("  %d failed\n", len(errs))

	seen := make(map[string]int, len(errs))
	for _, err := range errs {
		seen[err.Error()]++
	}

	shown := 0
	for msg, count := range seen {
		if shown == 3 {
			fmt.Printf("  ... and %d other distinct errors\n", len(seen)-shown)
			break
		}
		fmt.Printf("  [%dx] %s\n", count, msg)
		shown++
	}
}

var stdin = bufio.NewReader(os.Stdin)

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}

	line, err := stdin.ReadString('\n')
	if err != nil {
		return def
	}
	if line = strings.TrimSpace(line); line == "" {
		return def
	}

	return line
}

func askInt(prompt string, def int) int {
	for {
		n, err := strconv.Atoi(ask(prompt, strconv.Itoa(def)))
		if err == nil && n >= 0 {
			return n
		}
		fmt.Println("  enter a number")
	}
}

func confirm(prompt string) bool {
	return strings.EqualFold(ask(prompt+"? type yes", "no"), "yes")
}
