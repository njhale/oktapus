package cli

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
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
