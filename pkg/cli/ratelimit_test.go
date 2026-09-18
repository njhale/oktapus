package cli

import (
	"testing"
	"time"
)

func TestPagesFor(t *testing.T) {
	tests := []struct {
		name     string
		groups   int
		pageSize int
		want     int
	}{
		{
			name:     "no groups still costs one request",
			groups:   0,
			pageSize: 200,
			want:     1,
		},
		{
			name:     "partial page",
			groups:   50,
			pageSize: 200,
			want:     1,
		},
		{
			name:     "exactly one page costs a trailing empty request",
			groups:   200,
			pageSize: 200,
			want:     2,
		},
		{
			name:     "one page plus a remainder",
			groups:   250,
			pageSize: 200,
			want:     2,
		},
		{
			name:     "a smaller page size costs more requests",
			groups:   250,
			pageSize: 25,
			want:     11,
		},
		{
			name:     "a page size of one costs a request per group",
			groups:   10,
			pageSize: 1,
			want:     11,
		},
		{
			name:     "an unset page size falls back to the provider's",
			groups:   250,
			pageSize: 0,
			want:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pagesFor(tt.groups, tt.pageSize); got != tt.want {
				t.Errorf("pagesFor(%d, %d) = %d, want %d", tt.groups, tt.pageSize, got, tt.want)
			}
		})
	}
}

func TestPercentiles(t *testing.T) {
	tests := []struct {
		name      string
		latencies []time.Duration
		wantOK    bool
		wantP50   time.Duration
		wantMax   time.Duration
	}{
		{
			name:      "no samples",
			latencies: nil,
			wantOK:    false,
		},
		{
			name:      "one sample",
			latencies: []time.Duration{5 * time.Millisecond},
			wantOK:    true,
			wantP50:   5 * time.Millisecond,
			wantMax:   5 * time.Millisecond,
		},
		{
			name: "unsorted input does not disturb the caller's order",
			latencies: []time.Duration{
				9 * time.Millisecond,
				1 * time.Millisecond,
				5 * time.Millisecond,
				3 * time.Millisecond,
			},
			wantOK:  true,
			wantP50: 5 * time.Millisecond,
			wantMax: 9 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]time.Duration(nil), tt.latencies...)

			p50, _, hi, ok := percentiles(input)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if p50 != tt.wantP50 {
				t.Errorf("p50 = %s, want %s", p50, tt.wantP50)
			}
			if hi != tt.wantMax {
				t.Errorf("max = %s, want %s", hi, tt.wantMax)
			}

			// The caller keeps its slice as the record of what happened, in order.
			for i := range input {
				if input[i] != tt.latencies[i] {
					t.Fatalf("percentiles reordered the input at %d: got %s, want %s", i, input[i], tt.latencies[i])
				}
			}
		})
	}
}
