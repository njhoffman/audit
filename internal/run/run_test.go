package run

import (
	"testing"
	"time"
)

func TestFreshnessOf(t *testing.T) {
	h := time.Hour
	cases := []struct {
		age, warn, old time.Duration
		want           Freshness
	}{
		{time.Minute, 24 * h, 168 * h, Fresh},
		{24 * h, 24 * h, 168 * h, Stale},
		{100 * h, 24 * h, 168 * h, Stale},
		{168 * h, 24 * h, 168 * h, Old},
		{1000 * h, 0, 0, Fresh},
		{1000 * h, 0, 168 * h, Old},
		{30 * h, 24 * h, 0, Stale},
	}
	for _, c := range cases {
		if got := FreshnessOf(c.age, c.warn, c.old); got != c.want {
			t.Errorf("FreshnessOf(%s, %s, %s) = %d, want %d", c.age, c.warn, c.old, got, c.want)
		}
	}
}

func TestHumanAge(t *testing.T) {
	h := time.Hour
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		5 * time.Minute:  "5m",
		3 * h:            "3h",
		47 * h:           "47h",
		48 * h:           "2d",
		13 * 24 * h:      "13d",
		21 * 24 * h:      "3w",
	} {
		if got := HumanAge(d); got != want {
			t.Errorf("HumanAge(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestAgo(t *testing.T) {
	if got := Ago(10 * time.Second); got != "just now" {
		t.Errorf("got %q", got)
	}
	if got := Ago(3 * time.Hour); got != "3h ago" {
		t.Errorf("got %q", got)
	}
}
