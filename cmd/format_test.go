package cmd

import "testing"

func TestFmtBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{45948080, "43.82 MB"},
		{1 << 30, "1.00 GB"},
	}
	for _, c := range cases {
		if got := fmtBytes(c.in); got != c.want {
			t.Errorf("fmtBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFmtRate(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0 B/s"},
		{0.4, "0 B/s"}, // 低于 1 B/s 视作静止
		{512, "512 B/s"},
		{9.47 * 1024 * 1024, "9.47 MB/s"},
	}
	for _, c := range cases {
		if got := fmtRate(c.in); got != c.want {
			t.Errorf("fmtRate(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
