package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that also understands the day and week suffixes
// used in the config file ("30d", "2w"), which time.ParseDuration rejects.
type Duration time.Duration

// ParseDuration parses "30d", "2w", "90m", "1h30m" and everything else
// time.ParseDuration accepts.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	// Split off a leading run of <number><d|w> units, then hand the rest to
	// the standard parser so "1w12h" keeps working.
	var total time.Duration
	rest := s
	for {
		i := 0
		for i < len(rest) && (rest[i] >= '0' && rest[i] <= '9' || rest[i] == '.') {
			i++
		}
		if i == 0 || i >= len(rest) {
			break
		}
		var unit time.Duration
		switch rest[i] {
		case 'd':
			unit = 24 * time.Hour
		case 'w':
			unit = 7 * 24 * time.Hour
		default:
			unit = 0
		}
		if unit == 0 {
			break
		}
		n, err := strconv.ParseFloat(rest[:i], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		total += time.Duration(n * float64(unit))
		rest = rest[i+1:]
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		total += d
	}
	return total, nil
}

// UnmarshalYAML accepts both "30d" and a plain number of seconds.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		parsed, err := ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var secs float64
	if err := unmarshal(&secs); err != nil {
		return fmt.Errorf("duration must be a string like \"30d\" or a number of seconds")
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Or returns d, or fallback when d is zero.
func (d Duration) Or(fallback time.Duration) time.Duration {
	if d == 0 {
		return fallback
	}
	return time.Duration(d)
}

// String prints whole days and weeks the way they were written in the config,
// so "retention 30d" does not read back as "720h0m0s".
func (d Duration) String() string {
	v := time.Duration(d)
	switch {
	case v == 0:
		return "0s"
	case v%(7*24*time.Hour) == 0 && v >= 7*24*time.Hour:
		return strconv.FormatInt(int64(v/(7*24*time.Hour)), 10) + "w"
	case v%(24*time.Hour) == 0:
		return strconv.FormatInt(int64(v/(24*time.Hour)), 10) + "d"
	default:
		return v.String()
	}
}
