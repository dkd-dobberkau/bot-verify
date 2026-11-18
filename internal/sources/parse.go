// Package sources fetches and parses the IP lists bot operators publish.
package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrNoPrefixes means a source parsed but listed nothing. An operator does
// not empty its list on purpose, so this is treated as a failed fetch.
var ErrNoPrefixes = errors.New("source contains no prefixes")

// Shortest accepted prefixes. Anything broader is an operator mistake that
// would confirm huge parts of the internet as one bot.
const (
	minIPv4Bits = 8
	minIPv6Bits = 16
)

// MaxPrefixes caps one source's list. The largest real list had 486 entries
// (2026-11-17); the cap bounds memory and per-request scans without the 5 MiB
// body limit having to do it.
const MaxPrefixes = 50_000

// Parser turns a source body into masked prefixes.
type Parser func(body []byte) ([]netip.Prefix, error)

var parsers = map[string]Parser{
	// {"prefixes":[{"ipv4Prefix":"…"},{"ipv6Prefix":"…"}]}, the shape Google
	// introduced and OpenAI, Anthropic, Bing, Apple and others copied.
	"google-prefixes": parseGooglePrefixes,
	// One IP or CIDR per line; blank lines and # comments are skipped.
	"cidr-lines": parseCIDRLines,
}

// ParserFor returns the parser for a format name used in bots.yaml.
func ParserFor(format string) (Parser, bool) {
	parse, ok := parsers[format]
	return parse, ok
}

// KnownFormat reports whether a format has a parser.
func KnownFormat(format string) bool {
	_, ok := parsers[format]
	return ok
}

func parseGooglePrefixes(body []byte) ([]netip.Prefix, error) {
	var doc struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("google-prefixes: %w", err)
	}
	out := make([]netip.Prefix, 0, len(doc.Prefixes))
	for i, entry := range doc.Prefixes {
		text := entry.IPv4 + entry.IPv6
		if entry.IPv4 != "" && entry.IPv6 != "" {
			return nil, fmt.Errorf("google-prefixes: entry %d has both ipv4Prefix and ipv6Prefix", i)
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("google-prefixes: entry %d: %w", i, err)
		}
		prefix, err = acceptPrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("google-prefixes: entry %d: %w", i, err)
		}
		out = append(out, prefix)
	}
	return nonEmpty(out)
}

func parseCIDRLines(body []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for n, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := parseIPOrPrefix(line)
		if err != nil {
			return nil, fmt.Errorf("cidr-lines: line %d: %w", n+1, err)
		}
		prefix, err = acceptPrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("cidr-lines: line %d: %w", n+1, err)
		}
		out = append(out, prefix)
	}
	return nonEmpty(out)
}

func parseIPOrPrefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		return netip.ParsePrefix(text)
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Unmap().Prefix(addr.Unmap().BitLen())
}

// acceptPrefix normalises an IPv4-mapped IPv6 prefix to IPv4, so the IPv4
// breadth limit applies to it and it matches the unmapped addresses Verify
// queries, then checks breadth and masks the host bits.
func acceptPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("prefix %s reaches beyond the IPv4-mapped range", prefix)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	if err := checkBreadth(prefix); err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}

func checkBreadth(prefix netip.Prefix) error {
	minBits := minIPv6Bits
	if prefix.Addr().Is4() {
		minBits = minIPv4Bits
	}
	if prefix.Bits() < minBits {
		return fmt.Errorf("prefix %s is broader than /%d", prefix, minBits)
	}
	return nil
}

func nonEmpty(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	switch {
	case len(prefixes) == 0:
		return nil, ErrNoPrefixes
	case len(prefixes) > MaxPrefixes:
		return nil, fmt.Errorf("source lists %d prefixes, more than %d", len(prefixes), MaxPrefixes)
	}
	return prefixes, nil
}
