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
		out = append(out, prefix.Masked())
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
		out = append(out, prefix)
	}
	return nonEmpty(out)
}

func parseIPOrPrefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		return prefix.Masked(), err
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Unmap().Prefix(addr.Unmap().BitLen())
}

func nonEmpty(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	if len(prefixes) == 0 {
		return nil, ErrNoPrefixes
	}
	return prefixes, nil
}
