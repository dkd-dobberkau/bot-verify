// Package catalog loads bots.yaml: every known bot and how its operator says
// a request from it can be verified.
package catalog

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// IDPattern is the shape of a bot id, shared with the HTTP API's input check.
var IDPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

var suffixPattern = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

// IPSource is one published IP list and the parser that reads it.
type IPSource struct {
	URL    string `yaml:"url"`
	Format string `yaml:"format"`
}

// Bot is one catalog entry. A bot is either checkable (IP sources and/or
// reverse-DNS suffixes) or carries the reason it is not.
type Bot struct {
	ID           string     `yaml:"id"`
	Name         string     `yaml:"name"`
	UATokens     []string   `yaml:"ua_tokens"`
	IPSources    []IPSource `yaml:"ip_sources"`
	RDNSSuffixes []string   `yaml:"rdns_suffixes"`
	NotCheckable string     `yaml:"not_checkable"`
	Docs         string     `yaml:"docs"`
}

// Checkable reports whether the operator publishes anything to verify against.
func (b Bot) Checkable() bool {
	return len(b.IPSources) > 0 || len(b.RDNSSuffixes) > 0
}

// Catalog is the validated content of bots.yaml.
type Catalog struct {
	Bots []Bot `yaml:"bots"`
	byID map[string]int
}

// Get returns the bot with the given id.
func (c *Catalog) Get(id string) (Bot, bool) {
	i, ok := c.byID[id]
	if !ok {
		return Bot{}, false
	}
	return c.Bots[i], true
}

// Load reads and validates a catalog file. knownFormats reports whether a
// source format has a parser; it is passed in so this package does not
// depend on the parsers.
func Load(path string, knownFormats func(string) bool) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var cat Catalog
	if err := yaml.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse catalog %s: %w", path, err)
	}
	cat.byID = make(map[string]int, len(cat.Bots))
	var errs []error
	for i := range cat.Bots {
		bot := &cat.Bots[i]
		if err := validate(bot, knownFormats); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := cat.byID[bot.ID]; dup {
			errs = append(errs, fmt.Errorf("bot %q: duplicate id", bot.ID))
			continue
		}
		cat.byID[bot.ID] = i
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("catalog %s: %w", path, errors.Join(errs...))
	}
	return &cat, nil
}

// validate checks one entry and normalises its suffixes (trailing dot removed).
func validate(bot *Bot, knownFormats func(string) bool) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("bot %q: %s", bot.ID, fmt.Sprintf(format, args...))
	}
	if !IDPattern.MatchString(bot.ID) {
		return fail("id must match %s", IDPattern)
	}
	if bot.Name == "" {
		return fail("name is required")
	}
	switch {
	case bot.Checkable() && bot.NotCheckable != "":
		return fail("has sources and not_checkable; use one")
	case !bot.Checkable() && bot.NotCheckable == "":
		return fail("needs ip_sources, rdns_suffixes or not_checkable")
	}
	for _, src := range bot.IPSources {
		if !strings.HasPrefix(src.URL, "https://") {
			return fail("source %q must use https://", src.URL)
		}
		if !knownFormats(src.Format) {
			return fail("source %q has unknown format %q", src.URL, src.Format)
		}
	}
	for i, suffix := range bot.RDNSSuffixes {
		suffix = strings.TrimSuffix(suffix, ".")
		if !suffixPattern.MatchString(suffix) {
			return fail("rdns suffix %q must be a lowercase domain without leading dot", bot.RDNSSuffixes[i])
		}
		bot.RDNSSuffixes[i] = suffix
	}
	return nil
}
