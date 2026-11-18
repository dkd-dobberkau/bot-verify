package sources

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, format string, body []byte) []netip.Prefix {
	t.Helper()
	parse, ok := ParserFor(format)
	if !ok {
		t.Fatalf("no parser for %q", format)
	}
	got, err := parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return got
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func TestGooglePrefixes(t *testing.T) {
	body, err := os.ReadFile("testdata/google_common.json")
	if err != nil {
		t.Fatal(err)
	}
	got := mustParse(t, "google-prefixes", body)
	want := prefixes("2001:4860:4801:10::/64", "66.249.64.0/27")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCIDRLines(t *testing.T) {
	got := mustParse(t, "cidr-lines", []byte("# comment\n192.0.2.0/24\n\n198.51.100.7\n"))
	want := prefixes("192.0.2.0/24", "198.51.100.7/32")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCIDRLinesRealFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/seranking.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := mustParse(t, "cidr-lines", body)
	if len(got) != 2 || got[0] != netip.MustParsePrefix("95.217.114.159/32") {
		t.Errorf("got %v", got)
	}
}

func TestPrefixesAreMasked(t *testing.T) {
	got := mustParse(t, "cidr-lines", []byte("192.0.2.77/24\n"))
	if got[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("got %v, want 192.0.2.0/24", got[0])
	}
}

func TestEmptyIsError(t *testing.T) {
	cases := []struct {
		format, body string
		noPrefixes   bool
	}{
		{"google-prefixes", `{"prefixes":[]}`, true},
		{"cidr-lines", "", true},
		{"google-prefixes", "", false},
		{"google-prefixes", "<html>", false},
		{"cidr-lines", "<html>", false},
	}
	for _, c := range cases {
		parse, _ := ParserFor(c.format)
		_, err := parse([]byte(c.body))
		if err == nil {
			t.Errorf("%s %q: no error", c.format, c.body)
			continue
		}
		if c.noPrefixes && !errors.Is(err, ErrNoPrefixes) {
			t.Errorf("%s %q: err %v, want ErrNoPrefixes", c.format, c.body, err)
		}
	}
}

func TestInvalidPrefixIsError(t *testing.T) {
	parse, _ := ParserFor("google-prefixes")
	if _, err := parse([]byte(`{"prefixes":[{"ipv4Prefix":"999.1.1.1/8"}]}`)); err == nil {
		t.Error("no error for invalid prefix")
	}
}

func TestKnownFormat(t *testing.T) {
	if !KnownFormat("google-prefixes") || !KnownFormat("cidr-lines") || KnownFormat("weird") {
		t.Error("KnownFormat mismatch")
	}
}

func TestRejectsOverlyBroadPrefixes(t *testing.T) {
	cases := []struct{ format, body string }{
		{"google-prefixes", `{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}`},
		{"google-prefixes", `{"prefixes":[{"ipv4Prefix":"10.0.0.0/7"}]}`},
		{"google-prefixes", `{"prefixes":[{"ipv6Prefix":"2000::/15"}]}`},
		{"cidr-lines", "192.0.2.0/24\n0.0.0.0/0\n"},
	}
	for _, c := range cases {
		parse, _ := ParserFor(c.format)
		if _, err := parse([]byte(c.body)); err == nil {
			t.Errorf("%s %q: no error", c.format, c.body)
		}
	}
	got := mustParse(t, "google-prefixes", []byte(`{"prefixes":[{"ipv4Prefix":"10.0.0.0/8"},{"ipv6Prefix":"2001::/16"}]}`))
	if len(got) != 2 {
		t.Errorf("/8 and /16 must be accepted, got %v", got)
	}
}

// IPv4-mapped IPv6 prefixes are normalised to IPv4, so the IPv4 breadth limit
// applies and they match the unmapped addresses Verify queries.
func TestMappedPrefixesAreTreatedAsIPv4(t *testing.T) {
	for _, format := range []string{"google-prefixes", "cidr-lines"} {
		body := func(prefix string) []byte {
			if format == "cidr-lines" {
				return []byte(prefix + "\n")
			}
			return []byte(`{"prefixes":[{"ipv6Prefix":"` + prefix + `"}]}`)
		}
		got := mustParse(t, format, body("::ffff:198.51.100.0/120"))
		if len(got) != 1 || got[0] != netip.MustParsePrefix("198.51.100.0/24") {
			t.Errorf("%s: got %v, want 198.51.100.0/24", format, got)
		}
		parse, _ := ParserFor(format)
		for _, broad := range []string{"::ffff:0.0.0.0/97", "::ffff:0.0.0.0/96", "::ffff:0.0.0.0/90"} {
			if _, err := parse(body(broad)); err == nil {
				t.Errorf("%s: %s accepted, want rejected as broader than IPv4 /8", format, broad)
			}
		}
	}
}

func TestRejectsTooManyPrefixes(t *testing.T) {
	var body strings.Builder
	for i := 0; i <= MaxPrefixes; i++ {
		fmt.Fprintf(&body, "10.%d.%d.%d\n", i>>16&255, i>>8&255, i&255)
	}
	parse, _ := ParserFor("cidr-lines")
	if _, err := parse([]byte(body.String())); err == nil {
		t.Errorf("a list with %d prefixes was accepted, limit is %d", MaxPrefixes+1, MaxPrefixes)
	}
}
