package catalog

import (
	"reflect"
	"strings"
	"testing"
)

func googleOnly(f string) bool { return f == "google-prefixes" }

func TestLoadValid(t *testing.T) {
	cat, err := Load("testdata/valid.yaml", googleOnly)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cat.Bots) != 3 {
		t.Fatalf("len(Bots) = %d, want 3", len(cat.Bots))
	}
	petal, ok := cat.Get("petalbot")
	if !ok {
		t.Fatal("petalbot not found")
	}
	if !reflect.DeepEqual(petal.RDNSSuffixes, []string{"petalsearch.com"}) {
		t.Errorf("petalbot suffixes = %v", petal.RDNSSuffixes)
	}
	if !petal.Checkable() {
		t.Error("petalbot should be checkable")
	}
	awario, ok := cat.Get("awario")
	if !ok || awario.Checkable() {
		t.Errorf("awario: found=%v checkable=%v, want found and not checkable", ok, awario.Checkable())
	}
	if _, ok := cat.Get("nope"); ok {
		t.Error("Get(nope) found a bot")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate":  "dupbot",
		"badid":      "Bad_Bot",
		"both":       "bothbot",
		"neither":    "neitherbot",
		"format":     "formatbot",
		"http":       "httpbot",
		"suffixdot":  "dotbot",
		"suffixcase": "casebot",
	}
	for file, id := range cases {
		t.Run(file, func(t *testing.T) {
			_, err := Load("testdata/invalid_"+file+".yaml", googleOnly)
			if err == nil {
				t.Fatal("Load returned no error")
			}
			if !strings.Contains(err.Error(), id) {
				t.Errorf("error %q does not name %q", err, id)
			}
		})
	}
}

func TestNewIndexesBots(t *testing.T) {
	cat := New([]Bot{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}})
	if bot, ok := cat.Get("b"); !ok || bot.Name != "B" {
		t.Errorf("Get(b) = %+v, %v", bot, ok)
	}
}
