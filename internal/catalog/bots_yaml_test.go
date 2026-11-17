package catalog

import "testing"

// catalogSize is the number of bots in goodbot-badbot's app/bot_claims.json
// on 2026-11-17, from which bots.yaml was derived.
const catalogSize = 51

func TestRepoBotsYAML(t *testing.T) {
	known := func(f string) bool { return f == "google-prefixes" || f == "cidr-lines" }
	cat, err := Load("../../bots.yaml", known)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cat.Bots) != catalogSize {
		t.Errorf("len(Bots) = %d, want %d", len(cat.Bots), catalogSize)
	}
	for _, id := range []string{"googlebot", "gptbot", "claudebot", "bingbot", "ahrefsbot", "ccbot"} {
		bot, ok := cat.Get(id)
		if !ok || !bot.Checkable() {
			t.Errorf("%s: found=%v checkable=%v, want checkable", id, ok, bot.Checkable())
		}
	}
	if bot, ok := cat.Get("awariosmartbot"); !ok || bot.Checkable() {
		t.Errorf("awariosmartbot: found=%v checkable=%v, want not checkable", ok, bot.Checkable())
	}
}
