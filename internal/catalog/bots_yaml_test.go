package catalog

import (
	"testing"

	"bot-verify/internal/sources"
)

// catalogSize is the number of bots in goodbot-badbot's app/bot_claims.json
// on 2026-11-17, from which bots.yaml was derived.
const catalogSize = 51

func TestRepoBotsYAML(t *testing.T) {
	cat, err := Load("../../bots.yaml", sources.KnownFormat)
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
