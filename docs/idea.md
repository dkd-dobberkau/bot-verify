# bot-verify — idea and what we know (2026-11-17)

## Where it comes from

goodbot-badbot.com logs crawlers that walk into honeypots despite robots.txt.
Its spoof filter only catches clients that rotate through several bot names; a
client that sticks to one borrowed name looks exactly like the real crawler.
The bot catalog (https://goodbot-badbot.com/bots, source: goodbot-badbot repo,
`app/bot_claims.json`) records, per bot, how its operator says you can recognise
it. Most name a published IP list or a reverse-DNS suffix; few sign requests.

## The idea

A service website operators can query: "IP x claims to be bot y — confirmed,
refuted, or not checkable?" Built from operators' own published infrastructure
(IP lists, reverse-DNS rules), not from observed visitors.

Possible interface: a DNS zone, like a DNSBL but as an *allow/verify* list,
e.g. a lookup of the reversed IP under a bot-specific name returns an A record
meaning "confirmed". Also possible: an HTTP API, or a downloadable dataset.

## Why "verify" and not "block"

- A blocklist of IPs needs visitor IPs. IP addresses are personal data (GDPR),
  and goodbot-badbot deliberately stores none. A false entry hurts a real crawler.
- A verify list needs only what bot operators publish themselves. No visitor
  data, nothing to leak, and a wrong answer is fixable from a public source.

## What we already know

- Recognition methods per bot (operator docs, retrieved 2026-11-17) are in
  goodbot-badbot's `app/bot_claims.json`, question `recognition`. Examples:
  OpenAI publishes `openai.com/gptbot.json`, `searchbot.json`,
  `chatgpt-user.json`; Anthropic `claude.com/crawling/bots.json`; Google
  `common-crawlers.json` plus reverse DNS on `googlebot.com`; Bing reverse DNS on
  `search.msn.com` plus `bing.com/toolbox/bingbot.json`; Ahrefs IP lists via
  `api.ahrefs.com` plus reverse DNS `ahrefs.com`/`ahrefs.net`; Common Crawl
  `index.commoncrawl.org/ccbot.json` plus reverse DNS `crawl.commoncrawl.org`.
  Some say outright that they publish nothing usable (Awario: "do not try to
  identify the bots via IP"; Brave: no differentiated user agent).
- Formats differ per operator (JSON shapes, plain lists, DNS-only). The
  collection step is the real work.
- Lesson from goodbot-badbot (fixed 2026-11-17): any consumer must take the client
  IP from a trusted proxy hop only. With uvicorn `--forwarded-allow-ips "*"` the
  client chose its own IP via X-Forwarded-For; a verify answer for a forged IP is
  worse than no answer. Whatever bot-verify ships, its docs must say this.

## Open decisions

1. Interface first: DNS zone, HTTP API, or dataset?
2. Who runs it: a public service, or software operators run themselves?
3. Scope of bots: only those with published infrastructure, or also a
   "not checkable" answer for the rest?
4. Stack and hosting (goodbot-badbot runs FastAPI on Mittwald).
