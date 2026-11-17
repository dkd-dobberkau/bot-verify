# Why each bot is classified the way it is

`bots.yaml` was derived on 2026-11-17 from goodbot-badbot's
`app/bot_claims.json` (question `recognition`, operator docs only). Every IP-list
URL was fetched once by hand on that day to pick its format. This page records
the calls that are not obvious from the file, so whoever maintains it later
does not undo them by accident.

The rule behind all of them: **a wrong `confirmed` is the worst outcome**, since
it lets a spoofer through with our stamp on it. When the evidence is weak, we
choose `not_checkable` over a check that someone other than the operator could pass.

## Checkable: 27 bots

| How | Bots |
|---|---|
| IP list only | gptbot, chatgpt-user, oai-searchbot, claudebot, claude-user, shapbot, perplexitybot, duckduckbot |
| IP list and reverse DNS | googlebot, googleother, google-cloudvertexbot, bingbot, applebot, ccbot, ahrefsbot, serankingbacklinksbot, seznambot, ibou-search, iboubot, barkrowler, riverbot |
| Reverse DNS only | petalbot, youbot, baiduspider, yandexbot, dataprovider, geedoshopproductfinder |

Formats: every JSON list uses the `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix":…}]}`
shape (`google-prefixes`). SERanking's `?txt=1` endpoint has one IP per line
(`cidr-lines`). No operator needed its own parser.

### Calls worth knowing

- **Googlebot: no `googleusercontent.com`.** Google's verification page lists
  `googlebot.com`, `google.com` and `googleusercontent.com`. But any Google Cloud
  VM can get a forward-confirmable `*.googleusercontent.com` PTR, so that suffix
  would confirm anyone renting a VM. It is left out, and the cost is that
  Google's user-triggered fetchers outside `common-crawlers.json` get `refuted`.
  The same reasoning rules out any suffix where customers can set their own PTR
  records (cloud and hosting providers).
- **GoogleOther, Google-CloudVertexBot** get only `googlebot.com`, the one domain
  Google names for them.
- **Claude-User and ClaudeBot** share `claude.com/crawling/bots.json`, and the
  three Google bots share `common-crawlers.json`. Each URL is fetched once.
- **CCBot:** Common Crawl says its reverse DNS works for IPv4 only, but its list
  includes IPv6. For that reason a reverse-DNS miss counts as `refuted` only once
  every IP list of the bot has loaded (see [verdicts.md](verdicts.md)).
- **Applebot:** the operator's docs give the list URL as `http://`. The same file
  is served over `https://search.developer.apple.com/applebot.json`, which is
  the one used (the catalog accepts only https).
- **YouBot, Geedo:** their docs name IP ranges in the page text (`68.67.112.0/24`,
  `83.99.206.0/24`). Those are not in the file, since there is no field for
  hand-copied ranges. The reverse-DNS rule covers them instead.
- **Broad suffixes** (`google.com`, `seznam.cz`, `yandex.ru`/`.net`/`.com`,
  `baidu.com`/`.jp`) are the operators' own words. Anyone can point the PTR of
  their own IP at any name, so a suffix is only unsafe if the operator's own
  name servers return a customer's IP for a name under it, as Google does for
  `*.bc.googleusercontent.com`. Checked on 2026-11-18 by sampling, with no such
  case found:
  - Yandex Cloud and Baidu Cloud IPs have no default PTR. The PTRs customers set
    themselves point to their own domains.
  - Both clouds put customer names under separate domains (`yandexcloud.net`,
    `yandex.cloud`; `baidubce.com`, `bcebos.com`).
  - No name that encodes an IP resolves to that IP (nip.io style) under any of
    the suffixes. `yandex.ru` and `yandex.com` have a wildcard, but it points
    only to Yandex's own `213.180.204.242`.
  - The real crawlers use `*.spider.yandex.com` and
    `baiduspider-*.crawl.baidu.com`.

  The suffixes stay as broad as the operators give them: narrowing them adds no
  protection and could refute real crawlers on other names. This is a sample,
  not a guarantee. It is worth repeating if an operator starts publishing names
  for customer IPs.

## Not checkable: 24 bots

`not_checkable` always carries the reason, in the operator's words where they
gave one.

| Reason | Bots |
|---|---|
| Operator publishes nothing to check against | bytespider, cohere-ai, chatglm-spider, deepseekbot, sogou-spider, seranking, moptimizer |
| User agent only, by the operator's own statement | meta-externalagent, meta-externalfetcher, dotbot, builtwith, semrushbot ("do not use any consecutive IP blocks"), awariosmartbot ("do not try to identify the bots via IP"), bravebot (no differentiated user agent) |
| IP ranges only on an HTML page | amazonbot, censysinspect, internetmeasurement |
| Signs requests with Web Bot Auth: verify the signature, not the IP | exasearchbot, pandalytics, anticlonebot |
| Not one operator's bot | heritrix (crawler software run by many operators), screaming-frog (desktop tool, user agent can be changed), mj12bot (distributed community crawler; a pre-arranged `CRAWLER-IDENT` on request) |
| No own user agent | google-extended (a robots.txt token used by existing Google crawlers) |

- **Amazonbot** does publish IPs, but only as an HTML page, and that page also
  shows the requesting client's own IP. Scraping it would put the scraper's own
  address on Amazonbot's list. It stays `not_checkable` until Amazon publishes
  a machine-readable list.
- **Web Bot Auth** (HTTP message signatures) is out of scope for v1. A request
  signed this way can be verified more reliably than any IP check, so these
  bots are candidates for a later version.

## Changing an entry

- Quote the operator. A suffix or list belongs in `bots.yaml` only if the
  operator's docs name it, and `docs` points to that page.
- Before adding a suffix, check that only the operator can get names under it.
- After adding a list, run the binary and check `/healthz` (`sources_loaded`
  equals `sources_total`) and `/v1/dataset` for the new prefixes.
