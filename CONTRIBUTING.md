# Contributing

## Setup

You need Go 1.27, the version in `go.mod`, which CI uses too.

```sh
go vet ./...
go test -race ./...
go build -o bot-verify ./cmd/bot-verify && ./bot-verify
go build -o bot-verify-dns ./cmd/bot-verify-dns   # DNS zone, see the README
```

`go test` also checks `bots.yaml`, so a broken catalog fails the tests.

## Changing bots.yaml

Most contributions will be bot entries. Read [docs/bots.md](docs/bots.md) first;
it explains the calls already made and the rules behind them:

- Every list URL and suffix comes from the operator's own documentation, linked
  as `docs`.
- Only `https://` sources.
- No reverse-DNS suffix that third parties can get names under (cloud and
  hosting PTR domains).
- A bot with nothing to check gets `not_checkable` with the operator's
  statement, not a guess.

If a source has a new format, add a parser in `internal/sources/parse.go` and a
test with a trimmed real response in `internal/sources/testdata/`.

## Code

- Write the test first, and watch it fail.
- Standard library only, apart from the YAML parser and `github.com/miekg/dns`
  for the DNS zone. Ask before adding a dependency.
- Never log or store a queried IP.
- `gofmt` and `go vet` must be clean.
- How verdicts are reached is described in [docs/verdicts.md](docs/verdicts.md).
  Keep it in step with the code.

## Commits and changes

- Conventional commit messages (`feat:`, `fix:`, `docs:`, `ci:`, …).
- Pull requests against `main`. CI (tests and Trivy scan) must be green.
- Note user-visible changes in `CHANGELOG.md`.

Security issues go through [SECURITY.md](SECURITY.md), not public issues.
