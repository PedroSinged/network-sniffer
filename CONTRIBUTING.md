# Contributing

Thanks for your interest in improving network-sniffer.

## Getting set up

1. Install Go 1.26+ and libpcap headers (`libpcap-dev` on Debian/Ubuntu,
   Npcap SDK on Windows).
2. `go mod download`
3. `make test` should pass.

## Workflow

- Branch off `master`.
- Keep changes focused; one logical change per pull request.
- Run before pushing:
  ```bash
  gofmt -l .      # must print nothing
  make vet
  make test
  ```
- Add or update tests for any behaviour change. Parser and filter logic must
  stay covered.
- Update `README.md` and `CHANGELOG.md` when user-facing behaviour changes.

## Code style

- Standard `gofmt`; no extra linters required, but `staticcheck` is run in CI
  when available.
- Packages under `internal/` are single-purpose. New protocol decoders go in
  `internal/parser` and must return `internal/event` types.
- The capture loop stays in `internal/sniffer`; parsers never touch pcap.

## Commit messages

Conventional-commit style prefixes are used in history (`feat:`, `fix:`,
`docs:`, `chore:`, `refactor:`, `test:`).

## Reporting bugs

Open an issue with the command line used, the interface type, OS, and the
output around the problem. A small `.pcap` reproducing it is ideal.
