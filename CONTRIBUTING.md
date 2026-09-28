# Contributing

## Setup

```
go build .
./morty -help
```

## Checks to run before submitting

```
make verify        # gofmt check, go vet, tests with -race, golangci-lint, zizmor
```

or individually:

```
go test -count=1 ./...
go test -race -count=1 ./...
golangci-lint run ./...
zizmor .
```

## Testing

- Unit and table-driven sanitizer tests live in `morty_test.go`
- Fuzz targets live in `fuzz_test.go` and `contenttype/fuzz_test.go`
- Handler-level tests use `httptest` upstreams and a real proxy listener
- `make fuzz` runs every fuzz target briefly
- `make bench` runs sanitizer benchmarks with allocation counts
- `make smoke` runs `scripts/smoke.sh` against a real running binary

## Commits and PRs

- Conventional commit style is used (`feat:`, `fix:`, `test:`, `ci:`, `docs:`)
- Workflows must stay zizmor-clean: actions pinned to commit SHAs,
  harden-runner first, least-privilege permissions

## Reporting bugs

Use the bug report issue template. For security issues, see SECURITY.md.
