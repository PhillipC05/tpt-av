# Contributing to TPT-AV

Thanks for your interest in improving TPT-AV! This document explains how to set
up your environment, the standards we follow, and how to submit changes.

## Code of Conduct

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.

## Getting started

1. Fork the repository and clone your fork.
2. Install **Go 1.25+**.
3. Build and run the test suite:

   ```sh
   go build ./...
   go test ./...
   ```

4. Create a topic branch off `main`:

   ```sh
   git checkout -b my-feature
   ```

## Development workflow

- **Format** your code: `make fmt` (runs `go fmt ./...`).
- **Vet** before pushing: `make vet` (runs `go vet ./...`).
- Keep changes focused — one logical change per pull request.
- Add or update tests for any behavior change.
- Update documentation (`README.md`, example configs) when behavior or config
  options change.

## Commit messages

Use clear, present-tense messages. We loosely follow
[Conventional Commits](https://www.conventionalcommits.org/) prefixes
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), which also feed the
release changelog.

## Pull requests

1. Ensure `go build ./...`, `go vet ./...`, and `go test ./...` all pass.
2. Push your branch and open a pull request against `main`.
3. Fill out the PR template and link any related issues.
4. A maintainer will review; please respond to feedback and keep the branch
   up to date.

## Reporting bugs and requesting features

Use the [issue templates](.github/ISSUE_TEMPLATE/). For **security
vulnerabilities**, do not open a public issue — follow [SECURITY.md](SECURITY.md).

## License of contributions

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE), consistent with the rest of the project.
