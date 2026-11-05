# AGENTS.md - Nais API Reconcilers

Guidelines for AI agents working on this project.

## Project Structure

- **Go project** that creates and maintains team resources and permissions in external services.
- Entry point in `cmd/api-reconcilers/`; startup, configuration, HTTP endpoints, and metrics in `internal/cmd/reconciler/`.
- Reconcilers in `internal/reconcilers/`, organized by service: Azure, Dependency-Track, GitHub, Google, Grafana, and Kubernetes namespaces.
- Shared reconciler interface, manager, and work queue in `internal/reconcilers/`.
- Service clients and helpers in `internal/azureclient/`, `internal/gcp/`, and `internal/kubernetes/`.
- Tests alongside Go source; shared HTTP test helpers in `internal/test/` and fixtures in `testdata/`.
- Helm chart in `charts/`; development tasks in `mise/tasks/`.

## Common Commands

| Task | Command |
|------|---------|
| Install toolchain | `mise install` |
| Build | `mise run build` |
| Run locally | `mise run local` |
| Run all tests (with race detector) | `mise run test` |
| Run tests with coverage profile | `mise run test --coverage` |
| Generate mocks | `mise run generate` |
| Format code | `mise run fmt` |
| Check formatting and generated mocks (clean working tree) | `mise run fmt:ci` |
| Run all checks | `mise run check` |
| Lint Go code | `mise run check:golangci-lint` |
| Static analysis | `mise run check:staticcheck` |
| Go vet | `mise run check:govet` |
| Vulnerability scan | `mise run check:govulncheck` |
| Lint Helm chart | `mise run check:helm-lint` |

For a focused test run, use the relevant package and test name:

```bash
go test -race -run TestName ./internal/reconcilers/...
```

## Workflow

- **Branches**: Use a descriptive feature, fix, or docs branch rather than `main` or another default/protected branch. Check the current branch before editing or committing, and reuse an existing task branch when appropriate. Commit to a default/protected branch only when explicitly requested.
- Read the relevant implementation and tests before changing code; follow existing package patterns.
- Preserve unrelated working-tree changes. Do not overwrite local configuration or credentials.
- After changing mocked interfaces, update `.configs/mockery.yaml` if needed and run `mise run generate`. Do not edit generated `mock_*.go` files by hand. The generation task deletes existing `internal/**/mock_*.go` files before recreating them, so inspect local changes first.
- After Go changes, run `mise run fmt`, `mise run test`, and `mise run check:golangci-lint`, plus other relevant static checks. Report any checks that could not be run.
- Before delivering PR work, regenerate mocks and review `git status --short`, including generated files. CI's `mise run fmt:ci` formats, regenerates, and checks for tracked differences; it expects a clean, committed working tree.

## Reconciler Conventions

- Implement the interface in `internal/reconcilers/reconciler.go`: `Configuration`, `Name`, `Reconcile`, and `Delete`.
- Wire new reconcilers into `internal/cmd/reconciler/main.go` and update configuration and chart values as needed.
- Nais API is the source of truth; use `github.com/nais/api/pkg/apiclient` and its gRPC types. API contracts are maintained in the API repository, not generated here.
- Reconciliation is scheduled and event-driven. Keep operations idempotent and safe to retry, including after partial failures; propagate context cancellation and return useful errors.
- Preserve the manager's queue and retry behavior: delayed retries must not block other teams, new events supersede pending retries, and success clears retry state. See `README.md` and manager/queue tests for details.
- Follow existing context, `logrus` logging, and metrics patterns. Never log credentials or tokens.

## Tests

- Keep tests independent of live services and credentials. Use generated mocks, `httptest`, and the helpers in `internal/test/`.
- Follow the surrounding test style; existing tests use both standard Go assertions and Testify mocks/assertions.
- Add regression tests for changed behavior, especially partial failures, deletion, pagination, and retries.
- For concurrent queue/manager behavior, follow existing `testing/synctest` patterns rather than relying on sleeps.

## Local Development

The Nais API must be running locally first; see its README and this repository's `README.md`.

```bash
mise install
cp .env.example .env # Only if .env does not already exist
mise run local
```

- Configure only the reconcilers needed for the task. External services may require authentication and real permissions; do not run against production or mutate live resources without explicit authorization.
- Configuration lives in `internal/cmd/reconciler/config/`; `.env.example` documents local environment variables.
- Kubernetes-related work may require a kind cluster and the resources in `hack/`. Follow the kind setup in `README.md`.
- Formatting uses `gofumpt`; tool versions are managed in `mise/config.toml`, with Go tools declared in `go.mod`.
