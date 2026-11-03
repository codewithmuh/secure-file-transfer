# 0010. Use Python only in v1 and remove the Go sample service

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

The repository template ships a Go sample service, `services/api-go`, with its own CI job, image build and smoke
test, release publishing, Makefile targets, compose service, Dependabot entries and a Go toolchain in the dev
container. The README says it "stays only if an ADR gives Go a job", and the project rule is to add Go only where it
earns its place and to keep the moving parts few.

The backend is one codebase: the API and every worker are built from one image and share the service layer, where
every permission check and tenant scope lives ([architecture](../architecture.md) section 2,
[ADR-0002](0002-api-framework.md), [ADR-0003](0003-multi-tenancy-shared-schema.md)). Each component, at the design
load ([capacity](../design/capacity-and-cost.md) A8, 3.1, 4.1):

| Component | Work at design load | Would Go earn its place? |
|---|---|---|
| API service | 150 requests/s in the peak hour, bursts to 300; about 10 ms of CPU each | No: ADR-0002 chose FastAPI |
| Download streams through the API ([abuse](../security/abuse-and-rate-limits.md) 5.7) | 35 MB/s in the peak hour, 70 MB/s in bursts, about 15 streams: 0.35 to 0.7 vCPU | The strongest case, but small, and every stream starts with the grant checks of the service layer |
| Scan worker | Waits on S3 and the scan engine's socket | No |
| Outbox relay, notification worker, lifecycle jobs | I/O-bound, a few messages a second | No |
| Operator CLI | One operator | A static binary would be convenient; Python installed with uv is enough |
| Cognito sign-in triggers | About 1.2 M short invocations a month | No |

## Decision

v1 has **no Go**. Remove `services/api-go` and everything that builds, tests or publishes it in the first build
milestone (phase 5), in the same change that adds the ECR push ([ADR-0007](0007-container-registry-ecr.md)).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Python only; remove the Go sample** (chosen) | One language, one toolchain and one dependency tree to patch (T-68 in the [threat model](../threat-model.md)). Every path goes through one service layer, which one isolation suite and one authorization matrix test. Fewer CI minutes and Dependabot pull requests. The repository shows only what runs. | The project shows no Go. A later Go component starts from nothing rather than from the template's sample. If downloads grow far past the design load, Python costs more CPU and memory per stream than Go would. |
| **Keep the sample, unused** | No work now; ready if Go earns a job. | CI builds, scans and publishes an image that runs nowhere; twice the dependency updates; two of the five required checks guard code nobody uses; readers can't tell what runs. |
| **Write the download stream path in Go now** | Lower CPU and memory per stream; a small static image. | Duplicates the grant checks, tenant scoping and row-level security settings that ADR-0002 keeps in one service layer, so the isolation suite and authorization matrix must cover two implementations; a second data-access layer to keep in step with Alembic migrations; no measured need, since streaming needs under 1 vCPU at design load. |

## Consequences

- **What goes**, in one pull request: `services/api-go/`; the `go` job in `ci.yml`, the `api-go` entry in the `images`
  matrix and `go` in its `needs`; the `api-go` entry in `release.yml`'s publish matrix; the `GO` variable and its steps
  in the `Makefile`; the `api-go` service in `compose.yaml`; the `gomod` entry and the Go directory of the Docker
  entry in `.github/dependabot.yml`; the Go feature and extension in `.devcontainer/devcontainer.json`; the
  `cosign verify` example for the GHCR `api-go` image in `SECURITY.md`, replaced by the ECR one (ADR-0007); the Go
  globs in `.editorconfig` (`*.go` and `go.mod`; the `Makefile` keeps its tabs); the Go block in `.gitignore`
  (`coverage.out`, `/bin/`); and Go in the requirements and layout of `README.md` and `CONTRIBUTING.md`.
- **Required checks.** The `protect-main` ruleset requires five checks, two of them Go's. They come off the ruleset
  when that pull request merges, because a required check that never runs blocks every later merge.
- **What stays**: the Python service, its CI job and image checks, release-please and the signing steps, which
  ADR-0007 moves to ECR.
- **The rule stays**: Go is added only where a measured need gives it a job, through a superseding ADR.

When to revisit: when the first load test (capacity section 8) shows streamed downloads costing well above A8's
1 vCPU per 100 MB/s, missing NFR-4 because of the Python event loop, or limited per pod by memory. A Go content service
would then serve the bytes of grants that the Python service created, with its checks covered by the same isolation
suite. Also revisit if an operator CLI has to be distributed to many people.
