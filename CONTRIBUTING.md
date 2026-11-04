# Contributing

Thanks for helping! This guide gets you from clone to merged pull request.

## Set up

Option A — **Dev Container** (VS Code / Codespaces): open the repo and choose *Reopen in Container*. Everything is installed.

Option B — local: install [uv](https://docs.astral.sh/uv/), [pre-commit](https://pre-commit.com/) and Docker, then:

```bash
make setup     # dependencies + git hooks
make check     # lint, type-check and test everything (what CI runs)
make contract  # the API contract checks (what CI's contract workflow runs)
make up        # run all services locally
```

## Workflow

1. **Issue first.** Every change starts as a GitHub issue with the problem, the scope and acceptance criteria. Anything
   bigger than a small fix gets a written plan (scope, design, risks) before code.
2. **One branch per issue**, from an up-to-date `main`: `<type>/<issue#>-<short-slug>`, e.g. `feat/12-upload-api` or
   `docs/2-prd`.
3. **Pull request.** Keep it small and focused. The body closes the issue (`Closes #12`) and says what changed, how it
   was tested and the risks; the PR template has the sections.
4. **The PR title is the commit.** Write it as a [Conventional Commit](https://www.conventionalcommits.org/):
   `feat: add share-link expiry`, `fix: reject expired upload links`, `docs: …`. `main` takes squash merges only, the
   squash commit is the PR title with an empty body, and release-please reads it for the version bump and changelog
   (`feat` → minor, `fix` → patch, `feat!` → major). Mark a breaking change with `!` in the title: a
   `BREAKING CHANGE:` footer in a branch commit does not survive the squash.
5. **Review and CI.** The PR gets a code review and findings are fixed on the same branch. The CI checks must pass
   and the branch must be up to date with `main`. No approval count is required: GitHub does not let authors approve
   their own PRs, and this repo has one maintainer.
6. **Merge.** The maintainer squash-merges; the branch is deleted automatically.

The `protect-main` ruleset blocks direct pushes, force-pushes and deletion of `main`. Until
[#6](https://github.com/codewithmuh/secure-file-transfer/issues/6) lands, the repository admin can bypass the rules
when merging a pull request. That exists only for release-please's Release PRs, which get no CI run; don't use it for
anything else.

## Standards

- Tests for every behaviour change; coverage must stay ≥ 80 %.
- **The API contract leads.** Add or change an operation in `docs/api/openapi.yaml` in the same pull request as the
  code. Two CI checks hold the two together ([docs/api/README.md](docs/api/README.md#11-checking-the-contract),
  section 11):
  - *Generated spec* fails when an operation the code implements is missing from the contract or differs from it.
    Change the code to match, or fix the contract in the same pull request.
  - *Breaking changes* fails when the contract changes in a way that breaks clients. Make the change backwards
    compatible. Only a deliberate break that the rules allow (a change to the draft contract before the first release,
    or removing an operation after its sunset date) gets the **`breaking`** label, which lets the check pass. Adding or
    removing the label re-runs it.
- Record significant decisions as an ADR in `docs/adr/` (copy `0000-template.md`).
- Update the runbook when you add an alert, and the architecture doc when you add a component.
- Never commit secrets — use `.env` locally (git-ignored) and a secret manager in the cloud.
