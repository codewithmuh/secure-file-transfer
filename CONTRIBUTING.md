# Contributing

Thanks for helping! This guide gets you from clone to merged pull request.

## Set up

Option A — **Dev Container** (VS Code / Codespaces): open the repo and choose *Reopen in Container*. Everything is installed.

Option B — local: install [uv](https://docs.astral.sh/uv/), [pre-commit](https://pre-commit.com/), Docker and Node (the
version in `web/.nvmrc`), then:

```bash
make setup      # dependencies + git hooks
make check      # lint, type-check and test everything (what CI runs)
make web-check  # only the web app: clean install, types, lint, tests, build
make web-a11y   # the web app's axe checks in English and Japanese, in the pinned Playwright image (Docker)
make contract   # the API contract checks (what CI's contract workflow runs)
make up         # run all services locally
```

## Workflow

1. **Issue first.** Every change starts as a GitHub issue with the problem, the scope and acceptance criteria. Anything
   bigger than a small fix gets a written plan (scope, design, risks) before code.
2. **One branch per issue, or per batch.** Branch from an up-to-date `main`: `<type>/<issue#>-<short-slug>`, e.g.
   `feat/12-upload-api` or `docs/2-prd`. Three to five related issues from the same area (app, DLP, web or infra) may
   share one branch and one pull request, named after the first issue. Only one batch is open at a time, and nothing
   is stacked on unmerged work.
3. **Pull request.** Keep it focused. The body closes each issue (`Closes #12`, one line per issue) and says what
   changed, how it was tested and the risks; the PR template has the sections. A batch PR also lists one Conventional
   Commit line per issue between `BEGIN_COMMIT_OVERRIDE` and `END_COMMIT_OVERRIDE`, so release-please writes a
   changelog entry for each issue instead of one for the squash commit.
4. **The PR title is the commit.** Write it as a [Conventional Commit](https://www.conventionalcommits.org/):
   `feat: add share-link expiry`, `fix: reject expired upload links`, `docs: …`. `main` takes squash merges only, the
   squash commit is the PR title with an empty body, and release-please reads it for the version bump and changelog
   (`feat` → minor, `fix` → patch, `feat!` → major). Mark a breaking change with `!` in the title: a
   `BREAKING CHANGE:` footer in a branch commit does not survive the squash.
5. **Review and CI.** The PR gets a code review and findings are fixed on the same branch. The CI checks must pass
   and the branch must be up to date with `main`. No approval count is required: GitHub does not let authors approve
   their own PRs, and this repo has one maintainer.
6. **Merge.** The maintainer squash-merges; the branch is deleted automatically.

The `protect-main` ruleset lives in [`.github/rulesets/protect-main.json`](.github/rulesets/protect-main.json). It
requires these checks, each a job that reports on every pull request: Repo checks, Python, Web app, Web app
accessibility, Local stack, Mail adapter, both Contract checks, Terraform, Deploy config and `promotion-gate`. The image build runs only when the code it packages
changes, so it isn't required. When you rename or add a job, update that file in the same pull request:
`.github/scripts/check-ruleset.sh`, run in Repo checks, fails if a required check isn't a job that reports on every
pull request. After the change merges, the maintainer runs `.github/scripts/apply-github-settings.sh` to apply it,
along with CodeQL default setup.

The ruleset also blocks direct pushes, force-pushes and deletion of `main`, and nobody may bypass it, the repository
admin included ([#6](https://github.com/codewithmuh/secure-file-transfer/issues/6)): every merge, Release PRs too,
needs green checks. `check-ruleset.sh` fails if a bypass actor comes back.

## Releases

release-please keeps a Release PR open with the next version and the changelog; merging it tags the release, and
`release.yml` publishes the signed image. release-please acts as the repository's release GitHub App, with a token
`actions/create-github-app-token` mints for each run, because GitHub starts no workflow for a pull request that
`GITHUB_TOKEN` opens or updates: the Release PR would never get its required checks. The token lasts at most an hour
and is revoked when the job ends; no personal access token is involved.

The maintainer sets the App up once, before the change that uses it (#6) merges:

1. **Create the App.** GitHub, Settings, Developer settings, GitHub Apps, New GitHub App, owned by the maintainer's
   account: a name such as `sft-release`, the repository's URL as its homepage, webhook off. Repository permissions:
   **Contents: Read and write** and **Pull requests: Read and write** only (Metadata: Read-only comes with them);
   nothing else, no account or organization permissions, no events. Installable on this account only.
2. **Install it** on `codewithmuh/secure-file-transfer` only ("Only select repositories").
3. **Make a private key** on the App's page and download it. Note the App's **Client ID**.
4. **Create the `release` environment** in the repository's settings, Environments: deployment branches and tags,
   selected branches, `main` only; no reviewers (a release must not wait for one).
5. **Add its two secrets** to the `release` environment: `RELEASE_APP_CLIENT_ID` (the Client ID) and
   `RELEASE_APP_PRIVATE_KEY` (the whole `.pem` file). Then delete the downloaded key; GitHub keeps no other copy, and a
   new one can be made on the App's page at any time (rotate it the same way, then delete the old key there).
6. **Merge, then apply the ruleset**: `.github/scripts/apply-github-settings.sh` (#59) replaces `protect-main` with the
   file in Git, which has no bypass actors.
7. **Close a Release PR opened before the App**, and delete its branch `release-please--branches--main`, if one is
   still open: the next push to `main` reopens it as the App, and its checks run.

If the change merges before steps 1 to 5, `release.yml` fails at the token step on every push to `main`: no Release
PR is opened or updated and nothing is released until the secrets exist, after which the next push to `main` works.
Nothing else breaks, and no image is published by mistake. If the ruleset is applied before the App works, a Release
PR opened by `GITHUB_TOKEN` can't be merged, because its checks never run; set the App up, then step 7.

## Standards

- Tests for every behaviour change; coverage must stay ≥ 80 %. Web app unit tests sit next to the code as
  `*.test.ts(x)` and run with Vitest.
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

## Licensing of contributions

The project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE), and the author also offers
commercial licences ([COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). So that every contribution can be offered both
ways, opening a pull request means you agree that:

1. You wrote the contribution, or have the right to submit it, and it doesn't include code under terms that conflict
   with these.
2. You keep the copyright in your contribution, and you grant Muhammad Rashid a perpetual, worldwide, non-exclusive,
   royalty-free and irrevocable licence to use, copy, change, distribute and sublicense it, under the project's licence
   or any other licence, including commercial ones.
3. Your contribution comes as is, without warranty.

If you can't agree to these terms, for example because your employer owns your work, say so in the pull request
before it is merged.
