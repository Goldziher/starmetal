# Release

## Release Flow

StarMetal publishes the public package name `starmetal` while keeping the installed command short:
`sm`.

Use one version across Cargo, npm, PyPI, Docker tags, GitHub release assets, and Homebrew:

```sh
task release:sync-version VERSION=0.1.0
```

Open a PR or push the version-sync commit, then run the dry-run release workflows from GitHub:

```sh
task release:dry-run VERSION=0.1.0 REF=main
```

Dry runs build and smoke-test platform archives, generate checksums, dry-run package-manager builds,
and dry-run the Docker image without creating releases, publishing packages, pushing images, or
updating Homebrew.

Cut the release only after the dry-run workflows and normal CI are green:

```sh
task release:tag VERSION=0.1.0
```

Tag publishing is handled by `.github/workflows/publish.yaml`:

- crates.io uses `rust-lang/crates-io-auth-action` and crates.io trusted publishing.
- npm uses `npm publish --provenance`; configure npm trusted publishing for project `starmetal`,
  owner `Goldziher/starmetal`, workflow `publish.yaml`.
- PyPI uses `pypa/gh-action-pypi-publish` with environment `pypi`; configure PyPI trusted
  publishing for project `starmetal`, owner `Goldziher/starmetal`, workflow `publish.yaml`, and
  environment `pypi`.
- GitHub Releases receive platform archives plus `starmetal_<version>_checksums.txt`.
- Homebrew updates `Goldziher/homebrew-tap` and dispatches its bottle workflow when
  `HOMEBREW_TOKEN` is configured.

Only PyPI uses a GitHub environment, named `pypi`. npm and crates.io do not use workflow
environments.

## v0.0.1 Namespace Release

The initial `0.0.1` npm, PyPI, and crates.io packages have already been published as namespace
holds. Check their status with:

```sh
task release:namespaces
```

## Docker

Docker images are published from `.github/workflows/publish-docker.yaml`.

The workflow publishes to GitHub Container Registry using the repository-scoped
`GITHUB_TOKEN`; no extra Docker registry secret is required.

Dry-run the workflow:

```sh
gh workflow run publish-docker.yaml -f tag=v0.1.0 -f ref=main -f dry_run=true
```

Publish for a tag:

```sh
task release:tag VERSION=0.1.0
```

The default image is:

```text
ghcr.io/goldziher/starmetal
```

For local publishing:

```sh
GHCR_TOKEN=<token-with-package-write> GHCR_USERNAME=<github-user> ./scripts/publish-docker-ghcr.sh --push
```
