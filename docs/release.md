# Release

## v0.0.1 Namespace Release

StarMetal publishes the public package name `starmetal` while keeping the installed command short:
`sm`.

Run a dry-run first:

```sh
task release:namespaces
```

Publish after credentials are ready:

```sh
npm login
cargo login
export UV_PUBLISH_TOKEN="pypi-..."
./scripts/release-namespaces.sh --publish
```

The script publishes:

- npm: `starmetal@0.0.1`, with `sm`
- PyPI: `starmetal==0.0.1`, with `sm`
- crates.io: `starmetal 0.0.1`, with `sm`

These `0.0.1` packages are namespace holds while the native binary installer packages are finalized.

## Docker

Docker images are published from `.github/workflows/publish-docker.yaml`.

Required GitHub repository variables:

- `GCP_PROJECT_ID`
- optional `GCP_REGION`, default `us-central1`
- optional `GCP_ARTIFACT_REGISTRY_REPOSITORY`, default `starmetal`

Required GitHub repository secrets:

- `GCP_WORKLOAD_IDENTITY_PROVIDER`
- `GCP_SERVICE_ACCOUNT_EMAIL`

Dry-run the workflow:

```sh
gh workflow run publish-docker.yaml -f tag=v0.0.1 -f dry_run=true
```

Publish for a tag:

```sh
git tag v0.0.1
git push origin main v0.0.1
```

The default image is:

```text
us-central1-docker.pkg.dev/<GCP_PROJECT_ID>/starmetal/starmetal
```

For local publishing:

```sh
GCP_PROJECT_ID=<project> ./scripts/publish-docker-gcr.sh --push
```
