# ADR-0015: Statistics and Operational Metrics

## Status

Accepted

## Context

Operators need to confirm that Starmetal is serving cache hits, fetching upstream misses, persisting
artifacts, and recording local publishing activity. For MVP readiness, this does not require durable
analytics, Prometheus, or a full audit log.

## Decision

Starmetal records in-memory per-ecosystem operational counters inside `CachingPackageService` and
exposes snapshots through the admin API.

Tracked per ecosystem:

| Counter | Meaning |
|---------|---------|
| `versions_cache_hits` | Version list served from storage |
| `versions_cache_misses` | Version list fetched from upstream |
| `metadata_cache_hits` | Version metadata served from storage |
| `metadata_cache_misses` | Version metadata fetched from upstream |
| `artifact_cache_hits` | Artifact bytes served from storage after Blake3 verification |
| `artifact_cache_misses` | Artifact bytes fetched from upstream |
| `bytes_served` | Artifact bytes returned by the service |
| `upstream_errors` | Upstream client errors observed by the service |
| `publishes` | Local publish operations completed |
| `yanks` | Local yank or unyank operations completed |
| `integrity_failures` | Blake3 or upstream digest failures |
| `last_activity_unix_seconds` | Last counter update time |

Metrics are intentionally process-local. They reset on restart and are not a source of billing,
auditing, or compliance evidence.

## Deferred

- Prometheus/OpenMetrics endpoint.
- Persistent audit/event log.
- Per-package durable statistics.
- Operator-configurable retention.
- Alerting and dashboards.

## Consequences

- The admin API can show useful cache behavior immediately.
- Docker E2E can assert cache behavior through storage and, where useful, metrics.
- Production-grade observability remains a future hardening task.
