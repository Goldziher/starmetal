-- Universal content model (ADR-0020): Component -> Asset -> Blob with a
-- content-addressed blob store and an asset -> blob reference table for
-- reference-counted garbage collection.
--
-- This file is the single source of truth for the schema. `scythe` parses it to
-- infer column types for code generation (it never executes it), and the crate
-- applies it verbatim to provision a database.

-- Blobs are content-addressed by their Blake3 digest (the primary key). The same
-- bytes referenced from many assets are stored exactly once. GC lifecycle columns
-- (`marked`, `soft_deleted_at`, `grace_expires_at`) drive mark -> soft-delete +
-- grace -> compact.
CREATE TABLE blobs (
    digest          TEXT PRIMARY KEY,
    size            BIGINT NOT NULL,
    content_type    TEXT,
    upstream_hashes JSONB NOT NULL DEFAULT '{}',
    marked          BOOLEAN NOT NULL DEFAULT FALSE,
    soft_deleted_at TIMESTAMPTZ,
    grace_expires_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The coordinate level: an ecosystem-scoped package version. `namespace` stores
-- the empty string (never NULL) when the ecosystem has no namespace concept, so
-- the uniqueness constraint and ON CONFLICT upsert are straightforward.
--
-- Lifecycle and usage columns (`created_at`, `updated_at`, `last_downloaded_at`,
-- `download_count`) back the retention engine (Stage 2c): each `RetentionRule`
-- selects versions to delete by inspecting these columns.
CREATE TABLE components (
    id                 BIGSERIAL PRIMARY KEY,
    ecosystem          TEXT NOT NULL,
    namespace          TEXT NOT NULL DEFAULT '',
    name               TEXT NOT NULL,
    version            TEXT NOT NULL,
    attributes         JSONB NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_downloaded_at TIMESTAMPTZ,
    download_count     BIGINT NOT NULL DEFAULT 0,
    UNIQUE (ecosystem, namespace, name, version)
);

-- The path level: a named file within a component. Its link to the underlying
-- blob lives in `asset_blobs`, not here, which is what makes reference-counted GC
-- possible.
CREATE TABLE assets (
    id           BIGSERIAL PRIMARY KEY,
    component_id BIGINT NOT NULL REFERENCES components (id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    content_type TEXT,
    attributes   JSONB NOT NULL DEFAULT '{}',
    UNIQUE (component_id, path)
);

-- The reference table: the increment/decrement surface of reference counting. A
-- blob with no row here is a garbage-collection candidate.
CREATE TABLE asset_blobs (
    asset_id    BIGINT NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    blob_digest TEXT NOT NULL REFERENCES blobs (digest),
    PRIMARY KEY (asset_id, blob_digest)
);

CREATE INDEX idx_asset_blobs_digest ON asset_blobs (blob_digest);
