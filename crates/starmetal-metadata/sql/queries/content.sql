-- Content-store queries (ADR-0020), consumed by PostgresContentStore.
-- Positional params ($1, $2, ...) bind to tokio-postgres.

-- @name InsertBlobIfAbsent
-- @returns :opt
-- Content-addressed insert. Returns the digest only when a NEW row was created,
-- so the caller writes bytes exactly once (dedup).
INSERT INTO blobs (digest, size, content_type, upstream_hashes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (digest) DO NOTHING
RETURNING digest;

-- @name GetBlob
-- @returns :opt
SELECT digest, size, content_type, upstream_hashes, marked, soft_deleted_at, grace_expires_at, created_at
FROM blobs
WHERE digest = $1;

-- @name UpsertComponent
-- @returns :one
INSERT INTO components (ecosystem, namespace, name, version, repository, attributes)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (ecosystem, namespace, name, version)
DO UPDATE SET attributes = EXCLUDED.attributes, repository = EXCLUDED.repository, updated_at = now()
RETURNING id;

-- @name GetComponentId
-- @returns :opt
SELECT id
FROM components
WHERE ecosystem = $1 AND namespace = $2 AND name = $3 AND version = $4;

-- @name ListComponentVersions
-- @returns :many
-- All versions of a (ecosystem, namespace, name) component, for the retention engine.
SELECT id, version, created_at, updated_at, last_downloaded_at, download_count
FROM components
WHERE ecosystem = $1 AND namespace = $2 AND name = $3;

-- @name ListComponentFamilies
-- @returns :many
-- Distinct (ecosystem, namespace, name, repository) component families, for the retention sweep.
-- `repository` is projected so the sweep can resolve a per-repository retention policy; all versions
-- of a package normally share one repository (if they span repositories, DISTINCT yields one family
-- row per repository, which is an acceptable edge).
SELECT DISTINCT ecosystem, namespace, name, repository FROM components;

-- @name DeleteComponent
-- @returns :exec
-- Cascades to assets + asset_blobs (ON DELETE CASCADE), dropping references so
-- freed blobs become garbage-collection candidates.
DELETE FROM components WHERE id = $1;

-- @name RecordDownload
-- @returns :exec
UPDATE components
SET last_downloaded_at = now(), download_count = download_count + 1
WHERE id = $1;

-- @name UpsertAsset
-- @returns :one
INSERT INTO assets (component_id, path, content_type, attributes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (component_id, path)
DO UPDATE SET content_type = EXCLUDED.content_type, attributes = EXCLUDED.attributes
RETURNING id;

-- @name GetAssetIdByRef
-- @returns :opt
SELECT a.id
FROM assets a
JOIN components c ON a.component_id = c.id
WHERE c.ecosystem = $1 AND c.namespace = $2 AND c.name = $3 AND c.version = $4 AND a.path = $5;

-- @name AddReference
-- @returns :exec
INSERT INTO asset_blobs (asset_id, blob_digest)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- @name RemoveReference
-- @returns :exec
DELETE FROM asset_blobs
WHERE asset_id = $1 AND blob_digest = $2;

-- @name IsBlobReferenced
-- @returns :one
SELECT EXISTS (SELECT 1 FROM asset_blobs WHERE blob_digest = $1) AS referenced;

-- @name ListUnreferencedBlobs
-- @returns :many
SELECT b.digest
FROM blobs b
WHERE b.soft_deleted_at IS NULL
    AND NOT EXISTS (SELECT 1 FROM asset_blobs ab WHERE ab.blob_digest = b.digest);

-- @name MarkBlobUnreferenced
-- @returns :exec
UPDATE blobs SET marked = TRUE WHERE digest = $1;

-- @name SoftDeleteBlob
-- @returns :exec
-- $2 is the caller-computed expiry (now + grace); avoids server-side interval
-- arithmetic whose parameter type scythe cannot infer.
UPDATE blobs
SET soft_deleted_at = now(), grace_expires_at = $2
WHERE digest = $1;

-- @name UndeleteBlob
-- @returns :exec
UPDATE blobs
SET soft_deleted_at = NULL, grace_expires_at = NULL, marked = FALSE
WHERE digest = $1;

-- @name ListExpiredSoftDeleted
-- @returns :many
-- $1 is the caller's "as of" instant. Comparing grace_expires_at (also set from
-- the caller's clock in SoftDeleteBlob) against a caller-supplied timestamp keeps
-- the whole grace decision on one authoritative clock, avoiding a client/server
-- clock-skew race when grace is zero.
SELECT digest
FROM blobs
WHERE soft_deleted_at IS NOT NULL AND grace_expires_at < $1;

-- @name DeleteBlob
-- @returns :exec
DELETE FROM blobs WHERE digest = $1;
