DO $$
BEGIN
    CREATE TYPE ufid_metadata_type AS ENUM (
        'text',
        'image',
        'url',
        'json',
        'number',
        'date',
        'binary',
        'other'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE TYPE ufid_identity_conflict_type AS ENUM (
        'optional_hash_mismatch',
        'required_hash_overlap'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS ufid_file (
    id BIGSERIAL PRIMARY KEY,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    crc32 TEXT NOT NULL CHECK (crc32 ~ '^[0-9a-f]{8}$'),
    md5 TEXT NOT NULL CHECK (md5 ~ '^[0-9a-f]{32}$'),
    sha1 TEXT NOT NULL CHECK (sha1 ~ '^[0-9a-f]{40}$'),
    sha256 TEXT CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    blake3 TEXT CHECK (blake3 IS NULL OR blake3 ~ '^[0-9a-f]{64}$'),
    UNIQUE (size_bytes, crc32, md5, sha1)
);

CREATE INDEX IF NOT EXISTS idx_ufid_file_crc32 ON ufid_file (crc32);
CREATE INDEX IF NOT EXISTS idx_ufid_file_md5 ON ufid_file (md5);
CREATE INDEX IF NOT EXISTS idx_ufid_file_sha1 ON ufid_file (sha1);
CREATE INDEX IF NOT EXISTS idx_ufid_file_sha256 ON ufid_file (sha256);
CREATE INDEX IF NOT EXISTS idx_ufid_file_blake3 ON ufid_file (blake3);

CREATE TABLE IF NOT EXISTS ufid_file_meta (
    id BIGSERIAL PRIMARY KEY,
    file_id BIGINT NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    metadata_type ufid_metadata_type NOT NULL,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    value TEXT NOT NULL,
    notes TEXT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ufid_file_meta_unique
    ON ufid_file_meta (
        file_id,
        metadata_type,
        name,
        value,
        COALESCE(notes, '')
    );

CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_file_id ON ufid_file_meta (file_id);
CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_name ON ufid_file_meta (name);
CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_type ON ufid_file_meta (metadata_type);
CREATE INDEX IF NOT EXISTS idx_ufid_file_meta_added_at ON ufid_file_meta (added_at);

CREATE TABLE IF NOT EXISTS ufid_archive_member (
    id BIGSERIAL PRIMARY KEY,
    parent_file_id BIGINT NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    child_file_id BIGINT REFERENCES ufid_file(id) ON DELETE CASCADE,
    archive_path TEXT,
    CHECK (child_file_id IS NOT NULL OR archive_path IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ufid_archive_member_unique
    ON ufid_archive_member (
        parent_file_id,
        COALESCE(child_file_id, -1),
        COALESCE(archive_path, '')
    );

CREATE INDEX IF NOT EXISTS idx_ufid_archive_member_parent
    ON ufid_archive_member (parent_file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_archive_member_child
    ON ufid_archive_member (child_file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_archive_member_path
    ON ufid_archive_member (archive_path);

CREATE TABLE IF NOT EXISTS ufid_identity_conflict (
    id BIGSERIAL PRIMARY KEY,
    file_id BIGINT NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    related_file_id BIGINT REFERENCES ufid_file(id) ON DELETE CASCADE,
    conflict_type ufid_identity_conflict_type NOT NULL,
    algorithm TEXT NOT NULL CHECK (
        algorithm IN ('crc32', 'md5', 'sha1', 'sha256', 'blake3')
    ),
    existing_value TEXT,
    incoming_value TEXT NOT NULL,
    incoming_size_bytes BIGINT NOT NULL CHECK (incoming_size_bytes >= 0),
    incoming_crc32 TEXT NOT NULL CHECK (incoming_crc32 ~ '^[0-9a-f]{8}$'),
    incoming_md5 TEXT NOT NULL CHECK (incoming_md5 ~ '^[0-9a-f]{32}$'),
    incoming_sha1 TEXT NOT NULL CHECK (incoming_sha1 ~ '^[0-9a-f]{40}$'),
    notes TEXT,
    logged_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ufid_identity_conflict_unique
    ON ufid_identity_conflict (
        file_id,
        COALESCE(related_file_id, -1),
        conflict_type,
        algorithm,
        COALESCE(existing_value, ''),
        incoming_value,
        incoming_size_bytes,
        incoming_crc32,
        incoming_md5,
        incoming_sha1,
        COALESCE(notes, '')
    );

CREATE INDEX IF NOT EXISTS idx_ufid_identity_conflict_file
    ON ufid_identity_conflict (file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_identity_conflict_related
    ON ufid_identity_conflict (related_file_id);

CREATE INDEX IF NOT EXISTS idx_ufid_identity_conflict_type
    ON ufid_identity_conflict (conflict_type);

CREATE TABLE IF NOT EXISTS ufid_source (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ufid_file_source (
    file_id BIGINT NOT NULL REFERENCES ufid_file(id) ON DELETE CASCADE,
    source_id BIGINT NOT NULL REFERENCES ufid_source(id),
    external_reference TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, source_id, external_reference)
);

CREATE TABLE IF NOT EXISTS ufid_user_account (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE CHECK (
        username = lower(username) AND length(trim(username)) > 0
    ),
    password_hash TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ufid_role (
    id SMALLSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS ufid_user_role (
    user_id BIGINT NOT NULL REFERENCES ufid_user_account(id) ON DELETE CASCADE,
    role_id SMALLINT NOT NULL REFERENCES ufid_role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS ufid_session (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES ufid_user_account(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_address INET
);

CREATE INDEX IF NOT EXISTS idx_ufid_session_token_hash ON ufid_session (token_hash);
CREATE INDEX IF NOT EXISTS idx_ufid_session_user_id ON ufid_session (user_id);
CREATE INDEX IF NOT EXISTS idx_ufid_session_expires_at ON ufid_session (expires_at);

CREATE TABLE IF NOT EXISTS ufid_audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES ufid_user_account(id),
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ufid_role (name)
VALUES
    ('reader'),
    ('contributor'),
    ('curator'),
    ('admin')
ON CONFLICT (name) DO NOTHING;
