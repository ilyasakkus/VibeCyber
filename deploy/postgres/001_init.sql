BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('web', 'source', 'mobile', 'desktop')),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    -- Query strings, credentials and local absolute paths must not be stored here.
    location_redacted TEXT NOT NULL,
    locator_fingerprint TEXT NOT NULL CHECK (locator_fingerprint ~ '^[a-f0-9]{64}$'),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, target_type, locator_fingerprint)
);

CREATE TABLE target_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK (method IN ('dns_txt', 'http_well_known', 'local_agent', 'manual')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'expired', 'revoked')),
    challenge_hash TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);

CREATE TABLE scan_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    profile TEXT NOT NULL CHECK (profile IN ('observe', 'safe', 'active')),
    scope JSONB NOT NULL,
    rate_limit_per_second INTEGER NOT NULL CHECK (rate_limit_per_second BETWEEN 1 AND 100),
    max_concurrency INTEGER NOT NULL CHECK (max_concurrency BETWEEN 1 AND 20),
    starts_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by UUID NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > starts_at)
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    authorization_id UUID REFERENCES scan_authorizations(id) ON DELETE RESTRICT,
    profile TEXT NOT NULL CHECK (profile IN ('observe', 'safe', 'active')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'cancelling', 'cancelled', 'completed', 'partial', 'failed')),
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by UUID NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (finished_at IS NULL OR started_at IS NOT NULL),
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'running', 'succeeded', 'failed', 'cancelled')),
    attempt SMALLINT NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 10),
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE TABLE module_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    rule_pack_version TEXT,
    image_digest TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'timed_out', 'cancelled')),
    limits JSONB NOT NULL,
    sanitized_error TEXT,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ
);

CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('input', 'raw_result', 'report', 'sbom')),
    object_key TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, object_key)
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    verification_status TEXT NOT NULL CHECK (verification_status IN ('unverified', 'observed', 'verified')),
    cwe_id INTEGER CHECK (cwe_id IS NULL OR cwe_id > 0),
    cve_id TEXT,
    cvss_vector TEXT,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved', 'accepted_risk', 'false_positive')),
    UNIQUE (organization_id, target_id, fingerprint),
    CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE finding_occurrences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module_run_id UUID REFERENCES module_runs(id) ON DELETE SET NULL,
    location JSONB NOT NULL,
    -- Evidence must already be redacted before insertion.
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (finding_id, scan_id, location)
);

CREATE TABLE suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    created_by UUID NOT NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id UUID,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX scans_org_created_idx ON scans (organization_id, created_at DESC);
CREATE INDEX scans_target_created_idx ON scans (target_id, created_at DESC);
CREATE INDEX scan_jobs_claim_idx ON scan_jobs (state, queued_at) WHERE state = 'queued';
CREATE INDEX findings_org_severity_idx ON findings (organization_id, severity, last_seen_at DESC);
CREATE INDEX occurrences_scan_idx ON finding_occurrences (scan_id, discovered_at DESC);
CREATE INDEX audit_org_created_idx ON audit_events (organization_id, created_at DESC);

COMMIT;
