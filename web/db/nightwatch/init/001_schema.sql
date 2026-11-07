-- Nightwatch schema v0.1 (MySQL 8)
--
-- NON-DESTRUCTIVE: never drops a database, table or row (it only re-creates the two
-- audit triggers). Safe to run again against an existing database.
-- MySQL's Docker image only runs files in /docker-entrypoint-initdb.d when the data
-- directory is empty, so restarting the containers never wipes data.
-- To wipe a DEV database on purpose, use db/nightwatch/reset/RESET_DEV_ONLY.sql by hand.
--
-- Tenancy: every customer-owned row carries org_id. Child rows reference their parent
-- by (id, org_id), so the database itself refuses to link an incident in one org to an
-- asset, action or evidence row from another org. The app still scopes every query by
-- the org from the session; this is the second layer.

CREATE DATABASE IF NOT EXISTS nightwatch CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE nightwatch;

-- ---------------------------------------------------------------------------
-- Organizations, people, access
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS organizations (
  org_id      CHAR(36)     NOT NULL PRIMARY KEY,
  name        VARCHAR(150) NOT NULL,
  slug        VARCHAR(80)  NOT NULL UNIQUE,
  sector      ENUM('municipality','utility','community_org','small_business','other','healthcare') NOT NULL DEFAULT 'other',
  plan        ENUM('pilot','standard','plus') NOT NULL DEFAULT 'pilot',
  status      ENUM('active','suspended') NOT NULL DEFAULT 'active',
  incident_seq INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'last INC-number issued; bumped atomically',
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
);

-- platform_role is for us (the provider). Customer roles live in memberships.
CREATE TABLE IF NOT EXISTS users (
  user_id        CHAR(36)     NOT NULL PRIMARY KEY,
  first_name     VARCHAR(100) NOT NULL,
  last_name      VARCHAR(100) NOT NULL,
  email          VARCHAR(150) NOT NULL UNIQUE,
  username       VARCHAR(70)  UNIQUE,
  password_hash  VARCHAR(255) NOT NULL,
  platform_role  ENUM('none','provider_staff','provider_admin') NOT NULL DEFAULT 'none',
  is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
  last_login_at  DATETIME(3)  NULL,
  created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
);

CREATE TABLE IF NOT EXISTS memberships (
  org_id      CHAR(36)    NOT NULL,
  user_id     CHAR(36)    NOT NULL,
  role        ENUM('owner','approver','analyst','viewer') NOT NULL,
  created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (org_id, user_id),
  KEY idx_memberships_user (user_id),
  CONSTRAINT fk_memberships_org  FOREIGN KEY (org_id)  REFERENCES organizations(org_id),
  CONSTRAINT fk_memberships_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Login sessions. The browser holds a random token in an HttpOnly cookie; only its
-- SHA-256 is stored, so a database leak doesn't hand out live sessions.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash   CHAR(64)     NOT NULL PRIMARY KEY,
  user_id      CHAR(36)     NOT NULL,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at   DATETIME(3)  NOT NULL,
  revoked_at   DATETIME(3)  NULL,
  ip           VARCHAR(45)  NULL,
  user_agent   VARCHAR(255) NULL,
  KEY idx_sessions_user (user_id),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Provider staff opening a customer's workspace. Every open is recorded and time-boxed.
CREATE TABLE IF NOT EXISTS support_sessions (
  session_id     CHAR(36)     NOT NULL PRIMARY KEY,
  org_id         CHAR(36)     NOT NULL,
  staff_user_id  CHAR(36)     NOT NULL,
  reason         VARCHAR(300) NOT NULL,
  started_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at     DATETIME(3)  NOT NULL,
  ended_at       DATETIME(3)  NULL,
  KEY idx_support_org (org_id, started_at),
  CONSTRAINT fk_support_org   FOREIGN KEY (org_id)        REFERENCES organizations(org_id),
  CONSTRAINT fk_support_staff FOREIGN KEY (staff_user_id) REFERENCES users(user_id)
);

-- ---------------------------------------------------------------------------
-- What we monitor
-- ---------------------------------------------------------------------------

-- A site is one customer location sending telemetry. Its ingest key decides the org
-- for everything it sends. Only a SHA-256 hash of the key is stored; the key is shown once.
CREATE TABLE IF NOT EXISTS sites (
  site_id            CHAR(36)     NOT NULL PRIMARY KEY,
  org_id             CHAR(36)     NOT NULL,
  name               VARCHAR(150) NOT NULL,
  ingest_key_hash    CHAR(64)     NOT NULL UNIQUE,
  ingest_key_prefix  VARCHAR(12)  NOT NULL,
  created_at         DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  revoked_at         DATETIME(3)  NULL,
  UNIQUE KEY uq_sites_id_org (site_id, org_id),
  CONSTRAINT fk_sites_org FOREIGN KEY (org_id) REFERENCES organizations(org_id)
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id      CHAR(36)     NOT NULL PRIMARY KEY,
  org_id        CHAR(36)     NOT NULL,
  site_id       CHAR(36)     NOT NULL,
  hostname      VARCHAR(255) NOT NULL,
  ip            VARCHAR(45)  NULL,
  kind          ENUM('endpoint','server','network','other') NOT NULL DEFAULT 'endpoint',
  os            VARCHAR(100) NULL,
  agent_ref     VARCHAR(64)  NULL COMMENT 'e.g. Wazuh agent id',
  agent_status  ENUM('online','offline','never_connected') NOT NULL DEFAULT 'never_connected',
  last_seen_at  DATETIME(3)  NULL,
  created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_assets_id_org (asset_id, org_id),
  UNIQUE KEY uq_assets_org_host (org_id, hostname),
  CONSTRAINT fk_assets_site FOREIGN KEY (site_id, org_id) REFERENCES sites(site_id, org_id)
);

-- ---------------------------------------------------------------------------
-- Detection and investigation
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
  incident_id         CHAR(36)     NOT NULL PRIMARY KEY,
  org_id              CHAR(36)     NOT NULL,
  ref                 VARCHAR(20)  NOT NULL,
  title               VARCHAR(200) NOT NULL,
  summary             TEXT         NOT NULL,
  severity            ENUM('low','medium','high','critical') NOT NULL,
  verdict             ENUM('malicious','suspicious','benign','undetermined') NOT NULL DEFAULT 'undetermined',
  confidence          DECIMAL(4,3) NOT NULL DEFAULT 0,
  status              ENUM('open','investigating','awaiting_approval','contained','resolved','false_positive') NOT NULL DEFAULT 'open',
  data_source         ENUM('live','replay','fixture') NOT NULL DEFAULT 'live',
  injection_detected  BOOLEAN      NOT NULL DEFAULT FALSE,
  injection_notes     TEXT         NULL,
  detected_at         DATETIME(3)  NOT NULL,
  created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  closed_at           DATETIME(3)  NULL,
  CONSTRAINT chk_incidents_confidence CHECK (confidence BETWEEN 0 AND 1),
  UNIQUE KEY uq_incidents_id_org (incident_id, org_id),
  UNIQUE KEY uq_incidents_org_ref (org_id, ref),
  KEY idx_incidents_org_status (org_id, status, detected_at),
  CONSTRAINT fk_incidents_org FOREIGN KEY (org_id) REFERENCES organizations(org_id)
);

-- Raw alerts as received. Dedupe on (org, source, source_alert_id).
CREATE TABLE IF NOT EXISTS alerts (
  alert_id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  org_id            CHAR(36)     NOT NULL,
  site_id           CHAR(36)     NOT NULL,
  asset_id          CHAR(36)     NULL,
  incident_id       CHAR(36)     NULL,
  source            ENUM('wazuh','pihole','logwatch','replay') NOT NULL,
  source_alert_id   VARCHAR(128) NOT NULL,
  rule_id           VARCHAR(32)  NULL,
  rule_level        TINYINT      NULL,
  rule_description  VARCHAR(500) NULL,
  raw               JSON         NOT NULL COMMENT 'UNTRUSTED: may contain attacker-controlled text',
  observed_at       DATETIME(3)  NOT NULL,
  received_at       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_alerts_dedupe (org_id, source, source_alert_id),
  KEY idx_alerts_org_time (org_id, received_at),
  CONSTRAINT fk_alerts_site     FOREIGN KEY (site_id, org_id)     REFERENCES sites(site_id, org_id),
  CONSTRAINT fk_alerts_asset    FOREIGN KEY (asset_id, org_id)    REFERENCES assets(asset_id, org_id),
  CONSTRAINT fk_alerts_incident FOREIGN KEY (incident_id, org_id) REFERENCES incidents(incident_id, org_id)
);

CREATE TABLE IF NOT EXISTS incident_assets (
  org_id       CHAR(36) NOT NULL,
  incident_id  CHAR(36) NOT NULL,
  asset_id     CHAR(36) NOT NULL,
  PRIMARY KEY (incident_id, asset_id),
  CONSTRAINT fk_ia_incident FOREIGN KEY (incident_id, org_id) REFERENCES incidents(incident_id, org_id),
  CONSTRAINT fk_ia_asset    FOREIGN KEY (asset_id, org_id)    REFERENCES assets(asset_id, org_id)
);

CREATE TABLE IF NOT EXISTS incident_mitre (
  incident_id     CHAR(36)     NOT NULL,
  technique_id    VARCHAR(16)  NOT NULL,
  technique_name  VARCHAR(150) NOT NULL,
  PRIMARY KEY (incident_id, technique_id),
  CONSTRAINT fk_mitre_incident FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id  BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  org_id       CHAR(36)     NOT NULL,
  incident_id  CHAR(36)     NOT NULL,
  claim        TEXT         NOT NULL,
  source       ENUM('wazuh','sysmon','windows_security','virustotal','urlscan','pihole','logwatch','agent') NOT NULL,
  log_ref      VARCHAR(255) NULL,
  observed_at  DATETIME(3)  NOT NULL,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_evidence_incident (incident_id),
  CONSTRAINT fk_evidence_incident FOREIGN KEY (incident_id, org_id) REFERENCES incidents(incident_id, org_id)
);

CREATE TABLE IF NOT EXISTS agent_runs (
  run_id          CHAR(36)     NOT NULL PRIMARY KEY,
  org_id          CHAR(36)     NOT NULL,
  incident_id     CHAR(36)     NOT NULL,
  agent           ENUM('triage','intel','investigator') NOT NULL,
  status          ENUM('running','succeeded','failed','skipped') NOT NULL DEFAULT 'running',
  model           VARCHAR(100) NULL COMMENT 'NULL = rule-based fallback',
  started_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  finished_at     DATETIME(3)  NULL,
  output_summary  TEXT         NULL,
  error           TEXT         NULL,
  KEY idx_runs_incident (incident_id),
  CONSTRAINT fk_runs_incident FOREIGN KEY (incident_id, org_id) REFERENCES incidents(incident_id, org_id)
);

-- Threat-intel lookups, cached to stay inside free API quotas.
CREATE TABLE IF NOT EXISTS intel_cache (
  indicator_type  ENUM('ip','domain','url','hash') NOT NULL,
  indicator       VARCHAR(512) NOT NULL,
  provider        ENUM('virustotal','urlscan') NOT NULL,
  verdict         ENUM('malicious','suspicious','harmless','unknown') NOT NULL DEFAULT 'unknown',
  summary         JSON         NULL,
  fetched_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at      DATETIME(3)  NOT NULL,
  PRIMARY KEY (indicator_type, indicator, provider)
);

-- ---------------------------------------------------------------------------
-- Response: policy, actions, approvals
-- ---------------------------------------------------------------------------

-- Per-org autonomy dial. Code reads this; the AI never does.
CREATE TABLE IF NOT EXISTS policies (
  org_id       CHAR(36)    NOT NULL,
  action_type  ENUM('block_ip','block_domain','isolate_host','quarantine_file','disable_account','notify_only') NOT NULL,
  risk         ENUM('low','high','critical') NOT NULL,
  mode         ENUM('auto','ask','never') NOT NULL,
  updated_by   CHAR(36)    NULL,
  updated_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (org_id, action_type),
  CONSTRAINT fk_policies_org  FOREIGN KEY (org_id)     REFERENCES organizations(org_id),
  CONSTRAINT fk_policies_user FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- One row per proposed response. Approving is a conditional UPDATE bound to
-- (action_id, org_id, target, status = 'awaiting_approval'); zero rows updated = refused.
-- idempotency_key stops the same action from being executed twice.
CREATE TABLE IF NOT EXISTS actions (
  action_id        CHAR(36)     NOT NULL PRIMARY KEY,
  org_id           CHAR(36)     NOT NULL,
  incident_id      CHAR(36)     NOT NULL,
  type             ENUM('block_ip','block_domain','isolate_host','quarantine_file','disable_account','notify_only') NOT NULL,
  target           VARCHAR(255) NOT NULL,
  risk             ENUM('low','high','critical') NOT NULL,
  policy_decision  ENUM('auto','ask','never') NOT NULL,
  status           ENUM('proposed','awaiting_approval','approved','executing','succeeded','failed','denied','expired') NOT NULL,
  rationale        TEXT         NOT NULL,
  idempotency_key  CHAR(64)     NOT NULL UNIQUE,
  requested_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at       DATETIME(3)  NULL,
  decided_by       CHAR(36)     NULL COMMENT 'NULL with decided_at set = decided by policy (auto)',
  decided_at       DATETIME(3)  NULL,
  executed_at      DATETIME(3)  NULL,
  completed_at     DATETIME(3)  NULL,
  result_verified  BOOLEAN      NULL,
  result_detail    TEXT         NULL,
  KEY idx_actions_org_status (org_id, status),
  KEY idx_actions_incident (incident_id),
  CONSTRAINT fk_actions_incident FOREIGN KEY (incident_id, org_id) REFERENCES incidents(incident_id, org_id),
  CONSTRAINT fk_actions_decider  FOREIGN KEY (decided_by) REFERENCES users(user_id)
);

-- ---------------------------------------------------------------------------
-- Audit log: append-only from the application's point of view.
-- The triggers stop UPDATE/DELETE through normal queries. A database administrator
-- can still drop triggers, so call this "tamper-evident to the app", not tamper-proof.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_log (
  audit_id     BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  org_id       CHAR(36)     NULL COMMENT 'NULL = platform-level event',
  actor_type   ENUM('user','agent','system','policy','provider_support') NOT NULL,
  actor_id     VARCHAR(64)  NULL,
  event        VARCHAR(64)  NOT NULL,
  incident_id  CHAR(36)     NULL,
  action_id    CHAR(36)     NULL,
  details      JSON         NULL,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_audit_org_time (org_id, created_at),
  KEY idx_audit_incident (incident_id)
);

DROP TRIGGER IF EXISTS audit_log_no_update;
DROP TRIGGER IF EXISTS audit_log_no_delete;

DELIMITER //
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
FOR EACH ROW BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
END//
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
FOR EACH ROW BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
END//
DELIMITER ;
