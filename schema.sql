-- ============================================================
-- LogSentinel Database Schema
-- Creates the two core tables used by the tool:
--   1. log_entries  — stores every parsed log line
--   2. threat_events — stores every detected threat,
--                      linked back to its originating log entry
-- ============================================================

-- Drop tables in reverse dependency order (for fresh re-runs)
DROP TABLE IF EXISTS threat_events;
DROP TABLE IF EXISTS log_entries;

-- -------------------------------------------------------
-- Table: log_entries
-- One row per parsed line across all log sources
-- -------------------------------------------------------
CREATE TABLE log_entries (
    id          INT AUTO_INCREMENT PRIMARY KEY,

    -- Which file was parsed and what type of log it is
    source_file VARCHAR(255)   NOT NULL,
    log_type    VARCHAR(50)    NOT NULL,          -- 'SSH', 'APACHE', 'WINDOWS'

    -- Parsed fields (NULL when not applicable to the log type)
    timestamp   DATETIME,
    ip_address  VARCHAR(45),                      -- supports IPv4 and IPv6
    user        VARCHAR(100),
    action      VARCHAR(255),
    status      VARCHAR(50),

    -- The original unmodified log line for forensic reference
    raw_line    TEXT,

    -- Row insertion time
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -------------------------------------------------------
-- Table: threat_events
-- One row per detected threat, may reference a log_entry
-- -------------------------------------------------------
CREATE TABLE threat_events (
    id            INT AUTO_INCREMENT PRIMARY KEY,

    -- Optional link to the originating log line
    log_entry_id  INT,

    -- Threat classification
    threat_type   VARCHAR(100) NOT NULL,          -- e.g. 'BRUTE_FORCE', 'REPEATED_404'
    severity      ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL,

    -- Human-readable explanation of the threat
    description   TEXT,

    -- When the threat was flagged by the detector
    detected_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- If the referenced log entry is deleted, keep the threat but clear the FK
    FOREIGN KEY (log_entry_id) REFERENCES log_entries(id) ON DELETE SET NULL
);
