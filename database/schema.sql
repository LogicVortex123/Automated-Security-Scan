-- Automated Security Assessment Dashboard - MySQL schema
-- Create database and table for historical scan results.

CREATE DATABASE IF NOT EXISTS lh_ehr_security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE lh_ehr_security;

CREATE TABLE IF NOT EXISTS security_scans (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  module_name     VARCHAR(128) NOT NULL,
  vulnerabilities_json JSON NOT NULL,
  overall_score   DECIMAL(4,1) NOT NULL COMMENT 'Max CVSS among findings for this scan',
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_module_created (module_name, created_at)
) ENGINE=InnoDB;
