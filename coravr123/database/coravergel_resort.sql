-- CoraVergel Resort — full schema for a FRESH database.
-- Run this once on an empty database (phpMyAdmin, or `mysql -u root -p < coravergel_resort.sql`).
--
-- If you already have a running database with real bookings in it, do NOT
-- run this file — use database/upgrade_current_database.sql instead, which
-- only adds missing columns and never drops or recreates existing tables.
--
-- This file replaces the previous version, which had two bugs that made it
-- fail on a truly fresh install:
--   1. A missing comma between `bookings.id_photo` and `bookings.id_type`
--      caused a straight SQL syntax error.
--   2. `remember_tokens` was created with a FOREIGN KEY to `admins` before
--      the `admins` table existed yet — MySQL rejects a foreign key to a
--      table that hasn't been created. Tables are now ordered so every
--      FOREIGN KEY points at a table already created above it.
-- It also folds in every column that database/upgrade_current_database.sql
-- used to patch on afterward (full_name, otp_enabled, otp_email, booking_ref,
-- room_count, payment_*, confirmed_at, badge, gallery, tags, etc.), so a
-- fresh install no longer needs to run both files — upgrade_current_database.sql
-- remains there for upgrading an existing installation that predates this file.

CREATE DATABASE IF NOT EXISTS coravergel_resort;
USE coravergel_resort;

-- ══════════════════════════════════════════════
-- ADMINS
-- ══════════════════════════════════════════════
CREATE TABLE admins (
    admin_id    INT AUTO_INCREMENT PRIMARY KEY,
    full_name   VARCHAR(100) NOT NULL,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    email       VARCHAR(100) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    role        VARCHAR(20)  NOT NULL DEFAULT 'admin',
    otp_enabled TINYINT(1)   NOT NULL DEFAULT 1,
    otp_email   VARCHAR(255) NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ══════════════════════════════════════════════
-- ROOMS
-- ══════════════════════════════════════════════
CREATE TABLE rooms (
    room_id     INT AUTO_INCREMENT PRIMARY KEY,
    capacity    INT NOT NULL DEFAULT 1,
    room_name   VARCHAR(100) NOT NULL UNIQUE,
    price       DECIMAL(10,2) NOT NULL,
    sale_price  DECIMAL(10,2) NULL,
    description TEXT NULL,
    image       VARCHAR(255) NULL,
    gallery     TEXT NULL,
    badge       VARCHAR(100) NOT NULL DEFAULT 'Available',
    tags        TEXT NULL,
    total_units INT NOT NULL DEFAULT 1,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ══════════════════════════════════════════════
-- BOOKINGS
-- (guests book without an account — no user_id/FK here by design)
-- ══════════════════════════════════════════════
CREATE TABLE bookings (
    booking_id         INT AUTO_INCREMENT PRIMARY KEY,
    booking_ref        VARCHAR(10) NULL,
    room_type          VARCHAR(100) NOT NULL,
    room_count         INT NOT NULL DEFAULT 1,
    check_in           DATE NOT NULL,
    check_out          DATE NOT NULL,
    guests             INT NOT NULL DEFAULT 1,
    adults             INT NOT NULL DEFAULT 1,
    children           INT NOT NULL DEFAULT 0,
    total_price        DECIMAL(10,2) NOT NULL DEFAULT 0,
    guest_name         VARCHAR(150) NOT NULL,
    guest_email        VARCHAR(150) NOT NULL,
    id_type            VARCHAR(50)  NULL,
    id_number          VARCHAR(100) NULL,
    id_photo           VARCHAR(255) NULL,
    contact_number     VARCHAR(30)  NULL,
    payment_method     VARCHAR(50)  NULL,
    payment_reference  VARCHAR(150) NULL,
    payment_receipt    VARCHAR(255) NULL,
    status             ENUM('pending','confirmed','cancelled') NOT NULL DEFAULT 'pending',
    confirmed_at       DATETIME NULL DEFAULT NULL,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_booking_ref (booking_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ══════════════════════════════════════════════
-- LOGIN SECURITY
-- ══════════════════════════════════════════════
CREATE TABLE login_attempts (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    email        VARCHAR(100) NOT NULL,
    attempts     INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ip_address   VARCHAR(45) NULL,
    UNIQUE KEY uniq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE login_history (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    admin_id     INT NOT NULL,
    username     VARCHAR(50) NOT NULL,
    ip_address   VARCHAR(45) NOT NULL,
    user_agent   VARCHAR(255) NULL,
    login_method VARCHAR(20) NOT NULL,
    logged_in_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    KEY idx_admin_id (admin_id),
    CONSTRAINT fk_login_history_admin FOREIGN KEY (admin_id) REFERENCES admins(admin_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE remember_tokens (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    admin_id       INT NOT NULL,
    selector       VARCHAR(18) NOT NULL,
    validator_hash CHAR(64) NOT NULL,
    expires_at     DATETIME NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_selector (selector),
    KEY idx_admin_id (admin_id),
    CONSTRAINT fk_remember_admin FOREIGN KEY (admin_id) REFERENCES admins(admin_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE otp_codes (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    email      VARCHAR(255) NOT NULL,
    otp        VARCHAR(10) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    KEY idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ══════════════════════════════════════════════
-- SEED DATA — safe to re-run; skips rooms that already exist
-- ══════════════════════════════════════════════
INSERT INTO rooms (room_name, price, total_units) VALUES
('Duplex Room',      3200, 5),
('Family Room',      6000, 3),
('Small Bahay Kubo', 2100, 4),
('Large Bahay Kubo', 3200, 3)
ON DUPLICATE KEY UPDATE room_name = room_name;

-- No admin account is created here on purpose — passwords should never be
-- hardcoded in a schema file that might end up in source control. Create
-- your admin account with scripts/create_admin.php after running this file.
