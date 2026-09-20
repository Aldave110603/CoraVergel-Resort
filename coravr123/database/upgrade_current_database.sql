-- CoraVergel Resort — safe upgrade for an EXISTING database
-- This does not drop tables or delete existing bookings.
-- Run this once in phpMyAdmin while your current database is named coravergel_resort.

USE coravergel_resort;

SET FOREIGN_KEY_CHECKS=0;

-- Helper: add a column only when it does not already exist.
DROP PROCEDURE IF EXISTS cv_add_column;
DELIMITER $$
CREATE PROCEDURE cv_add_column(IN p_table VARCHAR(64), IN p_column VARCHAR(64), IN p_definition TEXT)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = p_table
          AND COLUMN_NAME = p_column
    ) THEN
        SET @cv_sql = CONCAT('ALTER TABLE `', p_table, '` ADD COLUMN `', p_column, '` ', p_definition);
        PREPARE cv_stmt FROM @cv_sql;
        EXECUTE cv_stmt;
        DEALLOCATE PREPARE cv_stmt;
    END IF;
END$$
DELIMITER ;

-- ADMINS
CALL cv_add_column('admins','full_name',"VARCHAR(100) NULL");
CALL cv_add_column('admins','otp_enabled',"TINYINT(1) NOT NULL DEFAULT 1");
CALL cv_add_column('admins','otp_email',"VARCHAR(255) NULL");

-- If an older schema used admin_name, preserve it in the current full_name field.
SET @has_admin_name = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'admins' AND COLUMN_NAME = 'admin_name'
);
SET @cv_sql = IF(@has_admin_name > 0,
    'UPDATE admins SET full_name = admin_name WHERE full_name IS NULL OR full_name = ''''',
    'SELECT 1');
PREPARE cv_stmt FROM @cv_sql;
EXECUTE cv_stmt;
DEALLOCATE PREPARE cv_stmt;

-- LOGIN ATTEMPTS
CALL cv_add_column('login_attempts','attempts',"INT NOT NULL DEFAULT 0");
SET @has_attempt_count = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'login_attempts' AND COLUMN_NAME = 'attempt_count'
);
SET @cv_sql = IF(@has_attempt_count > 0,
    'UPDATE login_attempts SET attempts = attempt_count',
    'SELECT 1');
PREPARE cv_stmt FROM @cv_sql;
EXECUTE cv_stmt;
DEALLOCATE PREPARE cv_stmt;

-- ROOMS
CALL cv_add_column('rooms','capacity',"INT NOT NULL DEFAULT 1");
CALL cv_add_column('rooms','gallery',"TEXT NULL");
CALL cv_add_column('rooms','badge',"VARCHAR(100) NOT NULL DEFAULT 'Available'");
CALL cv_add_column('rooms','tags',"TEXT NULL");

-- BOOKINGS
CALL cv_add_column('bookings','booking_ref',"VARCHAR(10) NULL");
CALL cv_add_column('bookings','room_count',"INT NOT NULL DEFAULT 1");
CALL cv_add_column('bookings','adults',"INT NOT NULL DEFAULT 1");
CALL cv_add_column('bookings','children',"INT NOT NULL DEFAULT 0");
CALL cv_add_column('bookings','total_price',"DECIMAL(10,2) NOT NULL DEFAULT 0");
CALL cv_add_column('bookings','id_type',"VARCHAR(50) NULL");
CALL cv_add_column('bookings','id_number',"VARCHAR(100) NULL");
CALL cv_add_column('bookings','id_photo',"VARCHAR(255) NULL");
CALL cv_add_column('bookings','contact_number',"VARCHAR(30) NULL");
CALL cv_add_column('bookings','payment_method',"VARCHAR(50) NULL");
CALL cv_add_column('bookings','payment_reference',"VARCHAR(150) NULL");
CALL cv_add_column('bookings','payment_receipt',"VARCHAR(255) NULL");
CALL cv_add_column('bookings','confirmed_at',"DATETIME NULL");

-- Backfill safe defaults for old bookings.
UPDATE bookings SET room_count = 1 WHERE room_count IS NULL OR room_count < 1;
UPDATE bookings SET adults = guests WHERE (adults IS NULL OR adults < 1) AND guests IS NOT NULL;
UPDATE bookings SET children = 0 WHERE children IS NULL;
UPDATE bookings SET total_price = 0 WHERE total_price IS NULL;
UPDATE bookings SET booking_ref = CONCAT('OLD', LPAD(booking_id, 6, '0'))
WHERE booking_ref IS NULL OR booking_ref = '';

-- A unique index is needed by the booking reference lookup.
SET @has_booking_ref_index = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'bookings'
      AND INDEX_NAME = 'uq_booking_ref'
);
SET @cv_sql = IF(@has_booking_ref_index = 0,
    'ALTER TABLE bookings ADD UNIQUE KEY uq_booking_ref (booking_ref)',
    'SELECT 1');
PREPARE cv_stmt FROM @cv_sql;
EXECUTE cv_stmt;
DEALLOCATE PREPARE cv_stmt;

-- Keep transactions/row locking reliable.
ALTER TABLE admins ENGINE=InnoDB;
ALTER TABLE rooms ENGINE=InnoDB;
ALTER TABLE bookings ENGINE=InnoDB;
ALTER TABLE login_attempts ENGINE=InnoDB;
ALTER TABLE login_history ENGINE=InnoDB;
ALTER TABLE remember_tokens ENGINE=InnoDB;
ALTER TABLE otp_codes ENGINE=InnoDB;

DROP PROCEDURE IF EXISTS cv_add_column;
SET FOREIGN_KEY_CHECKS=1;

SELECT 'CoraVergel schema upgrade completed.' AS result;
