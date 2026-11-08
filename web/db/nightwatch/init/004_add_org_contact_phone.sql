-- Adds a phone number for each client, so the Nightwatch team can reach them.
-- Safe to run more than once (guarded for MySQL 8.4, which has no ADD COLUMN IF NOT EXISTS).
-- New databases already get this column from 001.
--   docker exec -i mysql_db mysql -uroot -p"$DB_PASSWORD" < db/nightwatch/init/004_add_org_contact_phone.sql
USE nightwatch;

SET @exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = 'nightwatch' AND TABLE_NAME = 'organizations' AND COLUMN_NAME = 'contact_phone'
);
SET @ddl := IF(@exists = 0,
  "ALTER TABLE organizations ADD COLUMN contact_phone VARCHAR(32) NULL COMMENT 'client business number, for our team to reach them' AFTER plan",
  "DO 0");
PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
