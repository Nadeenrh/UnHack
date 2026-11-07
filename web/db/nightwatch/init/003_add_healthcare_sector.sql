-- Adds the 'healthcare' sector (clinics, dental, physio, psychology practices).
-- Non-destructive and safe to run more than once: it only widens the ENUM.
--
-- New databases get this automatically (001 already includes it; this is a no-op there).
-- Existing dev databases keep their data, so MySQL won't re-run init/. Apply it by hand:
--   docker exec -i mysql_db mysql -uroot -p"$DB_PASSWORD" < db/nightwatch/init/003_add_healthcare_sector.sql

USE nightwatch;

ALTER TABLE organizations
  MODIFY sector ENUM('municipality','utility','community_org','small_business','other','healthcare')
  NOT NULL DEFAULT 'other';
