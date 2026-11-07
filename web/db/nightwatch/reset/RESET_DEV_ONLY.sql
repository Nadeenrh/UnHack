-- DEV ONLY. DESTROYS THE ENTIRE NIGHTWATCH DATABASE.
--
-- Never run this automatically, from app code, or against anything with real data.
-- Run it by hand, then re-run db/nightwatch/init/*.sql in order:
--
--   docker exec -i mysql_db mysql -uroot -p < db/nightwatch/reset/RESET_DEV_ONLY.sql
--
-- Kept separate from the init scripts on purpose, so a normal start can never wipe data.

DROP DATABASE IF EXISTS nightwatch;
