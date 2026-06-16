-- Parental controls per BNet account
-- schedule: 0-1439 minutes from midnight; 1440 = end of day (unrestricted)
-- start >= end means the day is completely blocked
CREATE TABLE IF NOT EXISTS `battlenet_parental_controls` (
  `battlenet_account_id` INT UNSIGNED NOT NULL,
  `enabled`              TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  `session_limit_min`    SMALLINT UNSIGNED NOT NULL DEFAULT 0
    COMMENT '0 = no limit; maximum session length in minutes',
  `sun_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `sun_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  `mon_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `mon_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  `tue_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `tue_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  `wed_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `wed_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  `thu_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `thu_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  `fri_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `fri_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  `sat_start`  SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  `sat_end`    SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
  PRIMARY KEY (`battlenet_account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
