-- Battle.net Friends System migration
-- Run against the 'auth' database

ALTER TABLE `battlenet_accounts`
  ADD COLUMN `battletag` VARCHAR(64) NOT NULL DEFAULT '' AFTER `email`;

CREATE TABLE IF NOT EXISTS `battlenet_friends` (
  `id`        INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `account1`  INT UNSIGNED NOT NULL,
  `account2`  INT UNSIGNED NOT NULL,
  `created`   INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_pair` (`account1`,`account2`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `battlenet_invitations` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `inviter_id`        INT UNSIGNED NOT NULL,
  `invitee_id`        INT UNSIGNED NOT NULL,
  `inviter_battletag` VARCHAR(64) NOT NULL DEFAULT '',
  `invitee_battletag` VARCHAR(64) NOT NULL DEFAULT '',
  `created`           INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_inv` (`inviter_id`,`invitee_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
