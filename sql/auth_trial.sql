-- 7-day trial account support
-- trial_expiry: 0 = not a trial account; unix timestamp when trial period expires
ALTER TABLE `battlenet_accounts`
ADD COLUMN `trial_expiry` INT UNSIGNED NOT NULL DEFAULT 0
COMMENT '0 = not a trial; unix timestamp when 7-day trial expires';
