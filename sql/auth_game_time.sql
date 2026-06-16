-- Game time subscription column for battlenet_accounts
-- 0 = unlimited access; non-zero = unix timestamp when subscription expires
ALTER TABLE `battlenet_accounts`
ADD COLUMN `game_time_expiry` INT UNSIGNED NOT NULL DEFAULT 0
COMMENT '0 = unlimited; unix timestamp when game time expires';
