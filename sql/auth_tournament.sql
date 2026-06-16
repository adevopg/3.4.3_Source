-- Arena Tournament realm subscription
-- tournament_expiry: 0 = no subscription; unix timestamp when subscription expires; 0xFFFFFFFF = permanent
ALTER TABLE `battlenet_accounts`
ADD COLUMN `tournament_expiry` INT UNSIGNED NOT NULL DEFAULT 0
COMMENT '0 = not subscribed; unix timestamp when tournament subscription expires';

-- Mark realms as tournament realms in the realm list
ALTER TABLE `realmlist`
ADD COLUMN `tournament` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0
COMMENT '1 = Arena Tournament realm; requires tournament subscription to enter';
