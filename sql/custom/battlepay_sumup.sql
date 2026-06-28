-- ───────────────────────────────────────────────────────────────────────────
-- Battlepay nativo → pasarela SumUp (NovaWeb)
-- Se aplica sobre la base de datos `auth` (LoginDatabase).
--
-- Flujo:
--   1) El jugador pulsa "Comprar" en la tienda nativa del cliente.
--   2) El worldserver (SendMakePurchase) busca el producto en `battlepay_price`.
--      Si tiene precio en €, crea una orden PENDING aquí y NO exige puntos.
--   3) El cliente abre /login/sso → /es/checkout (NovaWeb) y paga con SumUp.
--   4) NovaWeb marca la orden PAID (creditPaymentIfPaid).
--   5) El worldserver (BattlepayManager::Update) ve la orden PAID del jugador
--      conectado y la entrega con ProcessDelivery → la marca DELIVERED.
-- ───────────────────────────────────────────────────────────────────────────

-- Órdenes de compra (las escribe el worldserver, las lee/actualiza NovaWeb).
CREATE TABLE IF NOT EXISTS `battlepay_orders` (
  `id`           INT          NOT NULL AUTO_INCREMENT,
  `reference`    VARCHAR(64)  NOT NULL,
  `account_id`   INT          NOT NULL,                 -- auth.account.id (cuenta de juego)
  `product_id`   INT          NOT NULL,                 -- Battlepay ProductID nativo
  `product_name` VARCHAR(120) NOT NULL DEFAULT '',
  `price_eur`    DECIMAL(10,2) NOT NULL DEFAULT 0,
  `status`       VARCHAR(16)  NOT NULL DEFAULT 'PENDING', -- PENDING | PAID | DELIVERED
  `created_at`   INT          NOT NULL,
  `paid_at`      INT          NULL,
  `delivered_at` INT          NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_reference` (`reference`),
  KEY `idx_account_status` (`account_id`, `status`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Mapa producto nativo → precio real en €. Si un ProductID NO está aquí (o
-- enabled=0), el worldserver usa el flujo clásico de puntos para ese producto.
CREATE TABLE IF NOT EXISTS `battlepay_price` (
  `product_id`   INT          NOT NULL,
  `product_name` VARCHAR(120) NOT NULL DEFAULT '',
  `price_eur`    DECIMAL(10,2) NOT NULL DEFAULT 0,
  `enabled`      TINYINT(1)   NOT NULL DEFAULT 1,
  PRIMARY KEY (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Ejemplo (ajusta product_id al de tu tienda nativa):
INSERT INTO `battlepay_price` (`product_id`, `product_name`, `price_eur`, `enabled`)
VALUES (54811, 'Corcel Celestial', 5.00, 1)
ON DUPLICATE KEY UPDATE `product_name`=VALUES(`product_name`), `price_eur`=VALUES(`price_eur`);
