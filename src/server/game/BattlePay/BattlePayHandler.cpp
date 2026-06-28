#include "Bag.h"
#include "BattlePayPackets.h"
#include "BattlePayMgr.h"
#include "BattlePayData.h"
#include "Config.h"
#include "Containers.h"
#include "DatabaseEnv.h"
#include "ObjectMgr.h"
#include "ScriptMgr.h"
#include "Random.h"
#include "Chat.h"
#include <ctime>
#include <iomanip>
#include <fstream>
#include <sstream>

namespace
{
    uint32 GetBagsFreeSlots(Player* player)
    {
        uint32 freeBagSlots = 0;
        for (uint8 i = INVENTORY_SLOT_BAG_START; i < INVENTORY_SLOT_BAG_END; i++)
            if (auto bag = player->GetBagByPos(i))
                freeBagSlots += bag->GetFreeSlots();

        uint8 inventoryEnd = INVENTORY_SLOT_ITEM_START + player->GetInventorySlotCount();
        for (uint8 i = INVENTORY_SLOT_ITEM_START; i < inventoryEnd; i++)
            if (!player->GetItemByPos(INVENTORY_SLOT_BAG_0, i))
                ++freeBagSlots;

        return freeBagSlots;
    }
}

void WorldSession::SendStartPurchaseResponse(WorldSession* session, Battlepay::Purchase const& purchase, Battlepay::Error const& result)
{
    WorldPackets::BattlePay::StartPurchaseResponse response;
    response.PurchaseID = purchase.PurchaseID;
    response.ClientToken = purchase.ClientToken;
    response.PurchaseResult = result;
    session->SendPacket(response.Write());
};

void WorldSession::SendPurchaseUpdate(WorldSession* session, Battlepay::Purchase const& purchase, uint32 result)
{
    WorldPackets::BattlePay::PurchaseUpdate packet;
    WorldPackets::BattlePay::Purchase data;
    data.PurchaseID = purchase.PurchaseID;
    data.UnkLong = 0;
    data.UnkLong2 = 0;
    data.Status = purchase.Status;
    data.ResultCode = result;
    data.ProductID = purchase.ProductID;
    data.UnkInt = purchase.ServerToken;
    data.WalletName = session->GetBattlePayMgr()->GetDefaultWalletName();
    packet.Purchase.emplace_back(data);
    session->SendPacket(packet.Write());
};

void WorldSession::HandleGetPurchaseListQuery(WorldPackets::BattlePay::GetPurchaseListQuery& /*packet*/)
{
    WorldPackets::BattlePay::PurchaseListResponse packet; // @TODO
    SendPacket(packet.Write());
}

void WorldSession::HandleUpdateVasPurchaseStates(WorldPackets::BattlePay::UpdateVasPurchaseStates& /*packet*/)
{
    WorldPackets::BattlePay::EnumVasPurchaseStatesResponse response;
    response.Result = 0;
    SendPacket(response.Write());
}

void WorldSession::HandleBattlePayDistributionAssign(WorldPackets::BattlePay::DistributionAssignToTarget& packet)
{
    if (!GetBattlePayMgr()->IsAvailable())
        return;

    GetBattlePayMgr()->AssignDistributionToCharacter(packet.TargetCharacter, packet.DistributionID, packet.ProductID, packet.SpecializationID, packet.ChoiceID);
}

void WorldSession::HandleGetProductList(WorldPackets::BattlePay::GetProductList& /*packet*/)
{
    if (!GetBattlePayMgr()->IsAvailable())
        return;

    GetBattlePayMgr()->SendProductList();
    GetBattlePayMgr()->SendAccountCredits();
}

void WorldSession::SendMakePurchase(ObjectGuid targetCharacter, uint32 clientToken, uint32 productID, WorldSession* session)
{
    if (!session || !session->GetBattlePayMgr()->IsAvailable())
        return;

    auto* mgr = session->GetBattlePayMgr();

    if (mgr == nullptr)
        return;

    auto player = session->GetPlayer();
    auto accountID = session->GetAccountId();

    Battlepay::Purchase purchase;
    purchase.ProductID = productID;
    purchase.ClientToken = clientToken;
    purchase.TargetCharacter = targetCharacter;
    purchase.Status = Battlepay::UpdateStatus::Loading;
    purchase.DistributionId = mgr->GenerateNewDistributionId();

    auto getProductInfo = sBattlePayDataStore->GetProductInfoForProduct(productID);
    if (getProductInfo == nullptr)
        return;

    BattlePayData::ProductInfo productInfo = *getProductInfo;

    purchase.CurrentPrice = uint64(productInfo.CurrentPriceFixedPoint);

    mgr->RegisterStartPurchase(purchase);

    auto purchaseData = mgr->GetPurchase();

    // ── TODO el pago va por SumUp (web). NUNCA usamos puntos/créditos. ───────
    // Creamos SIEMPRE una orden PENDING que NovaWeb cobrará por la pasarela; al
    // confirmarse el pago, BattlepayManager::Update la entrega (ProcessDelivery).
    // Precio en €: de `battlepay_price` si está listado; si no, del precio nativo
    // del producto (CurrentPriceFixedPoint / g_CurrencyPrecision, p.ej. $10 → 10.00).
    std::string productName;
    float priceEur = float(productInfo.CurrentPriceFixedPoint) / float(Battlepay::g_CurrencyPrecision);

    if (QueryResult priceRes = LoginDatabase.PQuery(
            "SELECT product_name, price_eur FROM battlepay_price WHERE product_id = {} AND enabled = 1", productID))
    {
        Field* pf = priceRes->Fetch();
        productName = pf[0].GetString();
        priceEur = pf[1].GetFloat();
    }
    LoginDatabase.EscapeString(productName);

    // Una única orden PENDING por (cuenta, producto): limpiamos las anteriores.
    LoginDatabase.PExecute(
        "DELETE FROM battlepay_orders WHERE account_id = {} AND product_id = {} AND status = 'PENDING'",
        accountID, productID);

    std::string reference = "bp_" + std::to_string(accountID) + "_" + std::to_string(productID) +
        "_" + std::to_string(uint32(time(nullptr))) + "_" + std::to_string(urand(1000, 9999));
    LoginDatabase.PExecute(
        "INSERT INTO battlepay_orders (reference, account_id, product_id, product_name, price_eur, status, created_at) "
        "VALUES ('{}', {}, {}, '{}', {:.2f}, 'PENDING', UNIX_TIMESTAMP())",
        reference, accountID, productID, productName, priceEur);

    ChatHandler(session).PSendSysMessage(
        "|cff66ccff[Tienda]|r Abriendo la pasarela de pago...");

    // En vez del flujo de puntos, disparamos el CHECKOUT WEB (pasarela): respondemos
    // OK a StartPurchase y enviamos SMSG_BATTLE_PAY_START_CHECKOUT para que el cliente
    // abra la pasarela. (El pago real se confirma por SumUp; la entrega la hace el poll.)
    purchaseData->PurchaseID = sBattlePayDataStore->GenerateNewPurchaseID();
    SendStartPurchaseResponse(session, *purchaseData, Battlepay::Error::Ok);

    WorldPackets::BattlePay::BattlePayStartCheckout checkout;
    checkout.ClientToken = clientToken;
    checkout.PurchaseID  = purchaseData->PurchaseID;
    session->SendPacket(checkout.Write());
};

void WorldSession::HandleBattlePayStartPurchase(WorldPackets::BattlePay::StartPurchase& packet)
{
    SendMakePurchase(packet.TargetCharacter, packet.ClientToken, packet.ProductID, this);
}

void WorldSession::HandleBattlePayConfirmPurchase(WorldPackets::BattlePay::ConfirmPurchaseResponse& packet)
{
    if (!GetBattlePayMgr()->IsAvailable())
        return;

    auto purchase = GetBattlePayMgr()->GetPurchase();
    if (!purchase)
        return;

    //const auto& productInfo = *sBattlePayDataStore->GetProductInfoForProduct(purchase->ProductID);
    //const auto& displayInfo = *sBattlePayDataStore->GetDisplayInfo(productInfo.Entry);

    if (purchase->Lock)
    {
        SendPurchaseUpdate(this, *purchase, Battlepay::Error::PurchaseDenied);
        return;
    }

    if (purchase->ServerToken != packet.ServerToken || !packet.ConfirmPurchase || purchase->CurrentPrice != packet.ClientCurrentPriceFixedPoint)
    {
        SendPurchaseUpdate(this, *purchase, Battlepay::Error::PurchaseDenied);
        return;
    }

    auto accountBalance = GetBattlePayMgr()->GetBattlePayCredits();
    if (accountBalance < static_cast<uint64>(purchase->CurrentPrice))
    {
        SendPurchaseUpdate(this, *purchase, Battlepay::Error::PurchaseDenied);
        return;
    }

    purchase->Lock = true;
    purchase->Status = Battlepay::UpdateStatus::Finish;

    SendPurchaseUpdate(this, *purchase, Battlepay::Error::Other);
    GetBattlePayMgr()->UpdateBattlePayCredits(purchase->CurrentPrice);
    GetBattlePayMgr()->ProcessDelivery(*purchase, false);
    GetBattlePayMgr()->SendProductList();
}

void WorldSession::HandleBattlePayAckFailedResponse(WorldPackets::BattlePay::BattlePayAckFailedResponse& /*packet*/)
{
}

// CMSG_BATTLE_PAY_OPEN_CHECKOUT (0x3714): el cliente pide abrir la pasarela web.
// Respondemos con SMSG_BATTLE_PAY_START_CHECKOUT (0x2824) para que abra el checkout.
void WorldSession::HandleBattlePayOpenCheckout(WorldPackets::BattlePay::BattlePayOpenCheckout& packet)
{
    std::ostringstream hex;
    hex << std::uppercase << std::hex << std::setfill('0');
    for (uint8 b : packet.RawData)
        hex << std::setw(2) << uint32(b) << ' ';

    Player* plr = GetPlayer();
    TC_LOG_INFO("server.BattlePay",
        "CMSG_BATTLE_PAY_OPEN_CHECKOUT | cuenta {} | jugador {} | ClientToken {} | extra {} bytes: {}",
        GetAccountId(),
        plr ? plr->GetName() : std::string("<sin jugador>"),
        packet.ClientToken,
        uint32(packet.RawData.size()),
        packet.RawData.empty() ? std::string("(ninguno)") : hex.str());

    // ── HIPÓTESIS SSO (RE 12.x): tras OPEN_CHECKOUT el cliente NO espera 0x2824,
    // espera SMSG_GENERATE_SSO_TOKEN_RESPONSE (0x281E) con el token con el que
    // autentica la webview del checkout. No existe CMSG separado: el request va
    // embebido en OPEN_CHECKOUT. Estructura (de 12.x):
    //   uint64 ClientToken (eco) | uint64 IssuedTime | uint64 ExpiryTime | string SSOToken (al final)
    uint32 accountId = GetAccountId();
    uint64 issued = uint64(time(nullptr));
    uint64 expiry = issued + 14400; // 4 h

    // Token que la web (inna.cl) podrá validar → cuenta + orden PENDING.
    std::ostringstream tok;
    tok << "EU-" << accountId << "-" << uint32(issued) << "-" << urand(100000, 999999);
    std::string ssoToken = tok.str();

    // Persistir para validación web (idempotente por cuenta: borra anteriores vivos).
    LoginDatabase.PExecute("DELETE FROM battlepay_sso WHERE account_id = {}", accountId);
    std::string tokEsc = ssoToken; LoginDatabase.EscapeString(tokEsc);
    LoginDatabase.PExecute(
        "INSERT INTO battlepay_sso (account_id, token, issued_at, expiry_at) VALUES ({}, '{}', {}, {})",
        accountId, tokEsc, issued, expiry);

    WorldPacket data(SMSG_GENERATE_SSO_TOKEN_RESPONSE, 25 + ssoToken.size());
    data << uint64(packet.ClientToken);
    data << uint64(issued);
    data << uint64(expiry);
    data << uint8(ssoToken.size()); // el cliente lee 1 byte de longitud antes del token
    data.WriteString(ssoToken);
    SendPacket(&data, true); // forced: 0x281E está registrado STATUS_UNHANDLED (server opcode)

    TC_LOG_INFO("server.BattlePay",
        "SMSG_GENERATE_SSO_TOKEN_RESPONSE enviado | cuenta {} | token '{}' | {} bytes",
        accountId, ssoToken, uint32(24 + ssoToken.size()));
}

void WorldSession::HandleBattlePayRequestPriceInfo(WorldPackets::BattlePay::BattlePayRequestPriceInfo& packet)
{
}

void WorldSession::SendDisplayPromo(int32 promotionID /*= 0*/)
{
    SendPacket(WorldPackets::BattlePay::DisplayPromotion(promotionID).Write());
}

void WorldSession::SendSyncWowEntitlements()
{
    WorldPackets::BattlePay::SyncWowEntitlements packet;
    SendPacket(packet.Write());
}
