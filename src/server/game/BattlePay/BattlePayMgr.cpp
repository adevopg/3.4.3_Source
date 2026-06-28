#include "AccountMgr.h"
#include "BattlePetMgr.h"
#include "BattlePayMgr.h"
#include "Common.h"
#include "CollectionMgr.h"
#include "ObjectMgr.h"
#include "CollectionMgr.h"
#include "WorldSession.h"
#include "Guild.h"
#include "GuildMgr.h"
#include "Player.h"
#include "BattlePayData.h"
#include "DatabaseEnv.h"
#include "ScriptMgr.h"
#include "CollectionMgr.h"
#include "SpellInfo.h"
#include "Mail.h"
#include "SpellMgr.h"
#include "Language.h"
#include "SpellPackets.h"
#include "Chat.h"
#include "DB2Stores.h"
#include "BattlePayPackets.h"
#include "LanguageMgr.h"
#include "Pet.h"
#include "Item.h"
#include "StringFormat.h"

using namespace Battlepay;

namespace
{
    void MailItems(Player* player, uint32 itemId, uint16 count)
    {
        CharacterDatabaseTransaction trans = CharacterDatabase.BeginTransaction();
        std::string _subject("The items you've oredered have been delivered.");
        MailDraft draft(_subject, "Our system has detected that at the time of your transaction your bags were full, so we've sent the items that you've ordered to your mailbox.");

        if (Item* pItem = Item::CreateItem(itemId, count, ItemContext::NONE, player))
        {
            pItem->SaveToDB(trans);
            draft.AddItem(pItem);
        }

        draft.SendMailTo(trans, player, MailSender(player, MAIL_STATIONERY_GM), MailCheckMask(MAIL_CHECK_MASK_COPIED | MAIL_CHECK_MASK_RETURNED));
        CharacterDatabase.CommitTransaction(trans);
    }
}

BattlepayManager::BattlepayManager(WorldSession* session)
{
    _session             = session;
    _distributionIDCount = 0;
    _walletName          = "Credits";
}

BattlepayManager::~BattlepayManager() = default;

void BattlepayManager::RegisterStartPurchase(Purchase purchase)
{
    _actualTransaction = purchase;
}

uint64 BattlepayManager::GenerateNewDistributionId()
{
    return uint64(0x1E77800000000000 | ++_distributionIDCount);
}

Purchase* BattlepayManager::GetPurchase()
{
    return &_actualTransaction;
}

std::string const& BattlepayManager::GetDefaultWalletName() const
{
    return _walletName;
}

uint32 BattlepayManager::GetShopCurrency() const
{
    return sWorld->getIntConfig(CONFIG_BATTLE_PAY_CURRENCY);
}

bool BattlepayManager::IsAvailable() const
{
    if (AccountMgr::IsAdminAccount(_session->GetSecurity()))
        return true;

    return sWorld->getBoolConfig(CONFIG_FEATURE_SYSTEM_BPAY_STORE_ENABLED);
}

void BattlepayManager::SavePurchase(const Purchase& purchase, bool claimed)
{
    const auto productInfo = sBattlePayDataStore->GetProductInfoForProduct(purchase.ProductID);
    if (productInfo == nullptr)
        return;

    const auto displayInfo = sBattlePayDataStore->GetDisplayInfo(productInfo->Entry);
    if (displayInfo == nullptr)
        return;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BATTLE_PAY_PURCHASE);
    stmt->setUInt32(0, purchase.PurchaseID);
    stmt->setUInt32(1, _session->GetAccountId());
    stmt->setUInt32(2, GetVirtualRealmAddress());
    stmt->setUInt32(3, purchase.ProductID);
    stmt->setString(4, displayInfo->Name1);
    stmt->setUInt32(5, purchase.CurrentPrice);
    stmt->setString(6, _session->GetRemoteAddress());
    stmt->setBool(7, claimed);
    LoginDatabase.Execute(stmt);
}

void BattlepayManager::ProcessDelivery(const Purchase& purchase, bool onLogin)
{
    const auto productInfo = sBattlePayDataStore->GetProductInfoForProduct(purchase.ProductID);
    if (productInfo == nullptr)
        return;

    bool claimed = false;

    Player* player = _session->GetPlayer();

    for (const uint32 productId : productInfo->ProductIds)
    {
        auto product = sBattlePayDataStore->GetProduct(productId);
        if (product == nullptr)
            continue;

        const auto* spellInfo = sSpellMgr->GetSpellInfo(product->DisplayId, DIFFICULTY_NONE);

        switch (product->Type)
        {
            case Battlepay::Item_:
            {
                if (player)
                {
                    // Entrega cada ítem del producto (battlepay_item). Si el inventario
                    // está lleno, se manda por correo. Sin esto el poll marcaba la orden
                    // DELIVERED y avisaba "entregada" pero no daba nada.
                    for (auto const& it : product->Items)
                    {
                        if (!it.ItemID)
                            continue;
                        uint16 const qty = uint16(std::min<uint32>(std::max<uint32>(1, it.Quantity), 1000));
                        if (!player->AddItem(it.ItemID, qty))
                            MailItems(player, it.ItemID, qty);
                        claimed = true;
                    }
                    // Fallback: producto sin filas en battlepay_item pero con ItemId directo.
                    if (!claimed && product->ItemId)
                    {
                        if (!player->AddItem(product->ItemId, 1))
                            MailItems(player, product->ItemId, 1);
                        claimed = true;
                    }
                }
                break;
            }
            case Battlepay::LevelBoost:
            {
                // alistar: TODO
                break;
            }
            case Battlepay::Pet:
            {
                if (player && spellInfo)
                {
                    player->AddSpell(spellInfo->Id, true, false, false, false);
                    claimed = true;
                }
                break;
            }
            case Battlepay::Mount:
            {
                if (player)
                {
                    // 1) Mount de tienda con ÍTEM (reins): se entrega el ítem y el
                    //    jugador lo usa para aprender la montura. (battlepay_product.ItemId)
                    if (product->ItemId)
                    {
                        if (!player->AddItem(product->ItemId, 1))
                            MailItems(player, product->ItemId, 1);
                        claimed = true;
                    }
                    // 2) Mount clásico sin ítem: se aprende directo por hechizo.
                    else if (spellInfo)
                    {
                        player->LearnSpell(spellInfo->Id, false);
                        _session->GetCollectionMgr()->AddMount(spellInfo->Id, MountStatusFlags::MOUNT_STATUS_NONE);
                        claimed = true;
                    }
                    // 3) Ni ítem ni hechizo válido (DisplayId de retail inexistente en 3.4.3).
                    else
                    {
                        TC_LOG_ERROR("server.BattlePay",
                            "Mount NO entregado: producto {} (DisplayId {}) sin ItemId y sin spell válido. Configura battlepay_product.ItemId o un DisplayId válido.",
                            product->ProductId, product->DisplayId);
                        ChatHandler(_session).PSendSysMessage("|cffff0000[Tienda]|r Esta montura no está configurada. Avisa a un administrador.");
                    }
                }
                break;
            }
            case Battlepay::WoWToken:
            {
                break;
            }
            case Battlepay::NameChange:
            {
                if (player)
                {
                    player->SetAtLoginFlag(AT_LOGIN_RENAME);
                    CharacterDatabase.PExecute("UPDATE characters SET at_login = at_login | {} WHERE guid = {}",
                        uint32(AT_LOGIN_RENAME), player->GetGUID().GetCounter());
                    ChatHandler(_session).PSendSysMessage("|cff66ccff[Tienda]|r Cambio de nombre activado. Vuelve a la selección de personaje para aplicarlo.");
                    claimed = true;
                }
                break;
            }
            case Battlepay::FactionChange:
            {
                if (player)
                {
                    player->SetAtLoginFlag(AT_LOGIN_CHANGE_FACTION);
                    CharacterDatabase.PExecute("UPDATE characters SET at_login = at_login | {} WHERE guid = {}",
                        uint32(AT_LOGIN_CHANGE_FACTION), player->GetGUID().GetCounter());
                    ChatHandler(_session).PSendSysMessage("|cff66ccff[Tienda]|r Cambio de facción activado. Vuelve a la selección de personaje para aplicarlo.");
                    claimed = true;
                }
                break;
            }
            case Battlepay::RaceChange:
            {
                if (player)
                {
                    player->SetAtLoginFlag(AT_LOGIN_CHANGE_RACE);
                    CharacterDatabase.PExecute("UPDATE characters SET at_login = at_login | {} WHERE guid = {}",
                        uint32(AT_LOGIN_CHANGE_RACE), player->GetGUID().GetCounter());
                    ChatHandler(_session).PSendSysMessage("|cff66ccff[Tienda]|r Cambio de raza activado. Vuelve a la selección de personaje para aplicarlo.");
                    claimed = true;
                }
                break;
            }
            case Battlepay::CharacterTransfer:
            {
                break;
            }
            case Battlepay::Toy:
            {
                if (player)
                {
                    const uint32 itemId = product->DisplayId;
                    const uint16 count = 1;

                    if (!player->AddItem(itemId, count))
                    {
                        MailItems(player, itemId, count);
                    }

                    claimed = true;
                }
                break;
            }
            case Battlepay::Expansion:
            {
                break;
            }
            case Battlepay::GameTime:
            {
                break;
            }
            case Battlepay::GuildNameChange:
            case Battlepay::GuildFactionChange:
            case Battlepay::GuildTransfer:
            case Battlepay::GuildFactionTranfer:
            {
                // alistar: NYI
                break;
            }
            case Battlepay::TransmogAppearance:
            {
                _session->GetCollectionMgr()->AddTransmogSet(product->Unk7);
                break;
            }
            // Custom:
            case Battlepay::ItemSet:
            case Battlepay::Gold:
            case Battlepay::Currency:
            {
                break;
            }
        }

        if (onLogin)
        {
            if (claimed)
            {
                LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_BATTLE_PAY_CLAIM_ITEMS);
                stmt->setUInt32(0, purchase.PurchaseID);
                LoginDatabase.Execute(stmt);
            }
        }
        else
        {
            SavePurchase(purchase, claimed);
        }
            
        sScriptMgr->OnBattlePayProductDelivery(_session, *product);
    }
}

void BattlepayManager::AlreadyOwnProduct(WorldPackets::BattlePay::Product& product) const
{
    switch (product.Type)
    {
        case Battlepay::Pet:
        {
            product.UnkBit = _session->GetBattlePetMgr()->GetPetBySpellId(product.DisplayId);
            break;
        }
        case Battlepay::Mount:
        {
            for (const auto& mounts : _session->GetCollectionMgr()->GetAccountMounts())
            {
                if (product.DisplayId == mounts.first)
                {
                    product.UnkBit = true; // already own
                    break;
                }
            }
            break;
        }
        case Battlepay::Toy:
        {
            product.UnkBit = _session->GetCollectionMgr()->HasToy(product.DisplayId);
            break;
        }
    }
}

void BattlepayManager::SendProductList()
{
    WorldPackets::BattlePay::ProductListResponse response;

    if (!IsAvailable())
    {
        response.Result = ProductListResult::LockUnk1;
        _session->SendPacket(response.Write());
        return;
    }

    response.Result = ProductListResult::Available;
    response.CurrencyID = GetShopCurrency() > 0 ? GetShopCurrency() : 1;

    // BATTLEPAY GROUP 
    for (const auto& itr : sBattlePayDataStore->GetProductGroups())
    {
        WorldPackets::BattlePay::Group group;
        group.GroupId = itr.GroupId;
        group.IconFileDataID = itr.IconFileDataID;
        group.DisplayType = itr.DisplayType;
        group.Ordering = itr.Ordering;
        group.Unk = itr.Unk;
        group.MainGroupID = itr.MainGroupID;
        group.Name = itr.Name;
        group.Description = itr.Description;

        response.ProductGroups.emplace_back(group);
    }

    // BATTLEPAY SHOP
    for (const auto& itr : sBattlePayDataStore->GetShopEntries())
    {
        WorldPackets::BattlePay::Shop shop;
        shop.EntryID = itr.EntryID;
        shop.GroupID = itr.GroupID;
        shop.ProductID = itr.ProductID;
        shop.Ordering = itr.Ordering;
        shop.VasServiceType = itr.VasServiceType;
        shop.StoreDeliveryType = itr.StoreDeliveryType;

        // shop entry and display entry must be the same
        auto data = WriteDisplayInfo(itr.Entry);
        if (std::get<0>(data))
        {
            shop.Display.emplace();
            shop.Display = std::get<1>(data);
        }

        auto productAddon = sBattlePayDataStore->GetProductAddon(itr.Entry);
        if (productAddon)
            if (productAddon->DisableListing > 0)
                continue;

        response.Shops.emplace_back(shop);
    }

    // BATTLEPAY PRODUCT INFO
    for (const auto& itr : sBattlePayDataStore->GetProductInfos())
    {
        const auto& productInfo = itr.second;

        auto productAddon = sBattlePayDataStore->GetProductAddon(productInfo.Entry);
        if (productAddon)
            if (productAddon->DisableListing > 0)
                continue;

        WorldPackets::BattlePay::ProductInfo productinfo;
        productinfo.ProductId = productInfo.ProductId;
        productinfo.NormalPriceFixedPoint = productInfo.NormalPriceFixedPoint;
        productinfo.CurrentPriceFixedPoint = productInfo.CurrentPriceFixedPoint;
        productinfo.ProductIds = productInfo.ProductIds;
        productinfo.Unk1 = productInfo.Unk1;
        productinfo.Unk2 = productInfo.Unk2;
        productinfo.UnkInts = productInfo.UnkInts;
        productinfo.Unk3 = productInfo.Unk3;
        productinfo.ChoiceType = productInfo.ChoiceType;

        // productinfo entry and display entry must be the same
        const auto& data = WriteDisplayInfo(productInfo.Entry);
        if (std::get<0>(data))
        {
            productinfo.Display.emplace();
            productinfo.Display = std::get<1>(data);
        }

        response.ProductInfos.emplace_back(productinfo);
    }

    for (auto& itr : sBattlePayDataStore->GetProducts())
    {
        auto& product = itr.second;
        auto productInfo = sBattlePayDataStore->GetProductInfoForProduct(product.ProductId);

        auto productAddon = sBattlePayDataStore->GetProductAddon(productInfo->Entry);
        if (productAddon)
            if (productAddon->DisableListing > 0)
                continue;

        // BATTLEPAY PRODUCTS
        WorldPackets::BattlePay::Product pProduct;
        pProduct.ProductId = product.ProductId;
        pProduct.Type = product.Type;
        pProduct.Flags = product.Flags;
        pProduct.Unk1 = product.Unk1;
        pProduct.DisplayId = product.DisplayId;
        pProduct.ItemId = product.ItemId;
        pProduct.Unk4 = product.Unk4;
        pProduct.Unk5 = product.Unk5;
        pProduct.Unk6 = product.Unk6;
        pProduct.Unk7 = product.Unk7;
        pProduct.Unk8 = product.Unk8;
        pProduct.Unk9 = product.Unk9;
        pProduct.UnkString = product.UnkString;
        pProduct.UnkBit = product.UnkBit;       // already own the item
        pProduct.UnkBits = product.UnkBits;

        // check if we own whatever we're buying
        AlreadyOwnProduct(pProduct);
        
        // BATTLEPAY ITEM
        if (product.Items.size() > 0)
        {
            const auto* productInfoPtr = sBattlePayDataStore->GetItemsOfProduct(product.ProductId);
            if (productInfoPtr == nullptr)
                continue;

            for (const auto& item : *productInfoPtr)
            {
                WorldPackets::BattlePay::ProductItem pItem;
                pItem.ID = item.ID;
                pItem.UnkByte = item.UnkByte;
                pItem.ItemID = item.ItemID;
                pItem.Quantity = item.Quantity;
                pItem.UnkInt1 = item.UnkInt1;
                pItem.UnkInt2 = item.UnkInt2;
                pItem.IsPet = item.IsPet;
                pItem.PetResult = item.PetResult;

                if (sBattlePayDataStore->DisplayInfoExist(productInfo->Entry))
                {
                    // productinfo entry and display entry must be the same
                    auto data = WriteDisplayInfo(productInfo->Entry);
                    if (std::get<0>(data))
                    {
                        pItem.Display.emplace();
                        pItem.Display = std::get<1>(data);
                    }
                }
                else
                    TC_LOG_INFO("server.battlepay", "Can't find displayinfo for product {} with product info entry: {}", product.Name, productInfo->Entry);

                pProduct.Items.emplace_back(pItem);
            }
        }

        // alistar: TODO not sure if we need to send this
#if 0
        // productinfo entry and display entry must be the same
        auto data = WriteDisplayInfo(productInfo->Entry);
        if (std::get<0>(data))
        {
            pProduct.Display.emplace();
            pProduct.Display = std::get<1>(data);
        }
#endif

        response.Products.emplace_back(pProduct);

    }

    /*
    TC_LOG_INFO("server.BattlePay", "SendProductList with {} ProductInfos, {} Products, {} Shops. CurrencyID: {}.", response.ProductInfos.size(), response.Products.size(), response.Shops.size(), response.CurrencyID);
    for (int i = 0; i != response.ProductInfos.size(); i++)
    {
        TC_LOG_INFO("server.BattlePay", "({}) ProductInfo: ProductId [%zu], First SubProductId [%zu], CurrentPriceFixedPoint [%lu]", i, response.ProductInfos[i].ProductId, response.ProductInfos[i].ProductIds[0], response.ProductInfos[i].CurrentPriceFixedPoint);
        TC_LOG_INFO("server.BattlePay", "({}) Products: ProductId [%zu], UnkString [{}]", i, response.Products[i].ProductId, response.Products[i].UnkString.c_str());
        TC_LOG_INFO("server.BattlePay", "({}) Shops: ProductId [%zu]", i, response.Shops[i].ProductID);
    }
    */

    _session->SendPacket(response.Write());
}

std::tuple<bool, WorldPackets::BattlePay::DisplayInfo> BattlepayManager::WriteDisplayInfo(uint32 displayInfoEntry)
{
    const auto qualityColor = [](uint32 displayInfoOrProductInfoEntry) -> std::string
    {
        auto productAddon = sBattlePayDataStore->GetProductAddon(displayInfoOrProductInfoEntry);
        if (!productAddon)
           return "|cffffffff";

        switch (sBattlePayDataStore->GetProductAddon(displayInfoOrProductInfoEntry)->NameColorIndex)
        {
        case 0:
            return "|cffffffff";
        case 1:
            return "|cff1eff00";
        case 2:
            return "|cff0070dd";
        case 3:
            return "|cffa335ee";
        case 4:
            return "|cffff8000";
        case 5:
            return "|cffe5cc80";
        case 6:
            return "|cffe5cc80";
        default:
            return "|cffffffff";
        }
    };

    auto info = WorldPackets::BattlePay::DisplayInfo();

    auto displayInfo = sBattlePayDataStore->GetDisplayInfo(displayInfoEntry);
    if (!displayInfo)
        return std::make_tuple(false, info);

    info.CreatureDisplayID = displayInfo->CreatureDisplayID;
    info.VisualID = displayInfo->VisualID;
    info.Name1 = displayInfo->Name1; // qualityColor(displayInfoEntry) + displayInfo->Name1 + "|r";
    info.Name2 = displayInfo->Name2;
    info.Name3 = displayInfo->Name3;
    info.Name4 = displayInfo->Name4;
    info.Name5 = displayInfo->Name5;
    info.Name6 = displayInfo->Name6;
    info.Name7 = displayInfo->Name7;
    info.Flags = displayInfo->Flags;
    info.Unk1 = displayInfo->Unk1;
    info.Unk2 = displayInfo->Unk2;
    info.Unk3 = displayInfo->Unk3;
    info.UnkInt1 = displayInfo->UnkInt1;
    info.UnkInt2 = displayInfo->UnkInt2;
    info.UnkInt3 = displayInfo->UnkInt3;

    for (size_t v = 0; v < displayInfo->Visuals.size(); v++)
    {
        BattlePayData::Visual visual = displayInfo->Visuals[v];

        if (!visual.Entry)
            visual = *sBattlePayDataStore->FindVisualForDisplayInfo(displayInfoEntry);

        WorldPackets::BattlePay::Visual _Visual;
        _Visual.Name = visual.Name;
        _Visual.DisplayId = visual.DisplayId;
        _Visual.VisualId = visual.VisualId;
        _Visual.Unk = visual.Unk;

        info.Visuals.push_back(_Visual);
    }

    if (displayInfo->Flags)
        info.Flags = displayInfo->Flags;

    return std::make_tuple(true, info);
}

void BattlepayManager::SendAccountCredits()
{
    // Sistema de puntos/créditos DESACTIVADO: las compras se pagan por SumUp (web),
    // no por saldo de Battlepay. No mostramos "current account balance".
}

void BattlepayManager::SendBattlePayDistribution(uint32 productId, uint8 status, uint64 distributionId, ObjectGuid targetGuid)
{
    const auto* product = sBattlePayDataStore->GetProduct(productId);

    if (product == nullptr)
        return;

    const auto* productInfo = sBattlePayDataStore->GetProductInfoForProduct(productId);

    if (productInfo == nullptr)
        return;

    WorldPackets::BattlePay::DistributionUpdate distributionBattlePay;
    distributionBattlePay.DistributionObject.DistributionID = distributionId;
    distributionBattlePay.DistributionObject.Status = status;
    distributionBattlePay.DistributionObject.ProductID = productId;
    distributionBattlePay.DistributionObject.Revoked = false; // not needed for us

    if (!targetGuid.IsEmpty())
    {
        distributionBattlePay.DistributionObject.TargetPlayer = targetGuid;
        distributionBattlePay.DistributionObject.TargetVirtualRealm = GetVirtualRealmAddress();
        distributionBattlePay.DistributionObject.TargetNativeRealm = GetVirtualRealmAddress();
    }

    WorldPackets::BattlePay::Product productData;
    
    productData.ProductId = product->ProductId;
    productData.Type      = product->Type;
    productData.Flags     = product->Flags;
    productData.Unk1      = product->Unk1;
    productData.DisplayId = product->DisplayId;
    productData.ItemId    = product->ItemId;
    productData.Unk4      = product->Unk4;
    productData.Unk5      = product->Unk5;
    productData.Unk6      = product->Unk6;
    productData.Unk7      = product->Unk7;
    productData.Unk8      = product->Unk8;
    productData.Unk9      = product->Unk9;
    productData.UnkString = product->UnkString;
    productData.UnkBit    = product->UnkBit;
    productData.UnkBits   = product->UnkBits;
    
    for (const auto& item : *sBattlePayDataStore->GetItemsOfProduct(product->ProductId))
    {
        WorldPackets::BattlePay::ProductItem productItem;

        productItem.ID        = item.ID;
        productItem.UnkByte   = item.UnkByte;
        productItem.ItemID    = item.ItemID;
        productItem.Quantity  = item.Quantity;
        productItem.UnkInt1   = item.UnkInt1;
        productItem.UnkInt2   = item.UnkInt2;
        productItem.IsPet     = item.IsPet;
        productItem.PetResult = item.PetResult;

        const auto& data = WriteDisplayInfo(productInfo->Entry);
        if (std::get<0>(data))
        {
            productItem.Display.emplace();
            productItem.Display = std::get<1>(data);
        }
    }

    const auto& data = WriteDisplayInfo(productInfo->Entry);
    if (std::get<0>(data))
    {
        productData.Display.emplace();
        productData.Display = std::get<1>(data);
    }

    distributionBattlePay.DistributionObject.Product = std::move(productData);
    _session->SendPacket(distributionBattlePay.Write());
}

void BattlepayManager::AssignDistributionToCharacter(ObjectGuid const& targetCharGuid, uint64 distributionId, uint32 productId, uint16 specId, uint16 choiceId)
{
    WorldPackets::BattlePay::UpgradeStarted upgrade;

    upgrade.CharacterGUID = targetCharGuid;

    _session->SendPacket(upgrade.Write());

    WorldPackets::BattlePay::BattlePayStartDistributionAssignToTargetResponse assignResponse;

    assignResponse.DistributionID = distributionId;
    assignResponse.unkint1        = specId;
    assignResponse.unkint2        = choiceId;

    _session->SendPacket(upgrade.Write());

    auto purchase = GetPurchase();
    purchase->Status = Battlepay::DistributionStatus::BATTLE_PAY_DIST_STATUS_ADD_TO_PROCESS;

    SendBattlePayDistribution(productId, purchase->Status, distributionId, targetCharGuid);
}

// Poll de entrega de órdenes Battlepay pagadas vía SumUp (NovaWeb).
// NovaWeb marca `battlepay_orders.status='PAID'` al confirmar el pago; aquí, para
// el jugador conectado, entregamos cada orden PAID con ProcessDelivery y la
// marcamos DELIVERED. Idempotente: el UPDATE condicionado a status='PAID' evita
// doble entrega aunque dos ticks la lean a la vez.
void BattlepayManager::Update(uint32 diff)
{
    if (!_session)
        return;

    Player* player = _session->GetPlayer();
    if (!player || !player->IsInWorld())
        return;

    // Throttle: consultamos la BD como mucho cada 5 segundos.
    if (_sumupPollTimer > diff)
    {
        _sumupPollTimer -= diff;
        return;
    }
    _sumupPollTimer = 5 * IN_MILLISECONDS;

    uint32 const accountId = _session->GetAccountId();

    // Query ASÍNCRONA — NUNCA bloquear el hilo World con DB. Un SELECT/UPDATE síncrono
    // aquí esperaba el lock de fila que NovaWeb toma al marcar 'PAID' → el hilo World
    // se congelaba 60s y el anti-freeze forzaba el crash. El callback corre en el hilo
    // World vía GetQueryProcessor() (ProcessQueryCallbacks), seguro para entregar.
    std::string sql = Trinity::StringFormat(
        "SELECT id, product_id FROM battlepay_orders "
        "WHERE account_id = {} AND status = 'PAID' AND delivered_at IS NULL ORDER BY id ASC",
        accountId);

    _session->GetQueryProcessor().AddCallback(LoginDatabase.AsyncQuery(sql.c_str()).WithCallback(
        [this, accountId](QueryResult result)
    {
        if (!result)
            return;

        Player* player = _session ? _session->GetPlayer() : nullptr;
        if (!player || !player->IsInWorld())
            return;

        do
        {
            Field* fields    = result->Fetch();
            uint32 orderId   = fields[0].GetUInt32();
            uint32 productId = fields[1].GetUInt32();

            auto productInfo = sBattlePayDataStore->GetProductInfoForProduct(productId);
            if (productInfo == nullptr)
            {
                TC_LOG_ERROR("server.BattlePay", "SumUp: orden {} con product_id {} sin ProductInfo; no se puede entregar.", orderId, productId);
                continue;
            }

            Battlepay::Purchase purchase;
            purchase.ProductID       = productId;
            purchase.TargetCharacter = player->GetGUID();
            purchase.CurrentPrice    = uint64(productInfo->CurrentPriceFixedPoint);
            purchase.Status          = Battlepay::UpdateStatus::Finish;
            purchase.PurchaseID      = orderId;
            purchase.DistributionId  = GenerateNewDistributionId();

            ProcessDelivery(purchase, false);
            SendProductList();

            // Marca como entregada (async; el SELECT filtra delivered_at IS NULL).
            LoginDatabase.PExecute(
                "UPDATE battlepay_orders SET status = 'DELIVERED', delivered_at = UNIX_TIMESTAMP() "
                "WHERE id = {} AND status = 'PAID'", orderId);

            ChatHandler(_session).PSendSysMessage("|cff00ff00[Tienda]|r Tu compra ha sido entregada. ¡Gracias!");
            TC_LOG_INFO("server.BattlePay", "SumUp: orden {} (product {}) entregada a la cuenta {}.", orderId, productId, accountId);
        } while (result->NextRow());
    }));
}

uint32 BattlepayManager::GetBattlePayCredits() const
{
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BATTLE_PAY_ACCOUNT_CREDITS);

    stmt->setUInt32(0, _session->GetBattlenetAccountId());

    PreparedQueryResult result_don = LoginDatabase.Query(stmt);

    if (!result_don)
        return 0;

    Field* fields = result_don->Fetch();
    uint32 credits = fields[0].GetUInt32();

    return credits * g_CurrencyPrecision; // currency precision .. in retail it like gold and copper .. 10 usd is 100000 battlepay credit
}

bool BattlepayManager::HasBattlePayCredits(uint32 count) const
{
    if (GetBattlePayCredits() >= count)
        return true;

    ChatHandler chH = ChatHandler(_session);
    chH.PSendSysMessage(20000, count);
    return false;
}

bool BattlepayManager::UpdateBattlePayCredits(uint64 price) const
{
    //TC_LOG_INFO("server.BattlePay", "UpdateBattlePayCredits: GetBattlePayCredits(): {} - price: %lu", GetBattlePayCredits(), price);
    uint64 calcCredit = (GetBattlePayCredits() - price) / g_CurrencyPrecision;
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_BATTLE_PAY_ACCOUNT_CREDITS);
    stmt->setUInt64(0, calcCredit);
    stmt->setUInt32(1, _session->GetBattlenetAccountId());
    LoginDatabase.Execute(stmt);

    return true;
}

bool BattlepayManager::ModifyBattlePayCredits(uint64 credits) const
{
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_BATTLE_PAY_ACCOUNT_CREDITS);
    stmt->setUInt64(0, credits);
    stmt->setUInt32(1, _session->GetBattlenetAccountId());
    LoginDatabase.Execute(stmt);

    return true;
}

void BattlepayManager::SendBattlePayBattlePetDelivered(ObjectGuid petguid, uint32 creatureID) const
{
    WorldPackets::BattlePay::BattlePayBattlePetDelivered response;
    response.DisplayID = creatureID;
    response.BattlePetGuid = petguid;
    _session->SendPacket(response.Write());
    TC_LOG_ERROR("", "Send BattlePayBattlePetDelivered guid: %lu && creatureID: {}", petguid.GetCounter(), creatureID);
}

void BattlepayManager::AddBattlePetFromBpayShop(uint32 /*battlePetCreatureID*/) const
{
     //if (BattlePetSpeciesEntry const* speciesEntry = BattlePets::BattlePetMgr::GetBattlePetSpeciesByCreature(battlePetCreatureID))
     //{
     //   // _session->GetBattlePetMgr()->AddPet(speciesEntry->ID, BattlePets::BattlePetMgr::SelectPetDisplay(speciesEntry),
     //     //   BattlePets::BattlePetMgr::RollPetBreed(speciesEntry->ID), BattlePets::BattlePetMgr::GetDefaultPetQuality(speciesEntry->ID));

     //     //it gives back false information need to get the pet guid from the add pet method somehow
     //    SendBattlePayBattlePetDelivered(ObjectGuid::Create<HighGuid::BattlePet>(sObjectMgr->GetGenerator<HighGuid::BattlePet>().Generate()), speciesEntry->CreatureID);
     //}
}
