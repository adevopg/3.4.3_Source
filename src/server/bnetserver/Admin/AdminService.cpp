#include "AdminService.h"
#include "AdminLogBuffer.h"
#include "Config.h"
#include "CryptoHash.h"
#include "CryptoRandom.h"
#include "DatabaseEnv.h"
#include "GitRevision.h"
#include "HttpCommon.h"
#include "Log.h"
#include "Realm.h"
#include "RealmList.h"
#include "SRP6.h"
#include "StringFormat.h"
#include "Util.h"
#include "TOTP.h"
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/verb.hpp>
#include <rapidjson/document.h>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <map>
#include <sstream>
#include <thread>
#include <string>
#include <vector>

using BnetSRP6   = Trinity::Crypto::SRP::BnetSRP6v2<Trinity::Crypto::SHA256>;
using GameSRP6   = Trinity::Crypto::SRP::GruntSRP6;

// ============================================================================
// User Portal SPA
// ============================================================================
static char const* k_PortalHtml = R"PORTAL(<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lineage Reborn &mdash; Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#07091a;--bg2:#0d1028;--card:#101530;--bdr:#1e2550;
  --gold:#c9a23d;--gold2:#e8c86e;--text:#d5cef0;--muted:#5a6090;
  --green:#1db85e;--red:#e04050;--blue:#3a8fd0;--purple:#8b5cf6;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;min-height:100vh;overflow-x:hidden}
a{color:var(--gold);text-decoration:none}a:hover{color:var(--gold2)}
/* NAV */
nav{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(7,9,26,.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--bdr);height:62px;display:flex;align-items:center;padding:0 24px;gap:0}
.nav-logo{display:flex;align-items:center;gap:10px;margin-right:32px;text-decoration:none}
.nav-logo .ico{width:36px;height:36px;background:linear-gradient(135deg,var(--gold),var(--gold2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.nav-logo span{font-size:16px;font-weight:700;color:var(--gold2);letter-spacing:.5px}
.nav-links{display:flex;align-items:center;gap:4px;flex:1}
.nav-link{padding:7px 14px;border-radius:7px;cursor:pointer;color:var(--muted);transition:all .15s;font-size:13px;font-weight:500;user-select:none}
.nav-link:hover{color:var(--text);background:rgba(255,255,255,.05)}
.nav-link.active{color:var(--gold);background:rgba(201,162,61,.1)}
.nav-auth{display:flex;align-items:center;gap:8px;margin-left:auto}
.btn{padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .15s}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--bdr)}
.btn-ghost:hover{color:var(--text);border-color:var(--muted)}
.btn-gold{background:linear-gradient(135deg,var(--gold),var(--gold2));color:#07091a}
.btn-gold:hover{filter:brightness(1.1);transform:translateY(-1px)}
.btn-outline{background:transparent;color:var(--gold);border:1px solid var(--gold)}
.btn-outline:hover{background:rgba(201,162,61,.1)}
.btn-danger{background:var(--red);color:#fff}
.btn-sm{padding:5px 12px;font-size:12px}
/* USER DROPDOWN */
.user-menu{position:relative}
.user-btn{display:flex;align-items:center;gap:8px;padding:6px 12px;border-radius:8px;cursor:pointer;background:rgba(255,255,255,.05);border:1px solid var(--bdr);color:var(--text);font-size:13px;font-weight:500}
.user-btn:hover{background:rgba(255,255,255,.08)}
.user-avatar{width:26px;height:26px;background:linear-gradient(135deg,var(--gold),var(--purple));border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0}
.user-dropdown{position:absolute;top:calc(100% + 8px);right:0;background:var(--card);border:1px solid var(--bdr);border-radius:10px;min-width:180px;overflow:hidden;display:none;box-shadow:0 8px 32px rgba(0,0,0,.5)}
.user-menu.open .user-dropdown{display:block}
.user-dd-item{padding:10px 16px;cursor:pointer;font-size:13px;color:var(--text);transition:background .1s}
.user-dd-item:hover{background:rgba(255,255,255,.05)}
.user-dd-sep{height:1px;background:var(--bdr);margin:4px 0}
/* MAIN CONTENT */
.main{padding-top:62px;min-height:100vh}
/* SECTION */
.section{display:none;padding:0}
.section.active{display:block}
/* HERO */
.hero{min-height:520px;display:flex;align-items:center;justify-content:center;text-align:center;position:relative;overflow:hidden;background:radial-gradient(ellipse 100% 80% at 50% 20%,#1a1050 0%,#0d0820 40%,var(--bg) 100%)}
.hero::before{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Ccircle fill='%23c9a23d' fill-opacity='0.06' cx='30' cy='30' r='1'/%3E%3C/g%3E%3C/svg%3E") repeat;opacity:.7}
.hero-inner{position:relative;z-index:1;max-width:760px;padding:60px 20px}
.hero-badge{display:inline-block;padding:5px 14px;border-radius:20px;background:rgba(201,162,61,.15);border:1px solid rgba(201,162,61,.3);color:var(--gold);font-size:12px;font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:20px}
.hero h1{font-size:clamp(30px,6vw,52px);font-weight:800;line-height:1.1;margin-bottom:16px;background:linear-gradient(135deg,var(--text) 40%,var(--gold2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero p{font-size:16px;color:var(--muted);margin-bottom:32px;max-width:520px;margin-left:auto;margin-right:auto;line-height:1.7}
.hero-btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.hero-stats{display:flex;gap:32px;justify-content:center;margin-top:40px;flex-wrap:wrap}
.hero-stat{text-align:center}
.hero-stat .val{font-size:28px;font-weight:800;color:var(--gold2);line-height:1}
.hero-stat .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.hero-stat .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:5px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(1.3)}}
/* NEWS SLIDER */
.slider-wrap{position:relative;overflow:hidden;border-radius:12px;margin:32px 0 20px}
.slider-track{display:flex;transition:transform .5s ease}
.slide{min-width:100%;border-radius:12px;overflow:hidden;position:relative;min-height:240px;background:var(--card);border:1px solid var(--bdr)}
.slide-bg{position:absolute;inset:0;background-size:cover;background-position:center;opacity:.35}
.slide-content{position:relative;z-index:1;padding:28px 32px;display:flex;flex-direction:column;justify-content:flex-end;min-height:240px;background:linear-gradient(to top,rgba(7,9,26,.95) 0%,rgba(7,9,26,.3) 100%)}
.slide-cat{display:inline-block;padding:3px 10px;border-radius:12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
.slide-title{font-size:22px;font-weight:700;margin-bottom:8px;color:#fff}
.slide-excerpt{font-size:13px;color:rgba(255,255,255,.65);max-width:600px}
.slider-nav{position:absolute;top:50%;transform:translateY(-50%);width:100%;display:flex;justify-content:space-between;pointer-events:none;padding:0 8px;z-index:2}
.slider-btn{width:36px;height:36px;border-radius:50%;background:rgba(0,0,0,.6);border:1px solid rgba(255,255,255,.15);color:#fff;cursor:pointer;pointer-events:all;display:flex;align-items:center;justify-content:center;font-size:14px;transition:all .15s}
.slider-btn:hover{background:rgba(201,162,61,.4)}
.slider-dots{display:flex;justify-content:center;gap:6px;margin-top:10px}
.slider-dot{width:7px;height:7px;border-radius:50%;background:var(--bdr);cursor:pointer;transition:all .2s}
.slider-dot.active{background:var(--gold);width:20px;border-radius:4px}
/* CONTAINER */
.container{max-width:1200px;margin:0 auto;padding:0 20px}
/* SECTION HEADER */
.sec-hdr{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:20px}
.sec-hdr h2{font-size:20px;font-weight:700}
.sec-hdr h2 span{color:var(--gold)}
/* NEWS GRID */
.news-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-bottom:32px}
.news-card{background:var(--card);border:1px solid var(--bdr);border-radius:12px;overflow:hidden;cursor:pointer;transition:all .2s;display:flex;flex-direction:column}
.news-card:hover{border-color:var(--gold);transform:translateY(-3px);box-shadow:0 8px 32px rgba(201,162,61,.12)}
.nc-img{height:160px;background:var(--bg2);background-size:cover;background-position:center;position:relative}
.nc-img-placeholder{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:40px;opacity:.3}
.nc-body{padding:16px;flex:1;display:flex;flex-direction:column}
.nc-cat{display:inline-block;padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.nc-title{font-size:15px;font-weight:700;margin-bottom:8px;line-height:1.4;color:var(--text)}
.nc-excerpt{font-size:12px;color:var(--muted);line-height:1.6;flex:1}
.nc-foot{display:flex;align-items:center;justify-content:space-between;margin-top:12px;padding-top:10px;border-top:1px solid var(--bdr);font-size:11px;color:var(--muted)}
/* CATEGORIES */
.cat-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
.cat-tab{padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--bdr);color:var(--muted);background:transparent;transition:all .15s}
.cat-tab:hover{border-color:var(--gold);color:var(--gold)}
.cat-tab.active{background:rgba(201,162,61,.15);border-color:var(--gold);color:var(--gold)}
/* CATEGORY COLORS */
.cat-parches,.nc-parches{background:rgba(59,130,246,.15);color:#60a5fa}
.cat-eventos,.nc-eventos{background:rgba(234,179,8,.15);color:#fbbf24}
.cat-mantenimiento,.nc-mantenimiento{background:rgba(239,68,68,.15);color:#f87171}
.cat-general,.nc-general{background:rgba(139,92,246,.15);color:#a78bfa}
.cat-actualizacion,.nc-actualizacion{background:rgba(34,197,94,.15);color:#4ade80}
/* DOWNLOADS */
.dl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:32px}
.dl-card{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:20px;transition:all .2s}
.dl-card:hover{border-color:var(--gold);transform:translateY(-2px)}
.dl-ico{font-size:32px;margin-bottom:12px}
.dl-name{font-size:15px;font-weight:700;margin-bottom:6px}
.dl-desc{font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.6}
.dl-meta{font-size:11px;color:var(--muted);display:flex;gap:12px;margin-bottom:14px}
/* RANKINGS */
.opt-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:32px}
.opt-card{background:var(--card2);border:1px solid var(--bdr);border-radius:12px;padding:22px 18px;cursor:pointer;transition:all .18s;text-align:center;display:flex;flex-direction:column;align-items:center;gap:10px}
.opt-card:hover{border-color:var(--gold);background:rgba(201,162,61,.07);transform:translateY(-2px)}
.opt-card .opt-ico{font-size:28px;line-height:1}
.opt-card .opt-title{font-size:13px;font-weight:700;color:var(--text)}
.opt-card .opt-desc{font-size:11px;color:var(--muted);line-height:1.4}
.rank-tabs{display:flex;gap:8px;margin-bottom:20px}
.rank-tab{padding:7px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid var(--bdr);color:var(--muted);background:transparent;transition:all .15s}
.rank-tab.active{background:rgba(201,162,61,.12);border-color:var(--gold);color:var(--gold)}
.rank-table{width:100%;border-collapse:collapse;margin-bottom:24px}
.rank-table th{text-align:left;padding:10px 14px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);border-bottom:1px solid var(--bdr)}
.rank-table td{padding:11px 14px;border-bottom:1px solid rgba(30,37,80,.5);font-size:13px;vertical-align:middle}
.rank-table tr:hover td{background:rgba(255,255,255,.02)}
.rank-pos{font-size:11px;font-weight:700;color:var(--muted);width:40px}
.rank-pos.top3{font-size:16px}
.rank-name{font-weight:600;color:var(--text)}
.rank-val{font-weight:700;color:var(--gold)}
/* STATUS */
.status-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;margin-bottom:24px}
.status-card{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:20px;text-align:center}
.status-ico{font-size:28px;margin-bottom:10px}
.status-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}
.status-val{font-size:24px;font-weight:800;color:var(--gold2)}
.status-pill{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600}
.online-pill{background:rgba(29,184,94,.12);color:var(--green);border:1px solid rgba(29,184,94,.3)}
.offline-pill{background:rgba(224,64,80,.12);color:var(--red);border:1px solid rgba(224,64,80,.3)}
/* ACCOUNT */
.char-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-top:16px}
.char-card{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:16px;text-align:center;position:relative}
.char-card .online-badge{position:absolute;top:10px;right:10px;width:9px;height:9px;border-radius:50%;background:var(--muted)}
.char-card .online-badge.on{background:var(--green)}
.char-name{font-size:15px;font-weight:700;margin:8px 0 4px}
.char-sub{font-size:11px;color:var(--muted)}
.class-ico{font-size:28px}
/* SECTION PADDING */
.sec-pad{padding:48px 0}
/* PAGE HERO (non-home sections) */
.page-hero{background:linear-gradient(to bottom,rgba(13,16,40,.9),var(--bg));padding:48px 0 32px;border-bottom:1px solid var(--bdr);margin-bottom:32px}
.page-hero h1{font-size:28px;font-weight:800}
.page-hero p{font-size:13px;color:var(--muted);margin-top:6px}
/* MODALS */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:center;justify-content:center;padding:20px}
.overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--bdr);border-radius:14px;padding:32px;width:100%;max-width:420px;position:relative}
.modal h2{font-size:20px;font-weight:800;margin-bottom:6px}
.modal .subtitle{font-size:13px;color:var(--muted);margin-bottom:24px}
.form-row{margin-bottom:16px}
.form-row label{display:block;font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.6px}
.form-row input{width:100%;background:var(--bg2);border:1px solid var(--bdr);border-radius:8px;padding:10px 14px;color:var(--text);font-size:14px;outline:none;transition:border .15s}
.form-row input:focus{border-color:var(--gold)}
.form-footer{margin-top:20px;display:flex;flex-direction:column;gap:10px}
.form-switch{text-align:center;font-size:13px;color:var(--muted)}
.form-switch a{cursor:pointer;color:var(--gold)}
.modal-close{position:absolute;top:16px;right:16px;background:rgba(255,255,255,.08);border:none;color:var(--muted);width:28px;height:28px;border-radius:50%;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center}
.modal-close:hover{color:var(--text)}
/* TOAST */
.toast-wrap{position:fixed;bottom:24px;right:24px;z-index:999;display:flex;flex-direction:column;gap:8px;align-items:flex-end}
.toast{padding:12px 18px;border-radius:8px;font-size:13px;font-weight:500;border:1px solid;opacity:0;transform:translateX(20px);transition:all .25s;pointer-events:none}
.toast.show{opacity:1;transform:translateX(0)}
.toast.ok{background:#0d2e1a;color:var(--green);border-color:var(--green)}
.toast.err{background:#2e0d0d;color:var(--red);border-color:var(--red)}
.toast.info{background:#0d1a30;color:#7ab4ff;border-color:var(--blue)}
/* FOOTER */
footer{background:var(--bg2);border-top:1px solid var(--bdr);padding:40px 0 20px;margin-top:60px}
.footer-grid{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:32px;margin-bottom:32px}
.footer-brand .ico{font-size:28px;margin-bottom:10px}
.footer-brand p{font-size:12px;color:var(--muted);line-height:1.7;max-width:240px;margin-top:8px}
.footer-col h4{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:12px}
.footer-col ul{list-style:none}
.footer-col li{margin-bottom:7px;font-size:13px;color:var(--muted);cursor:pointer}
.footer-col li:hover{color:var(--text)}
.footer-bottom{display:flex;align-items:center;justify-content:space-between;padding-top:20px;border-top:1px solid var(--bdr);font-size:12px;color:var(--muted)}
/* ARTICLE VIEW */
.article-header{padding:48px 0 32px;border-bottom:1px solid var(--bdr);margin-bottom:32px}
.article-content{font-size:15px;line-height:1.8;color:#c8c2e0;max-width:760px}
.article-content h2,.article-content h3{color:var(--text);margin:24px 0 12px}
.article-content p{margin-bottom:16px}
/* MISC */
.empty{text-align:center;padding:48px;color:var(--muted);font-size:14px}
.pager{display:flex;gap:8px;justify-content:center;margin:24px 0}
.pager-btn{padding:6px 14px;border-radius:7px;font-size:13px;background:var(--card);border:1px solid var(--bdr);color:var(--muted);cursor:pointer}
.pager-btn.active{background:rgba(201,162,61,.15);border-color:var(--gold);color:var(--gold)}
.divider{height:1px;background:var(--bdr);margin:32px 0}
@media(max-width:768px){
  .footer-grid{grid-template-columns:1fr 1fr}
  .hero h1{font-size:28px}
  nav{padding:0 14px}
  .nav-links .nav-link:not(.always){display:none}
}
/* CHAR SERVICES */
.char-svc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.char-svc-card{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:14px 10px;cursor:pointer;transition:all .18s;text-align:center}
.char-svc-card:hover{border-color:var(--gold);background:rgba(201,162,61,.07)}
.char-svc-card .svc-ico{font-size:22px;margin-bottom:5px}
.char-svc-card .svc-name{font-size:12px;font-weight:700;color:var(--text)}
.char-svc-card .svc-cost{font-size:11px;color:var(--gold);margin-top:3px}
.char-svc-card .svc-note{font-size:10px;color:var(--red);margin-top:2px}
/* SHOP */
.shop-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-top:8px}
.shop-item{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:14px;text-align:center}
.shop-item .si-name{font-size:13px;font-weight:700;color:var(--text);margin-bottom:4px}
.shop-item .si-desc{font-size:11px;color:var(--muted);line-height:1.4;margin-bottom:8px}
.shop-item .si-price{font-size:12px;color:var(--gold);font-weight:700;margin-bottom:8px}
/* FORM extras */
.form-row select,.form-row textarea{width:100%;background:var(--bg2);border:1px solid var(--bdr);border-radius:8px;padding:10px 14px;color:var(--text);font-size:14px;outline:none;transition:border .15s}
.form-row select:focus,.form-row textarea:focus{border-color:var(--gold)}
.form-row textarea{resize:vertical;min-height:80px}
/* QUEST LIST */
.quest-item{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border-bottom:1px solid var(--bdr);font-size:12px}
.quest-item:last-child{border-bottom:none}
/* FORUM */
.forum-cat-row{display:flex;align-items:center;gap:14px;padding:16px 22px;border-bottom:1px solid var(--bdr);cursor:pointer;transition:background .15s}
.forum-cat-row:hover{background:rgba(201,162,61,.05)}
.forum-cat-row:last-child{border-bottom:none}
.forum-cat-ico{font-size:26px;width:44px;text-align:center;flex-shrink:0}
.forum-cat-body{flex:1}
.forum-cat-name{font-size:15px;font-weight:700;color:var(--text)}
.forum-cat-desc{font-size:12px;color:var(--muted);margin-top:3px}
.forum-cat-meta{text-align:right;font-size:11px;color:var(--muted);line-height:1.7;flex-shrink:0}
.forum-thread-row{display:grid;grid-template-columns:1fr 70px 70px;gap:10px;align-items:center;padding:12px 22px;border-bottom:1px solid var(--bdr);cursor:pointer;transition:background .15s}
.forum-thread-row:hover{background:rgba(201,162,61,.05)}
.forum-thread-row:last-child{border-bottom:none}
.forum-thread-name{font-size:14px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.forum-thread-sub{font-size:11px;color:var(--muted);margin-top:3px}
.forum-thread-stat{text-align:center;font-size:11px;color:var(--muted)}
.forum-thread-stat .n{font-size:15px;font-weight:700;color:var(--text);display:block}
.forum-badge{display:inline-block;font-size:10px;padding:2px 7px;border-radius:4px;font-weight:700;vertical-align:middle}
.forum-badge.pin{background:rgba(201,162,61,.15);color:var(--gold)}
.forum-badge.lock{background:rgba(107,112,153,.15);color:var(--muted)}
.forum-post-box{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:18px 22px;margin-bottom:14px}
.forum-post-hdr{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--bdr)}
.forum-post-author{font-weight:800;font-size:14px;color:var(--gold)}
.forum-post-meta{font-size:11px;color:var(--muted)}
.forum-post-body{font-size:13px;color:var(--text);line-height:1.7;white-space:pre-wrap;word-break:break-word}
.forum-breadcrumb{display:flex;gap:6px;align-items:center;font-size:12px;color:var(--muted);margin-bottom:18px;flex-wrap:wrap}
.forum-breadcrumb .crumb{cursor:pointer;color:var(--gold)}
.forum-breadcrumb .crumb:hover{text-decoration:underline}
.forum-card{background:var(--bg);border:1px solid var(--bdr);border-radius:12px;overflow:hidden;margin-bottom:4px}
.forum-hdr-row{display:grid;grid-template-columns:1fr 70px 70px;gap:10px;padding:8px 22px;border-bottom:1px solid var(--bdr);font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase}
.forum-empty{padding:40px;text-align:center;color:var(--muted);font-size:13px}
/* HISTORY */
.hist-item{display:flex;justify-content:space-between;align-items:flex-start;padding:10px 14px;border-bottom:1px solid var(--bdr);font-size:12px}
.hist-item:last-child{border-bottom:none}
.hist-item .hi-desc{color:var(--text);flex:1;padding-right:10px}
.hist-item .hi-amt{font-weight:700;min-width:60px;text-align:right;white-space:nowrap}
.hist-item .hi-amt.pos{color:var(--green)}
.hist-item .hi-amt.neg{color:var(--red)}
.hist-item .hi-meta{font-size:10px;color:var(--muted);display:block;margin-top:2px}
.hist-tabs{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.hist-tab{padding:6px 14px;border-radius:20px;cursor:pointer;font-size:12px;font-weight:700;border:1px solid var(--bdr);background:var(--bg2);color:var(--muted);transition:all .18s}
.hist-tab.active{background:var(--gold);border-color:var(--gold);color:#222}
/* SHARED INPUT */
.input{background:var(--bg2);border:1px solid var(--bdr);border-radius:8px;padding:9px 13px;color:var(--text);font-size:13px;outline:none;transition:border-color .15s;font-family:inherit}
.input:focus{border-color:var(--gold)}
.input option{background:var(--card);color:var(--text)}
/* WEB CHAT */
.wchat-wrap{display:flex;flex-direction:column;height:560px;overflow:hidden}
.wchat-toolbar{display:flex;gap:6px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--bdr);flex-wrap:wrap;flex-shrink:0}
.wchat-tab{padding:4px 12px;border-radius:16px;cursor:pointer;font-size:11px;font-weight:700;border:1px solid var(--bdr);background:var(--bg2);color:var(--muted);transition:all .15s}
.wchat-tab.active{background:var(--gold);border-color:var(--gold);color:#222}
.wchat-log{flex:1;overflow-y:auto;padding:10px 16px;display:flex;flex-direction:column;gap:1px;min-height:0;scroll-behavior:smooth}
.wchat-msg{font-size:12px;line-height:1.65;padding:2px 4px;border-radius:4px;word-break:break-word}
.wchat-msg.say{color:#e8e8e8}
.wchat-msg.yell{color:#FFD700}
.wchat-msg.guild{color:#40C040}
.wchat-msg.officer{color:#40A040}
.wchat-msg.whisper{color:#FF80FF}
.wchat-msg.party{color:#80C0FF}
.wchat-msg.raid{color:#FF8040}
.wchat-msg.emote{color:#FFAAAA;font-style:italic}
.wchat-msg.chan{color:#00CCFF}
.wchat-msg:hover{background:rgba(255,255,255,.04)}
.wchat-ts{color:var(--muted);font-size:10px;margin-right:5px;user-select:none}
.wchat-type-tag{font-size:10px;opacity:.6;margin-right:4px}
.wchat-sender{font-weight:700}
.wchat-input{display:flex;gap:8px;align-items:center;padding:10px 14px;border-top:1px solid var(--bdr);flex-wrap:wrap;flex-shrink:0}
.wchat-status-bar{font-size:11px;color:var(--muted);padding:6px 16px;border-top:1px solid var(--bdr);flex-shrink:0}
.wchat-char-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 13px;background:var(--bg2);border:1px solid var(--bdr);border-radius:18px;font-size:12px;cursor:pointer;transition:border-color .15s,color .15s;user-select:none}
.wchat-char-pill:hover{border-color:var(--gold)}
.wchat-char-pill.is-online{border-color:rgba(34,197,94,.4);color:var(--text)}
.wchat-char-pill.is-offline{color:var(--muted)}
.wchat-char-pill.is-selected{border-color:var(--gold)!important;color:var(--gold)!important;background:rgba(201,162,61,.08)}
</style>
</head>
<body>
<!-- NAVIGATION -->
<nav>
  <a class="nav-logo" href="#" onclick="navTo('home')">
    <div class="ico">⚔</div>
    <span>LINEAGE REBORN</span>
  </a>
  <div class="nav-links">
    <div class="nav-link always active" data-page="home" onclick="navTo('home')">Inicio</div>
    <div class="nav-link always" data-page="forum" onclick="navTo('forum')">Foro</div>
    <div class="nav-link always" data-page="chat" onclick="navTo('chat')">Chat</div>
    <div class="nav-link always" data-page="news" onclick="navTo('news')">Noticias</div>
    <div class="nav-link" data-page="downloads" onclick="navTo('downloads')">Descargas</div>
    <div class="nav-link" data-page="rankings" onclick="navTo('rankings')">Rankings</div>
    <div class="nav-link" data-page="status" onclick="navTo('status')">Estado</div>
  </div>
  <div class="nav-auth" id="nav-auth">
    <button class="btn btn-ghost btn-sm" onclick="openLogin()">Ingresar</button>
    <button class="btn btn-gold btn-sm" onclick="openRegister()">Registrarse</button>
  </div>
</nav>

<!-- MAIN -->
<div class="main">

<!-- ═══ HOME ═══ -->
<div class="section active" id="sec-home">
  <!-- Hero -->
  <div class="hero">
    <div class="hero-inner">
      <div class="hero-badge">⚡ Wrath of the Lich King Classic 3.4.3</div>
      <h1>La Aventura<br>Comienza Aqui</h1>
      <p>Un servidor privado Wrath of the Lich King con rates progresivos, PvP equilibrado y una comunidad activa. ¡Unete ahora!</p>
      <div class="hero-btns">
        <button class="btn btn-gold" style="padding:12px 28px;font-size:15px" onclick="navTo('downloads')">&#x1F3AE; Jugar Ahora</button>
        <button class="btn btn-outline" style="padding:12px 28px;font-size:15px" onclick="openRegister()">&#x1F4DD; Crear Cuenta</button>
      </div>
      <div class="hero-stats" id="hero-stats">
        <div class="hero-stat"><div class="val"><span class="dot"></span><span id="hs-online">...</span></div><div class="lbl">En linea</div></div>
        <div class="hero-stat"><div class="val" id="hs-chars">...</div><div class="lbl">Personajes</div></div>
        <div class="hero-stat"><div class="val" id="hs-guilds">...</div><div class="lbl">Guilds</div></div>
        <div class="hero-stat"><div class="val" id="hs-uptime">...</div><div class="lbl">Uptime</div></div>
      </div>
    </div>
  </div>

  <div class="container">
    <!-- Featured slider -->
    <div class="sec-pad" style="padding-top:32px;padding-bottom:16px">
      <div class="sec-hdr">
        <h2>Noticias <span>Destacadas</span></h2>
        <a href="#" onclick="navTo('news')" style="font-size:13px">Ver todas &rarr;</a>
      </div>
      <div class="slider-wrap">
        <div class="slider-track" id="slider-track"></div>
        <div class="slider-nav">
          <button class="slider-btn" onclick="sliderPrev()">&#x276E;</button>
          <button class="slider-btn" onclick="sliderNext()">&#x276F;</button>
        </div>
      </div>
      <div class="slider-dots" id="slider-dots"></div>
    </div>

    <!-- Latest news grid -->
    <div class="sec-pad" style="padding-top:16px">
      <div class="sec-hdr">
        <h2>Ultimas <span>Noticias</span></h2>
      </div>
      <div class="news-grid" id="home-news-grid"><div class="empty">Cargando...</div></div>
    </div>

    <!-- Features row -->
    <div class="sec-pad" style="padding-top:0">
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px">
        <div class="status-card"><div class="status-ico">&#x1F4DC;</div><div style="font-weight:700;margin-bottom:6px">Lore Autentico</div><div style="font-size:12px;color:var(--muted)">Historia fiel al WotLK original con quests y eventos clasicos</div></div>
        <div class="status-card"><div class="status-ico">&#x2694;</div><div style="font-weight:700;margin-bottom:6px">PvP Competitivo</div><div style="font-size:12px;color:var(--muted)">Arenas balanceadas, Battlegrounds activos y Wintergrasp diario</div></div>
        <div class="status-card"><div class="status-ico">&#x1F3F0;</div><div style="font-weight:700;margin-bottom:6px">Raids Progresivas</div><div style="font-size:12px;color:var(--muted)">Desde Naxxramas hasta Icecrown Citadel con dificultad ajustada</div></div>
        <div class="status-card"><div class="status-ico">&#x1F6E1;</div><div style="font-weight:700;margin-bottom:6px">Staff Dedicado</div><div style="font-size:12px;color:var(--muted)">Equipo activo, anti-cheat y soporte en espanol e ingles</div></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ NEWS ═══ -->
<div class="section" id="sec-news">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F4F0; Noticias</h1>
      <p>Actualizaciones, eventos y parches del servidor</p>
    </div>
  </div>
  <div class="container">
    <div class="cat-tabs" id="news-cat-tabs">
      <div class="cat-tab active" data-cat="all" onclick="newsSetCat('all')">Todas</div>
      <div class="cat-tab" data-cat="parches" onclick="newsSetCat('parches')">Parches</div>
      <div class="cat-tab" data-cat="eventos" onclick="newsSetCat('eventos')">Eventos</div>
      <div class="cat-tab" data-cat="mantenimiento" onclick="newsSetCat('mantenimiento')">Mantenimiento</div>
      <div class="cat-tab" data-cat="actualizacion" onclick="newsSetCat('actualizacion')">Actualizaciones</div>
      <div class="cat-tab" data-cat="general" onclick="newsSetCat('general')">General</div>
    </div>
    <div class="news-grid" id="news-grid"><div class="empty">Cargando...</div></div>
    <div class="pager" id="news-pager"></div>
  </div>
</div>

<!-- ═══ ARTICLE ═══ -->
<div class="section" id="sec-article">
  <div class="container">
    <div class="article-header">
      <div style="margin-bottom:12px"><a href="#" onclick="navTo('news')" style="font-size:13px;color:var(--muted)">&larr; Volver a Noticias</a></div>
      <span id="art-cat" class="nc-cat" style="font-size:11px;padding:3px 10px;border-radius:10px;margin-bottom:12px;display:inline-block"></span>
      <h1 id="art-title" style="font-size:28px;font-weight:800;margin:10px 0"></h1>
      <div style="font-size:12px;color:var(--muted);margin-top:8px">Por <strong id="art-author" style="color:var(--text)"></strong> &mdash; <span id="art-date"></span></div>
    </div>
    <div class="article-content" id="art-content"></div>
  </div>
</div>

<!-- ═══ FORUM ═══ -->
<div class="section" id="sec-forum">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F4AC; Foro</h1>
      <p>Discusion, guias y soporte de la comunidad</p>
    </div>
  </div>
  <div class="container">
    <div class="sec-pad">
      <div class="forum-breadcrumb" id="forum-bc"></div>
      <!-- Category list -->
      <div id="forum-view-cats">
        <div class="forum-card" id="forum-cats-list"><div class="forum-empty">Cargando...</div></div>
      </div>
      <!-- Thread list -->
      <div id="forum-view-threads" style="display:none">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
          <div id="forum-cat-title" style="font-size:20px;font-weight:800;color:var(--gold)"></div>
          <button class="btn btn-gold btn-sm" onclick="forumOpenNewThread()" id="forum-btn-new" style="display:none">&#x270F; Nuevo Tema</button>
        </div>
        <div class="forum-card">
          <div class="forum-hdr-row"><div>Tema</div><div>Vistas</div><div>Respuestas</div></div>
          <div id="forum-threads-list"></div>
        </div>
        <div id="forum-threads-pager" style="text-align:center;margin-top:14px"></div>
      </div>
      <!-- Thread view -->
      <div id="forum-view-thread" style="display:none">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;flex-wrap:wrap;gap:10px">
          <div id="forum-thread-title" style="font-size:19px;font-weight:800;color:var(--text);flex:1;min-width:0"></div>
          <div id="forum-thread-actions" style="display:flex;gap:8px;flex-wrap:wrap;flex-shrink:0"></div>
        </div>
        <div id="forum-posts-list"></div>
        <div id="forum-posts-pager" style="text-align:center;margin-top:14px"></div>
        <div id="forum-reply-area" style="margin-top:22px"></div>
      </div>
      <!-- New thread form -->
      <div id="forum-view-newthread" style="display:none">
        <div class="dl-card">
          <div style="font-size:16px;font-weight:800;margin-bottom:18px">&#x270F; Crear Nuevo Tema</div>
          <div class="form-row">
            <label>Titulo</label>
            <input type="text" id="forum-new-title" placeholder="Titulo del tema..." maxlength="120"
              style="width:100%;background:var(--bg2);border:1px solid var(--bdr);border-radius:8px;padding:10px 14px;color:var(--text);font-size:14px;outline:none;transition:border .15s;box-sizing:border-box">
          </div>
          <div class="form-row" style="margin-top:12px">
            <label>Contenido</label>
            <textarea id="forum-new-body" placeholder="Escribe el contenido del tema..." rows="10" maxlength="20000"></textarea>
          </div>
          <div id="forum-new-err" style="color:var(--red);font-size:12px;margin-top:8px;display:none"></div>
          <div style="display:flex;gap:10px;margin-top:16px">
            <button class="btn btn-ghost" onclick="forumBack()">&#x2190; Cancelar</button>
            <button class="btn btn-gold" onclick="forumSubmitThread()">Publicar Tema</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ WEB CHAT ═══ -->
<div class="section" id="sec-chat">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F4AC; Chat del Juego</h1>
      <p>Habla con otros jugadores en tiempo real desde el navegador</p>
    </div>
  </div>
  <div class="container">
    <div class="sec-pad">
      <!-- Character selector -->
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap">
        <span style="font-size:12px;color:var(--muted);flex-shrink:0">Personaje:</span>
        <div id="wchat-char-list" style="display:flex;gap:8px;flex-wrap:wrap">
          <span style="font-size:12px;color:var(--muted)">Inicia sesion para ver tus personajes...</span>
        </div>
        <button class="btn btn-ghost btn-sm" onclick="wchatRefreshChars()" style="flex-shrink:0">&#x21BB; Actualizar</button>
      </div>
      <!-- Chat box -->
      <div class="forum-card wchat-wrap">
        <!-- Filter tabs -->
        <div class="wchat-toolbar">
          <button class="wchat-tab active" data-filter="all" onclick="wchatSetFilter('all')">Todo</button>
          <button class="wchat-tab" data-filter="say" onclick="wchatSetFilter('say')">Say</button>
          <button class="wchat-tab" data-filter="guild" onclick="wchatSetFilter('guild')">Guild</button>
          <button class="wchat-tab" data-filter="whisper" onclick="wchatSetFilter('whisper')">Whisper</button>
          <button class="wchat-tab" data-filter="yell" onclick="wchatSetFilter('yell')">Yell</button>
          <button class="wchat-tab" data-filter="party" onclick="wchatSetFilter('party')">Party/Raid</button>
          <button class="wchat-tab" data-filter="channel" onclick="wchatSetFilter('channel')">Canales</button>
        </div>
        <!-- Messages log -->
        <div id="wchat-log" class="wchat-log">
          <div class="wchat-status-bar" style="border:none;padding:30px 0;text-align:center">
            Selecciona un personaje para ver el chat...
          </div>
        </div>
        <!-- Input area (hidden until char selected) -->
        <div class="wchat-input" id="wchat-input-area" style="display:none">
          <select id="wchat-type" class="input" style="width:115px;flex-shrink:0" onchange="wchatTypeChange()">
            <option value="say">Say</option>
            <option value="yell">Yell</option>
            <option value="guild">Guild</option>
            <option value="officer">Oficial</option>
            <option value="whisper">Whisper</option>
            <option value="emote">Emote</option>
            <option value="channel">Canal</option>
          </select>
          <input id="wchat-target" class="input" style="width:120px;display:none;flex-shrink:0" placeholder="Nombre jugador...">
          <select id="wchat-channel-sel" class="input" style="width:160px;display:none;flex-shrink:0"><option value="">Cargando...</option></select>
          <input id="wchat-msg" class="input" style="flex:1;min-width:120px" placeholder="Escribe un mensaje... (Enter para enviar)" maxlength="255"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){wchatSend();event.preventDefault();}">
          <button class="btn btn-gold" onclick="wchatSend()" style="flex-shrink:0">Enviar</button>
        </div>
        <!-- Status bar -->
        <div class="wchat-status-bar" id="wchat-status-bar" style="display:none"></div>
      </div>
      <!-- Legend -->
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:14px;font-size:11px">
        <span style="color:#e8e8e8">&#x25CF; Say</span>
        <span style="color:#FFD700">&#x25CF; Yell</span>
        <span style="color:#40C040">&#x25CF; Guild</span>
        <span style="color:#FF80FF">&#x25CF; Whisper</span>
        <span style="color:#80C0FF">&#x25CF; Party</span>
        <span style="color:#FF8040">&#x25CF; Raid</span>
        <span style="color:#FFAAAA;font-style:italic">&#x25CF; Emote</span>
        <span style="color:#00CCFF">&#x25CF; Canales</span>
      </div>
    </div>
  </div>
</div>

<!-- ═══ DOWNLOADS ═══ -->
<div class="section" id="sec-downloads">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F4E5; Descargas</h1>
      <p>Cliente del juego, parches y addons recomendados</p>
    </div>
  </div>
  <div class="container">
    <div class="sec-hdr"><h2>Cliente del <span>Juego</span></h2></div>
    <div class="dl-grid">
      <div class="dl-card">
        <div class="dl-ico">&#x1FA9F;</div>
        <div class="dl-name">WotLK Client (Windows)</div>
        <div class="dl-desc">Cliente oficial Wrath of the Lich King 3.4.3 para Windows. Include todos los parches necesarios.</div>
        <div class="dl-meta"><span>&#x1F4BE; ~15 GB</span><span>&#x1F5A5; Windows</span></div>
        <a href="https://archive.org" target="_blank" class="btn btn-gold" style="display:block;text-align:center">Descargar</a>
      </div>
      <div class="dl-card">
        <div class="dl-ico">&#x1F4E6;</div>
        <div class="dl-name">Parche de Realmlist</div>
        <div class="dl-desc">Archivo realmlist.wtf preconfigurado para conectarte directamente al servidor.</div>
        <div class="dl-meta"><span>&#x1F4BE; &lt; 1 KB</span><span>&#x1F527; Config</span></div>
        <a href="#" onclick="downloadRealmlist()" class="btn btn-outline" style="display:block;text-align:center">Descargar</a>
      </div>
      <div class="dl-card">
        <div class="dl-ico">&#x1F3AE;</div>
        <div class="dl-name">Launcher Personalizado</div>
        <div class="dl-desc">Lanzador con actualizaciones automaticas, lista de servidores y estadisticas en tiempo real.</div>
        <div class="dl-meta"><span>&#x1F4BE; ~5 MB</span><span>&#x1F5A5; Windows</span></div>
        <button class="btn btn-ghost" style="width:100%">Proximamente</button>
      </div>
    </div>

    <div class="divider"></div>
    <div class="sec-hdr"><h2>Addons <span>Recomendados</span></h2></div>
    <div class="dl-grid">
      <div class="dl-card">
        <div class="dl-ico">&#x1F4A5;</div>
        <div class="dl-name">Deadly Boss Mods</div>
        <div class="dl-desc">Alertas para jefes en raids e instancias. Imprescindible para cualquier raider.</div>
        <div class="dl-meta"><span>Combate</span><span>Essential</span></div>
        <a href="https://www.curseforge.com/wow/addons/deadly-boss-mods" target="_blank" class="btn btn-outline" style="display:block;text-align:center">CurseForge &rarr;</a>
      </div>
      <div class="dl-card">
        <div class="dl-ico">&#x1F4CA;</div>
        <div class="dl-name">Recount / Skada</div>
        <div class="dl-desc">Medidor de DPS/HPS. Analiza el rendimiento del grupo en tiempo real.</div>
        <div class="dl-meta"><span>Estadisticas</span><span>Util</span></div>
        <a href="https://www.curseforge.com" target="_blank" class="btn btn-outline" style="display:block;text-align:center">CurseForge &rarr;</a>
      </div>
      <div class="dl-card">
        <div class="dl-ico">&#x1F5BC;</div>
        <div class="dl-name">ElvUI</div>
        <div class="dl-desc">Redisena completamente la interfaz del juego. Moderno, limpio y altamente configurable.</div>
        <div class="dl-meta"><span>Interfaz</span><span>Popular</span></div>
        <a href="https://www.tukui.org" target="_blank" class="btn btn-outline" style="display:block;text-align:center">TukUI &rarr;</a>
      </div>
    </div>

    <div class="divider"></div>
    <div style="background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:24px;margin-bottom:32px">
      <h3 style="margin-bottom:12px">&#x1F4CB; Guia de Instalacion Rapida</h3>
      <ol style="color:var(--muted);font-size:13px;line-height:2;padding-left:20px">
        <li>Descarga el cliente de WotLK 3.4.3</li>
        <li>Instala o extrae el cliente en cualquier carpeta</li>
        <li>Descarga y reemplaza el archivo <code style="background:var(--bg2);padding:1px 6px;border-radius:4px">realmlist.wtf</code> en la carpeta <code style="background:var(--bg2);padding:1px 6px;border-radius:4px">Data/enUS/</code></li>
        <li>Ejecuta <code style="background:var(--bg2);padding:1px 6px;border-radius:4px">WoW.exe</code> y crea tu cuenta en este portal</li>
        <li>¡Inicia sesion en el juego con tu email y contrasena!</li>
      </ol>
    </div>
  </div>
</div>

<!-- ═══ RANKINGS ═══ -->
<div class="section" id="sec-rankings">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F3C6; Rankings</h1>
      <p>Los mejores jugadores y guilds del servidor</p>
    </div>
  </div>
  <div class="container">
    <div class="rank-tabs">
      <button class="rank-tab active" onclick="rankLoad('honor',this)">&#x2694; Honor</button>
      <button class="rank-tab" onclick="rankLoad('level',this)">&#x2B50; Nivel</button>
      <button class="rank-tab" onclick="rankLoad('guilds',this)">&#x1F3F0; Guilds</button>
      <button class="rank-tab" onclick="rankLoad('classes',this)">&#x1F9D9; Por Clase</button>
      <button class="rank-tab" onclick="rankLoad('races',this)">&#x1F9DD; Por Raza</button>
      <button class="rank-tab" onclick="rankLoad('achievements',this)">&#x1F3C6; Logros</button>
    </div>
    <div id="rank-container"><div class="empty">Cargando...</div></div>
  </div>
</div>

<!-- ═══ STATUS ═══ -->
<div class="section" id="sec-status">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F4E1; Estado del Servidor</h1>
      <p>Estado en tiempo real &mdash; actualiza cada 30 segundos</p>
    </div>
  </div>
  <div class="container">
    <div class="sec-hdr"><h2>&#x1F4F6; <span>Servicios</span></h2></div>
    <div id="svc-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:32px"><div class="empty">Cargando...</div></div>
    <div class="sec-hdr" style="margin-top:8px"><h2>&#x26A1; <span>Tasas del Servidor</span></h2></div>
    <div id="rate-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:14px;margin-bottom:32px"></div>
    <div class="sec-hdr" style="margin-top:8px"><h2>&#x1F4CA; <span>Estadisticas</span></h2></div>
    <div class="status-grid" id="status-grid"></div>
  </div>
</div>

<!-- ═══ ACCOUNT ═══ -->
<div class="section" id="sec-account">
  <div class="page-hero">
    <div class="container">
      <h1>&#x1F464; Mi Cuenta</h1>
      <p>Gestiona tu cuenta y personajes</p>
    </div>
  </div>
  <div class="container">
    <div id="acc-content"><div class="empty">Inicia sesion para ver tu cuenta</div></div>
  </div>
</div>

</div><!-- /main -->

<!-- ═ MODALS ═ -->
<div class="overlay" id="modal-login">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('login')">&#x2715;</button>
    <h2>&#x1F511; Iniciar Sesion</h2>
    <div class="subtitle">Accede a tu cuenta del servidor</div>
    <div class="form-row"><label>Email</label><input type="email" id="li-email" placeholder="tu@email.com" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <div class="form-row"><label>Contrasena</label><input type="password" id="li-pass" placeholder="••••••••" onkeydown="if(event.key==='Enter')doLogin()"></div>
    <div class="form-footer">
      <button class="btn btn-gold" onclick="doLogin()" style="width:100%;padding:12px">Ingresar</button>
      <div class="form-switch">¿No tienes cuenta? <a onclick="closeModal('login');openRegister()">Registrate aqui</a></div>
    </div>
    <div id="li-err" style="margin-top:12px;font-size:12px;color:var(--red);text-align:center;display:none"></div>
  </div>
</div>

<div class="overlay" id="modal-register">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('register')">&#x2715;</button>
    <h2>&#x1F4DD; Crear Cuenta</h2>
    <div class="subtitle">Registrate y empieza a jugar gratis</div>
    <div class="form-row"><label>Email</label><input type="email" id="rg-email" placeholder="tu@email.com"></div>
    <div class="form-row"><label>Contrasena</label><input type="password" id="rg-pass" placeholder="Minimo 6 caracteres"></div>
    <div class="form-row"><label>Confirmar Contrasena</label><input type="password" id="rg-pass2" placeholder="Repite la contrasena" onkeydown="if(event.key==='Enter')doRegister()"></div>
    <div style="font-size:11px;color:var(--muted);margin-bottom:16px;line-height:1.6">Al registrarte aceptas los <a>Terminos de Servicio</a> y las <a>Reglas del Servidor</a>.</div>
    <div class="form-footer">
      <button class="btn btn-gold" onclick="doRegister()" style="width:100%;padding:12px">Crear Cuenta</button>
      <div class="form-switch">¿Ya tienes cuenta? <a onclick="closeModal('register');openLogin()">Inicia sesion</a></div>
    </div>
    <div id="rg-err" style="margin-top:12px;font-size:12px;color:var(--red);text-align:center;display:none"></div>
  </div>
</div>

<div class="overlay" id="modal-chpass">
  <div class="modal">
    <button class="modal-close" onclick="closeModal('chpass')">&#x2715;</button>
    <h2>&#x1F504; Cambiar Contrasena</h2>
    <div class="subtitle">Actualiza la contrasena de tu cuenta</div>
    <div class="form-row"><label>Nueva Contrasena</label><input type="password" id="cp-new" placeholder="Nueva contrasena (min 6 caracteres)"></div>
    <div class="form-row"><label>Confirmar Nueva</label><input type="password" id="cp-new2" placeholder="Confirmar nueva contrasena"></div>
    <div class="form-footer">
      <button class="btn btn-gold" onclick="doChangePass()" style="width:100%;padding:12px">Actualizar Contrasena</button>
    </div>
    <div id="cp-err" style="margin-top:12px;font-size:12px;color:var(--red);text-align:center;display:none"></div>
  </div>
</div>

<!-- MODAL: 2FA -->
<div class="overlay" id="modal-2fa">
  <div class="modal" style="max-width:480px">
    <button class="modal-close" onclick="closeModal('2fa')">&#x2715;</button>
    <h2>&#x1F4F1; Verificacion en 2 Pasos</h2>
    <div class="subtitle">Protege tu cuenta con Google Authenticator o similar</div>
    <div id="fa-body">
      <div id="fa-setup" style="display:none">
        <p style="font-size:13px;color:var(--muted);margin-bottom:16px">Escanea el codigo QR con tu app de autenticacion o introduce el codigo manualmente.</p>
        <div style="text-align:center;margin-bottom:16px"><img id="fa-qr" src="" width="180" height="180" style="border-radius:8px;background:#fff;padding:6px"></div>
        <div style="background:var(--bg);border:1px solid var(--bdr);border-radius:8px;padding:10px;text-align:center;font-family:monospace;font-size:14px;letter-spacing:2px;margin-bottom:16px" id="fa-secret-txt"></div>
        <div class="form-row"><label>Codigo de verificacion (6 digitos)</label><input type="text" id="fa-code" maxlength="6" placeholder="000000" inputmode="numeric"></div>
        <button class="btn btn-gold" onclick="do2FAEnable()" style="width:100%;padding:11px;margin-top:8px">Activar 2FA</button>
        <div id="fa-err" style="margin-top:10px;font-size:12px;color:var(--red);display:none"></div>
      </div>
      <div id="fa-disable" style="display:none">
        <p style="font-size:13px;color:var(--muted);margin-bottom:16px">Introduce el codigo de tu app para desactivar el 2FA.</p>
        <div class="form-row"><label>Codigo TOTP actual</label><input type="text" id="fa-dis-code" maxlength="6" placeholder="000000" inputmode="numeric"></div>
        <button class="btn btn-gold" onclick="do2FADisable()" style="width:100%;padding:11px;margin-top:8px;background:var(--red)">Desactivar 2FA</button>
        <div id="fa-dis-err" style="margin-top:10px;font-size:12px;color:var(--red);display:none"></div>
      </div>
      <div id="fa-loading" style="text-align:center;padding:40px;color:var(--muted)">Cargando...</div>
    </div>
  </div>
</div>

<!-- MODAL: Transferir PD -->
<div class="overlay" id="modal-transfer">
  <div class="modal" style="max-width:440px">
    <button class="modal-close" onclick="closeModal('transfer')">&#x2715;</button>
    <h2>&#x1F4E4; Transferir PD</h2>
    <div class="subtitle">Envia Puntos de Donacion a otra cuenta</div>
    <div class="form-row"><label>Email de destino</label><input type="email" id="tr-email" placeholder="cuenta@ejemplo.com"></div>
    <div class="form-row"><label>Cantidad de PD</label><input type="number" id="tr-amount" min="1" placeholder="Cantidad"></div>
    <p style="font-size:11px;color:var(--muted);margin-bottom:12px" id="tr-fee-info"></p>
    <button class="btn btn-gold" onclick="doTransfer()" style="width:100%;padding:11px">Transferir</button>
    <div id="tr-err" style="margin-top:10px;font-size:12px;color:var(--red);display:none"></div>
  </div>
</div>

<!-- MODAL: Comercio PD -->
<div class="overlay" id="modal-trade">
  <div class="modal" style="max-width:480px">
    <button class="modal-close" onclick="closeModal('trade')">&#x2715;</button>
    <h2>&#x2696; Comercio PD / Oro</h2>
    <div class="subtitle" id="trade-rates-txt">Cargando tasas...</div>
    <div style="margin-bottom:16px">
      <div class="rank-tabs">
        <button class="rank-tab active" id="trade-tab-buy" onclick="tradeTab('buy')">&#x1F4B0; Comprar PD con Oro</button>
        <button class="rank-tab" id="trade-tab-sell" onclick="tradeTab('sell')">&#x1F4B8; Vender PD por Oro</button>
      </div>
      <div class="form-row"><label>Personaje</label><select id="trade-char" style="width:100%;padding:9px;border-radius:8px;background:var(--bg);border:1px solid var(--bdr);color:var(--text)"></select></div>
      <div class="form-row"><label id="trade-pd-lbl">Cantidad de PD a comprar</label><input type="number" id="trade-pd" min="1" placeholder="PD"></div>
      <p style="font-size:12px;color:var(--muted)" id="trade-calc"></p>
      <button class="btn btn-gold" onclick="doTrade()" style="width:100%;padding:11px;margin-top:8px" id="trade-btn">Confirmar</button>
      <div id="trade-err" style="margin-top:10px;font-size:12px;color:var(--red);display:none"></div>
    </div>
  </div>
</div>

<!-- MODAL: Codigo Promocional -->
<div class="overlay" id="modal-promo">
  <div class="modal" style="max-width:400px">
    <button class="modal-close" onclick="closeModal('promo')">&#x2715;</button>
    <h2>&#x1F381; Codigo Promocional</h2>
    <div class="subtitle">Canjea un codigo por PD o PV</div>
    <div class="form-row"><label>Codigo</label><input type="text" id="promo-code" placeholder="CODIGO-PROMO" style="text-transform:uppercase"></div>
    <button class="btn btn-gold" onclick="doPromo()" style="width:100%;padding:11px;margin-top:8px">Canjear</button>
    <div id="promo-msg" style="margin-top:10px;font-size:13px;text-align:center;display:none"></div>
  </div>
</div>

<!-- MODAL: Votar -->
<div class="overlay" id="modal-vote">
  <div class="modal" style="max-width:500px">
    <button class="modal-close" onclick="closeModal('vote')">&#x2715;</button>
    <h2>&#x1F5F3; Vota por Nosotros</h2>
    <div class="subtitle">Vota en cada sitio y reclama tus PV</div>
    <div id="vote-sites"><div style="text-align:center;color:var(--muted);padding:30px">Cargando...</div></div>
  </div>
</div>

<!-- MODAL: Stripe -->
<div class="overlay" id="modal-stripe">
  <div class="modal" style="max-width:500px">
    <button class="modal-close" onclick="closeModal('stripe')">&#x2715;</button>
    <h2>&#x1F4B3; Adquirir PD</h2>
    <div class="subtitle">Compra Puntos de Donacion con tarjeta</div>
    <div id="stripe-pkgs"><div style="text-align:center;color:var(--muted);padding:30px">Cargando...</div></div>
    <div id="stripe-err" style="margin-top:12px;font-size:12px;color:var(--red);display:none"></div>
  </div>
</div>

<!-- CHAR MANAGEMENT MODAL -->
<div class="overlay" id="modal-char-mgmt">
  <div class="modal" style="max-width:640px;overflow-y:auto;max-height:88vh">
    <button class="modal-close" onclick="closeModal('char-mgmt')">&#x2715;</button>
    <div id="cmgmt-char-hdr" style="margin-bottom:18px"></div>
    <!-- View: services grid (default) -->
    <div id="cmgmt-view-main"></div>
    <!-- View: quest tracker -->
    <div id="cmgmt-view-quest" style="display:none">
      <div style="font-size:14px;font-weight:700;margin-bottom:10px">&#x1F4CB; Rastreador de Misiones</div>
      <div id="cmgmt-quest-list" style="max-height:340px;overflow-y:auto;border:1px solid var(--bdr);border-radius:8px"></div>
      <button class="btn btn-ghost" style="margin-top:14px" onclick="cmgmtBack()">&#x2190; Volver</button>
    </div>
    <!-- View: generic action form -->
    <div id="cmgmt-view-form" style="display:none">
      <div id="cmgmt-form-title" style="font-size:15px;font-weight:800;color:var(--gold);margin-bottom:14px"></div>
      <div id="cmgmt-form-body"></div>
      <div id="cmgmt-form-err" style="color:var(--red);font-size:12px;margin-top:8px;display:none"></div>
      <div style="display:flex;gap:8px;margin-top:18px">
        <button class="btn btn-ghost" onclick="cmgmtBack()">&#x2190; Volver</button>
        <button class="btn btn-gold" id="cmgmt-confirm-btn" onclick="cmgmtDoAction()">Confirmar</button>
      </div>
    </div>
    <!-- View: deleted chars -->
    <div id="cmgmt-view-deleted" style="display:none">
      <div style="font-size:14px;font-weight:700;margin-bottom:10px">&#x267B; Recuperar personaje borrado</div>
      <div id="cmgmt-deleted-list" style="max-height:360px;overflow-y:auto"></div>
      <div id="cmgmt-deleted-err" style="color:var(--red);font-size:12px;margin-top:8px;display:none"></div>
      <button class="btn btn-ghost" style="margin-top:14px" onclick="cmgmtBack()">&#x2190; Volver</button>
    </div>
    <!-- View: item shop -->
    <div id="cmgmt-view-shop" style="display:none">
      <div style="font-size:14px;font-weight:700;margin-bottom:12px">&#x1F6CD; Tienda de Objetos</div>
      <div id="cmgmt-shop-content" style="max-height:420px;overflow-y:auto"></div>
      <div id="cmgmt-shop-err" style="color:var(--red);font-size:12px;margin-top:8px;display:none"></div>
      <button class="btn btn-ghost" style="margin-top:14px" onclick="cmgmtBack()">&#x2190; Volver</button>
    </div>
  </div>
</div>

<!-- HISTORY MODAL -->
<div class="overlay" id="modal-history">
  <div class="modal" style="max-width:620px;overflow-y:auto;max-height:88vh">
    <button class="modal-close" onclick="closeModal('history')">&#x2715;</button>
    <div style="font-size:17px;font-weight:800;margin-bottom:18px">&#x1F4DC; <span style="color:var(--gold)">Historiales</span></div>
    <div class="hist-tabs">
      <button class="hist-tab active" data-cat="pdpv" onclick="switchHistTab('pdpv')">PD / PV</button>
      <button class="hist-tab" data-cat="transaction" onclick="switchHistTab('transaction')">Transacciones</button>
      <button class="hist-tab" data-cat="security" onclick="switchHistTab('security')">Seguridad</button>
    </div>
    <div id="hist-list" style="max-height:380px;overflow-y:auto;border:1px solid var(--bdr);border-radius:8px"></div>
    <div id="hist-pagination" style="text-align:center;margin-top:10px;font-size:12px;color:var(--muted)"></div>
  </div>
</div>

<!-- TOAST -->
<div class="toast-wrap" id="toast-wrap"></div>

<!-- FOOTER -->
<footer>
  <div class="container">
    <div class="footer-grid">
      <div class="footer-brand">
        <div class="ico">⚔</div>
        <div style="font-size:16px;font-weight:700;color:var(--gold2)">Lineage Reborn</div>
        <p>El servidor de Wrath of the Lich King en espanol. Comunidad, progresion y PvP para todos.</p>
      </div>
      <div class="footer-col">
        <h4>Juego</h4>
        <ul>
          <li onclick="navTo('downloads')">Descargar Cliente</li>
          <li onclick="navTo('status')">Estado del Servidor</li>
          <li onclick="navTo('rankings')">Rankings</li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Comunidad</h4>
        <ul>
          <li>Discord</li>
          <li onclick="navTo('forum')" style="cursor:pointer">Foro</li>
          <li>Wiki</li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Cuenta</h4>
        <ul>
          <li onclick="openRegister()">Registrarse</li>
          <li onclick="openLogin()">Iniciar Sesion</li>
          <li onclick="navTo('account')">Mi Cuenta</li>
        </ul>
      </div>
    </div>
    <div class="footer-bottom">
      <div>&copy; 2026 Lineage Reborn &mdash; Servidor privado sin fines de lucro</div>
      <div>World of Warcraft es propiedad de Blizzard Entertainment</div>
    </div>
  </div>
</footer>

<script>
// ── STATE ────────────────────────────────────────────────
var TOKEN = localStorage.getItem('pt') || '';
var EMAIL = localStorage.getItem('pe') || '';
var BNET  = parseInt(localStorage.getItem('pb') || '0');
var _statusTimer = null;
var _heroTimer   = null;

// ── NAV ────────────────────────────────────────────────
function navTo(page, pushState) {
  if (page !== 'status' && _statusTimer) { clearInterval(_statusTimer); _statusTimer = null; }
  if (page !== 'chat'   && typeof _wChatTimer!=='undefined' && _wChatTimer) { clearInterval(_wChatTimer); _wChatTimer = null; }
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.nav-link').forEach(function(n){ n.classList.toggle('active', n.dataset.page===page); });
  var el = document.getElementById('sec-'+page);
  if (!el) el = document.getElementById('sec-news');
  el.classList.add('active');
  window.scrollTo(0, 0);
  if (page !== 'home' && _heroTimer) { clearInterval(_heroTimer); _heroTimer = null; }
  if      (page==='home')      { loadHeroStats(); loadHomeNews(); _heroTimer = setInterval(loadHeroStats, 10000); }
  else if (page==='forum')     loadForum();
  else if (page==='chat')      loadWebChat();
  else if (page==='news')      loadNews(0);
  else if (page==='rankings')  rankLoad('honor');
  else if (page==='status')    { loadStatus(); _statusTimer = setInterval(loadStatus, 30000); }
  else if (page==='account')   loadAccount();
  else if (page==='downloads') {}
}

// ── AUTH NAV ────────────────────────────────────────────
function updateNavAuth() {
  var el = document.getElementById('nav-auth');
  if (TOKEN && EMAIL) {
    var initials = EMAIL[0].toUpperCase();
    el.innerHTML = '<div class="user-menu" id="user-menu" onclick="toggleUserMenu()">'
      + '<div class="user-btn"><div class="user-avatar">'+initials+'</div>'+EMAIL.split('@')[0]+'</div>'
      + '<div class="user-dropdown">'
      + '<div class="user-dd-item" onclick="navTo(\'account\')">&#x1F464; Mi Cuenta</div>'
      + '<div class="user-dd-item" onclick="document.getElementById(\'modal-chpass\').classList.add(\'open\')">&#x1F512; Cambiar Contrasena</div>'
      + '<div class="user-dd-sep"></div>'
      + '<div class="user-dd-item" onclick="doLogout()" style="color:var(--red)">&#x23FB; Cerrar Sesion</div>'
      + '</div></div>';
  } else {
    el.innerHTML = '<button class="btn btn-ghost btn-sm" onclick="openLogin()">Ingresar</button>'
      + '<button class="btn btn-gold btn-sm" onclick="openRegister()">Registrarse</button>';
  }
}

function toggleUserMenu() {
  var m = document.getElementById('user-menu');
  if (m) m.classList.toggle('open');
}
document.addEventListener('click', function(e) {
  var m = document.getElementById('user-menu');
  if (m && !m.contains(e.target)) m.classList.remove('open');
});

// ── TOASTS ─────────────────────────────────────────────
function toast(msg, type) {
  type = type || 'ok';
  var w = document.getElementById('toast-wrap');
  var d = document.createElement('div');
  d.className = 'toast ' + type;
  d.textContent = msg;
  w.appendChild(d);
  requestAnimationFrame(function(){ d.classList.add('show'); });
  setTimeout(function(){ d.classList.remove('show'); setTimeout(function(){ d.remove(); }, 300); }, 3500);
}

// ── FETCH HELPERS ───────────────────────────────────────
function pFetch(url, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (TOKEN) opts.headers['x-portal-token'] = TOKEN;
  return fetch(url, opts).then(function(r){
    return r.json().catch(function(){ return {ok:false,error:'Error del servidor'}; });
  });
}

// ── MODALS ──────────────────────────────────────────────
function openLogin()    { document.getElementById('modal-login').classList.add('open'); setTimeout(function(){document.getElementById('li-email').focus();},50); }
function openRegister() { document.getElementById('modal-register').classList.add('open'); }
function closeModal(id) { document.getElementById('modal-'+id).classList.remove('open'); }
document.querySelectorAll('.overlay').forEach(function(o){
  o.addEventListener('click', function(e){ if(e.target===o) o.classList.remove('open'); });
});

// ── AUTH ────────────────────────────────────────────────
function doLogin() {
  var email = document.getElementById('li-email').value.trim();
  var pass  = document.getElementById('li-pass').value;
  var err   = document.getElementById('li-err');
  err.style.display='none';
  if (!email || !pass) { err.textContent='Completa todos los campos'; err.style.display='block'; return; }
  fetch('/api/portal/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:email,password:pass})})
    .then(function(r){return r.json();}).then(function(d){
      if (d.ok) {
        TOKEN = d.token; EMAIL = d.email; BNET = d.bnetId;
        localStorage.setItem('pt', TOKEN); localStorage.setItem('pe', EMAIL); localStorage.setItem('pb', BNET);
        closeModal('login');
        updateNavAuth();
        toast('Bienvenido, '+EMAIL.split('@')[0]+'!');
        navTo('account');
      } else {
        err.textContent = d.error || 'Error al iniciar sesion';
        err.style.display = 'block';
      }
    }).catch(function(){ err.textContent='Error de conexion'; err.style.display='block'; });
}

function doRegister() {
  var email  = document.getElementById('rg-email').value.trim();
  var pass   = document.getElementById('rg-pass').value;
  var pass2  = document.getElementById('rg-pass2').value;
  var err    = document.getElementById('rg-err');
  err.style.display='none';
  if (!email || !pass) { err.textContent='Completa todos los campos'; err.style.display='block'; return; }
  if (pass !== pass2)  { err.textContent='Las contrasenas no coinciden'; err.style.display='block'; return; }
  if (pass.length < 6) { err.textContent='La contrasena debe tener al menos 6 caracteres'; err.style.display='block'; return; }
  fetch('/api/portal/register', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:email,password:pass})})
    .then(function(r){return r.json();}).then(function(d){
      if (d.ok) {
        closeModal('register');
        toast('Cuenta creada correctamente. Ya puedes iniciar sesion.');
        openLogin();
        document.getElementById('li-email').value = email;
      } else {
        err.textContent = d.error || 'Error al crear la cuenta';
        err.style.display='block';
      }
    }).catch(function(){ err.textContent='Error de conexion'; err.style.display='block'; });
}

function doLogout() {
  fetch('/api/portal/logout', {method:'POST', headers:{'x-portal-token':TOKEN}});
  TOKEN=''; EMAIL=''; BNET=0;
  localStorage.removeItem('pt'); localStorage.removeItem('pe'); localStorage.removeItem('pb');
  updateNavAuth();
  toast('Sesion cerrada','info');
}

function doChangePass() {
  var np   = document.getElementById('cp-new').value;
  var np2  = document.getElementById('cp-new2').value;
  var err  = document.getElementById('cp-err');
  err.style.display='none';
  if (!np) { err.textContent='Ingresa la nueva contrasena'; err.style.display='block'; return; }
  if (np!==np2)  { err.textContent='Las contrasenas no coinciden'; err.style.display='block'; return; }
  pFetch('/api/portal/account/password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({new_password:np})})
    .then(function(d){
      if(d.ok){ closeModal('chpass'); toast('Contrasena actualizada correctamente'); }
      else { err.textContent=d.error||'Error al cambiar contrasena'; err.style.display='block'; }
    });
}

// ── STATUS / HERO STATS ─────────────────────────────────
function loadHeroStats() {
  fetch('/api/portal/status').then(function(r){return r.json();}).then(function(d){
    document.getElementById('hs-online').textContent = d.online || 0;
    document.getElementById('hs-chars').textContent  = (d.chars||0).toLocaleString();
    document.getElementById('hs-guilds').textContent = d.guilds || 0;
    document.getElementById('hs-uptime').textContent = d.uptime || '--';
  }).catch(function(){});
}

function svcCard(name, online, sub, uptime) {
  var badge = online
    ? '<span style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.35);border-radius:20px;padding:4px 12px;font-size:11px;font-weight:700;white-space:nowrap">&#x25CF; EN LINEA</span>'
    : '<span style="background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.35);border-radius:20px;padding:4px 12px;font-size:11px;font-weight:700;white-space:nowrap">&#x25CF; OFFLINE</span>';
  return '<div class="dl-card" style="display:flex;align-items:center;gap:16px">'
    +'<div style="font-size:32px;line-height:1">'+(online?'&#x1F7E2;':'&#x1F534;')+'</div>'
    +'<div style="flex:1;min-width:0">'
    +'<div style="font-weight:700;font-size:15px;margin-bottom:3px">'+escH(name)+'</div>'
    +(sub?'<div style="font-size:12px;color:var(--muted)">'+escH(sub)+'</div>':'')
    +(uptime?'<div style="font-size:11px;color:var(--muted);margin-top:2px">Uptime: '+escH(uptime)+'</div>':'')
    +'</div>'+badge+'</div>';
}
function statCard(ico, label, val, extraStyle) {
  return '<div class="status-card"><div class="status-ico">'+ico+'</div>'
    +'<div class="status-label">'+label+'</div>'
    +'<div class="status-val"'+(extraStyle?' style="'+extraStyle+'"':'')+'>'+(val!==undefined?val:0)+'</div></div>';
}
function popLabel(pop) {
  if (!pop || pop < 200) return 'Baja';
  if (pop < 500)  return 'Media';
  if (pop < 1000) return 'Alta';
  return 'Llena';
}
function loadStatus() {
  var sc = document.getElementById('svc-cards');
  var rc = document.getElementById('rate-cards');
  var gc = document.getElementById('status-grid');
  fetch('/api/portal/status').then(function(r){return r.json();}).then(function(d){
    // Services: bnetserver always online since we serve this page, then all realms
    var svcHtml = svcCard('Servidor de Login', true, 'WotLK Classic 3.4.3', d.uptime);
    if (d.realms && d.realms.length) {
      d.realms.forEach(function(r){
        var sub = r.online ? 'Poblacion: '+popLabel(r.pop) : 'Fuera de linea';
        svcHtml += svcCard(r.name, r.online, sub, null);
      });
    }
    sc.innerHTML = svcHtml;
    // Rates
    var RATE_LABELS = {xp:'Experiencia',drop:'Drop Items',gold:'Oro',rep:'Reputacion',honor:'Honor'};
    var RATE_ICONS  = {xp:'&#x2B50;',drop:'&#x1F4E6;',gold:'&#x1FA99;',rep:'&#x1F4C8;',honor:'&#x2694;'};
    if (d.rates && Object.keys(d.rates).length) {
      rc.innerHTML = Object.keys(d.rates).map(function(k){
        var num = parseFloat(d.rates[k])||0;
        return '<div class="status-card"><div class="status-ico">'+(RATE_ICONS[k]||'&#x1F522;')+'</div>'
          +'<div class="status-label">'+(RATE_LABELS[k]||k)+'</div>'
          +'<div class="status-val">x'+num+'</div></div>';
      }).join('');
    } else {
      rc.innerHTML = '<div class="empty" style="grid-column:1/-1">Rates no configuradas</div>';
    }
    // Stats
    gc.innerHTML = statCard('&#x1F4AC;','Jugadores en Linea',d.online)
      + statCard('&#x1F9D9;','Total Personajes',(d.chars||0).toLocaleString())
      + statCard('&#x1F3F0;','Guilds',d.guilds)
      + statCard('&#x23F1;','Uptime',d.uptime,'font-size:15px');
  }).catch(function(){
    if (sc) sc.innerHTML='<div class="empty">Error al cargar estado</div>';
  });
}

// ── NEWS ────────────────────────────────────────────────
var _newsCat = 'all', _newsPage = 0;

function catClass(cat) {
  var m={'parches':'nc-parches','eventos':'nc-eventos','mantenimiento':'nc-mantenimiento','general':'nc-general','actualizacion':'nc-actualizacion'};
  return m[cat] || 'nc-general';
}
function catLabel(cat) {
  var m={'parches':'Parche','eventos':'Evento','mantenimiento':'Mantenim.','general':'General','actualizacion':'Update'};
  return m[cat] || cat;
}
function newsCard(n) {
  var imgBg = n.image ? 'background-image:url('+JSON.stringify(n.image)+')' : '';
  return '<div class="news-card" onclick="openArticle('+n.id+')">'
    + '<div class="nc-img" style="'+imgBg+'"><div class="nc-img-placeholder">'+(n.image?'':'&#x1F4F0;')+'</div></div>'
    + '<div class="nc-body">'
    + '<span class="nc-cat '+catClass(n.category)+'">'+catLabel(n.category)+'</span>'
    + '<div class="nc-title">'+escH(n.title)+'</div>'
    + '<div class="nc-excerpt">'+escH(n.summary||'')+'</div>'
    + '<div class="nc-foot"><span>'+escH(n.author||'Staff')+'</span><span>'+(n.date||'').substring(0,10)+'</span></div>'
    + '</div></div>';
}

function loadHomeNews() {
  fetch('/api/portal/news?page=0').then(function(r){return r.json();}).then(function(d){
    var g = document.getElementById('home-news-grid');
    if (!d.news || !d.news.length) { g.innerHTML='<div class="empty">No hay noticias disponibles</div>'; return; }
    g.innerHTML = d.news.slice(0,6).map(newsCard).join('');
    loadSlider(d.news.filter(function(n){return n.featured;}).slice(0,5).length ? d.news.filter(function(n){return n.featured;}) : d.news.slice(0,3));
  }).catch(function(){ document.getElementById('home-news-grid').innerHTML='<div class="empty">Error al cargar noticias</div>'; });
}

function newsSetCat(cat) {
  _newsCat = cat; _newsPage = 0;
  document.querySelectorAll('.cat-tab').forEach(function(t){ t.classList.toggle('active', t.dataset.cat===cat); });
  loadNews(0);
}

function loadNews(page) {
  _newsPage = page;
  var url = '/api/portal/news?page='+page+((_newsCat&&_newsCat!=='all')?'&cat='+_newsCat:'');
  fetch(url).then(function(r){return r.json();}).then(function(d){
    var g = document.getElementById('news-grid');
    if (!d.news||!d.news.length) { g.innerHTML='<div class="empty">No hay noticias en esta categoria</div>'; document.getElementById('news-pager').innerHTML=''; return; }
    g.innerHTML = d.news.map(newsCard).join('');
    var p = document.getElementById('news-pager'); p.innerHTML='';
    for(var i=0;i<d.pages;i++){
      var b=document.createElement('button'); b.className='pager-btn'+(i===page?' active':'');
      b.textContent=i+1; (function(pi){b.onclick=function(){loadNews(pi);};})(i);
      p.appendChild(b);
    }
  }).catch(function(){ document.getElementById('news-grid').innerHTML='<div class="empty">Error al cargar noticias</div>'; });
}

function openArticle(id) {
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.getElementById('sec-article').classList.add('active');
  window.scrollTo(0,0);
  fetch('/api/portal/news/article?id='+id).then(function(r){return r.json();}).then(function(d){
    document.getElementById('art-cat').textContent   = catLabel(d.category||'');
    document.getElementById('art-cat').className     = 'nc-cat '+catClass(d.category);
    document.getElementById('art-title').textContent = d.title||'';
    document.getElementById('art-author').textContent= d.author||'Staff';
    document.getElementById('art-date').textContent  = (d.date||'').substring(0,10);
    document.getElementById('art-content').innerHTML = (d.content||'').replace(/\n/g,'<br>');
  });
}

// ── SLIDER ──────────────────────────────────────────────
var _sliderIdx = 0, _sliderLen = 0, _sliderTimer = null;

function loadSlider(items) {
  _sliderLen = items.length; _sliderIdx = 0;
  var track = document.getElementById('slider-track');
  var dots  = document.getElementById('slider-dots');
  if (!items.length) { track.innerHTML='<div class="slide"><div class="slide-content" style="min-height:180px;justify-content:center;align-items:center"><span style="color:var(--muted)">Sin noticias destacadas</span></div></div>'; dots.innerHTML=''; return; }
  track.innerHTML = items.map(function(n){
    return '<div class="slide" onclick="openArticle('+n.id+')" style="cursor:pointer">'
      + (n.image?'<div class="slide-bg" style="background-image:url('+JSON.stringify(n.image)+')"></div>':'')
      + '<div class="slide-content">'
      + '<span class="nc-cat '+catClass(n.category||'general')+'">'+catLabel(n.category||'general')+'</span>'
      + '<div class="slide-title">'+escH(n.title)+'</div>'
      + '<div class="slide-excerpt">'+escH(n.summary||'')+'</div>'
      + '</div></div>';
  }).join('');
  dots.innerHTML = items.map(function(_,i){
    return '<div class="slider-dot'+(i===0?' active':'')+'\" onclick="sliderGo('+i+')"></div>';
  }).join('');
  if (_sliderTimer) clearInterval(_sliderTimer);
  _sliderTimer = setInterval(sliderNext, 6000);
}

function sliderGo(i) {
  _sliderIdx = i;
  document.getElementById('slider-track').style.transform = 'translateX(-'+(_sliderIdx*100)+'%)';
  document.querySelectorAll('.slider-dot').forEach(function(d,idx){ d.classList.toggle('active',idx===_sliderIdx); });
}
function sliderNext() { sliderGo((_sliderIdx+1) % Math.max(1,_sliderLen)); }
function sliderPrev() { sliderGo((_sliderIdx-1+_sliderLen) % Math.max(1,_sliderLen)); }

// ── RANKINGS ─────────────────────────────────────────────
var CLASS_NAMES = ['?','Warrior','Paladin','Hunter','Rogue','Priest','Death Knight','Shaman','Mage','Warlock','?','Druid'];
var CLASS_ICONS = ['?','⚔','🛡','🏹','🗡','✨','💀','🌩','🔮','👁','?','🌿'];
var CLASS_NAMES = ['?','Guerrero','Paladin','Cazador','Pícaro','Sacerdote','Cab. de la Muerte','Chamán','Mago','Brujo','?','Druida'];
var CLASS_COLORS= ['','#C79C6E','#F58CBA','#ABD473','#FFF569','#FFFFFF','#C41F3B','#0070DE','#69CCF0','#9482C9','','#FF7D0A'];
var RACE_NAMES  = ['?','Human','Orc','Dwarf','Night Elf','Undead','Tauren','Gnome','Troll','?','Blood Elf','Draenei'];
var RACE_FACTION= [0,1,2,1,1,2,2,1,2,0,2,1]; // 1=alliance 2=horde
var MEDALS = ['🥇','🥈','🥉'];

function fmtTime(sec) {
  var d=Math.floor(sec/86400), h=Math.floor((sec%86400)/3600), m=Math.floor((sec%3600)/60);
  return (d?d+'d ':'')+(h?h+'h ':'')+(m+'m');
}

function rankLoad(type, btn) {
  if (btn) {
    document.querySelectorAll('.rank-tab').forEach(function(t){ t.classList.remove('active'); });
    btn.classList.add('active');
  }
  var c = document.getElementById('rank-container');
  c.innerHTML = '<div class="empty">Cargando...</div>';
  fetch('/api/portal/rankings?type='+type).then(function(r){return r.json();}).then(function(d){
    var h = '';

    // ── HONOR ──────────────────────────────────────────────────────────
    if (type==='honor') {
      if (!d.rows||!d.rows.length) { c.innerHTML='<div class="empty">Sin datos</div>'; return; }
      h = '<table class="rank-table"><thead><tr>'
        +'<th>#</th><th>Personaje</th><th>Clase</th><th>Raza</th>'
        +'<th>Kills Hoy</th><th>Total Kills</th>'
        +'</tr></thead><tbody>';
      d.rows.forEach(function(r,i){
        var pos = i<3?'<span class="rank-pos top3">'+MEDALS[i]+'</span>':'<span class="rank-pos">'+(i+1)+'</span>';
        var ico=CLASS_ICONS[r.class||0], clsN=CLASS_NAMES[r.class||0]||'?', clsC=CLASS_COLORS[r.class||0]||'#fff';
        var racN=RACE_NAMES[r.race||0]||'?';
        h += '<tr><td>'+pos+'</td><td class="rank-name">'+escH(r.name)+'</td>'
          +'<td><span style="color:'+clsC+'">'+ico+' '+escH(clsN)+'</span></td>'
          +'<td>'+escH(racN)+'</td>'
          +'<td style="color:var(--gold)">'+r.today+'</td>'
          +'<td class="rank-val">'+r.value.toLocaleString()+' kills</td></tr>';
      });
      h += '</tbody></table>';

    // ── NIVEL ──────────────────────────────────────────────────────────
    } else if (type==='level') {
      if (!d.rows||!d.rows.length) { c.innerHTML='<div class="empty">Sin datos</div>'; return; }
      h = '<table class="rank-table"><thead><tr>'
        +'<th>#</th><th>Personaje</th><th>Clase</th><th>Raza</th>'
        +'<th>Nivel</th><th>Tiempo jugado</th>'
        +'</tr></thead><tbody>';
      d.rows.forEach(function(r,i){
        var pos = i<3?'<span class="rank-pos top3">'+MEDALS[i]+'</span>':'<span class="rank-pos">'+(i+1)+'</span>';
        var ico=CLASS_ICONS[r.class||0], clsN=CLASS_NAMES[r.class||0]||'?', clsC=CLASS_COLORS[r.class||0]||'#fff';
        h += '<tr><td>'+pos+'</td><td class="rank-name">'+escH(r.name)+'</td>'
          +'<td><span style="color:'+clsC+'">'+ico+' '+escH(clsN)+'</span></td>'
          +'<td>'+escH(RACE_NAMES[r.race||0]||'?')+'</td>'
          +'<td class="rank-val">'+r.level+'</td>'
          +'<td style="color:var(--muted)">'+fmtTime(r.value)+'</td></tr>';
      });
      h += '</tbody></table>';

    // ── GUILDS ─────────────────────────────────────────────────────────
    } else if (type==='guilds') {
      if (!d.rows||!d.rows.length) { c.innerHTML='<div class="empty">Sin datos</div>'; return; }
      h = '<table class="rank-table"><thead><tr>'
        +'<th>#</th><th>Guild</th><th>Miembros</th><th>Fundada</th>'
        +'</tr></thead><tbody>';
      d.rows.forEach(function(r,i){
        var pos = i<3?'<span class="rank-pos top3">'+MEDALS[i]+'</span>':'<span class="rank-pos">'+(i+1)+'</span>';
        var sinceDate = r.since ? new Date(r.since*1000).toISOString().substring(0,10) : '--';
        h += '<tr><td>'+pos+'</td><td class="rank-name">'+escH(r.name)+'</td>'
          +'<td class="rank-val">'+r.value+'</td><td>'+sinceDate+'</td></tr>';
      });
      h += '</tbody></table>';

    // ── POR CLASE ──────────────────────────────────────────────────────
    } else if (type==='classes') {
      h = '<div style="margin-bottom:12px;font-size:13px;color:var(--muted)">&#x1F4CD; '+escH(d.realm||'Servidor')+'</div>';
      h += '<table class="rank-table"><thead><tr>'
        +'<th>Clase</th>'
        +'<th style="color:#60a5fa">&#x1F6E1; Alianza</th>'
        +'<th style="color:#f87171">&#x1F480; Horda</th>'
        +'<th>Total</th><th>Distribucion</th>'
        +'</tr></thead><tbody>';
      var totalA=0, totalH=0, totalAll=0;
      (d.classes||[]).forEach(function(r){
        var ico=CLASS_ICONS[r.id||0], clsN=CLASS_NAMES[r.id||0]||'?', clsC=CLASS_COLORS[r.id||0]||'#fff';
        totalA+=r.alliance; totalH+=r.horde; totalAll+=r.total;
        var pctA=r.total?Math.round(r.alliance/r.total*100):0;
        var pctH=r.total?100-pctA:0;
        var bar='<div style="display:flex;height:6px;border-radius:3px;overflow:hidden;min-width:80px">'
          +'<div style="width:'+pctA+'%;background:#3b82f6"></div>'
          +'<div style="width:'+pctH+'%;background:#ef4444"></div>'
          +'</div>';
        h += '<tr>'
          +'<td><span style="color:'+clsC+'">'+ico+' '+escH(clsN)+'</span></td>'
          +'<td style="color:#93c5fd">'+r.alliance+'<span style="color:var(--muted);font-size:10px"> ('+pctA+'%)</span></td>'
          +'<td style="color:#fca5a5">'+r.horde+'<span style="color:var(--muted);font-size:10px"> ('+pctH+'%)</span></td>'
          +'<td class="rank-val">'+r.total+'</td>'
          +'<td>'+bar+'</td></tr>';
      });
      h += '<tr style="font-weight:700;border-top:2px solid var(--bdr)">'
        +'<td>Total</td><td style="color:#93c5fd">'+totalA+'</td><td style="color:#fca5a5">'+totalH+'</td>'
        +'<td class="rank-val">'+totalAll+'</td><td></td></tr>';
      h += '</tbody></table>';

    // ── POR RAZA ───────────────────────────────────────────────────────
    } else if (type==='races') {
      h = '<div style="margin-bottom:12px;font-size:13px;color:var(--muted)">&#x1F4CD; '+escH(d.realm||'Servidor')+'</div>';
      h += '<table class="rank-table"><thead><tr>'
        +'<th>Raza</th>'
        +'<th style="color:#60a5fa">&#x1F6E1; Alianza</th>'
        +'<th style="color:#f87171">&#x1F480; Horda</th>'
        +'<th>Total</th><th>Distribucion</th>'
        +'</tr></thead><tbody>';
      var totalA=0, totalH=0, totalAll=0;
      (d.races||[]).forEach(function(r){
        var raceN=RACE_NAMES[r.id]||'Desconocida';
        var faction=RACE_FACTION[r.id]||0;
        var raceColor=faction===1?'#60a5fa':faction===2?'#f87171':'#9ca3af';
        totalA+=r.alliance; totalH+=r.horde; totalAll+=r.total;
        var pctA=r.total?Math.round(r.alliance/r.total*100):0;
        var pctH=r.total?100-pctA:0;
        var bar='<div style="display:flex;height:6px;border-radius:3px;overflow:hidden;min-width:80px">'
          +'<div style="width:'+pctA+'%;background:#3b82f6"></div>'
          +'<div style="width:'+pctH+'%;background:#ef4444"></div>'
          +'</div>';
        h += '<tr>'
          +'<td><span style="color:'+raceColor+'">'+escH(raceN)+'</span></td>'
          +'<td style="color:#93c5fd">'+r.alliance+'<span style="color:var(--muted);font-size:10px"> ('+pctA+'%)</span></td>'
          +'<td style="color:#fca5a5">'+r.horde+'<span style="color:var(--muted);font-size:10px"> ('+pctH+'%)</span></td>'
          +'<td class="rank-val">'+r.total+'</td>'
          +'<td>'+bar+'</td></tr>';
      });
      h += '<tr style="font-weight:700;border-top:2px solid var(--bdr)">'
        +'<td>Total</td><td style="color:#93c5fd">'+totalA+'</td><td style="color:#fca5a5">'+totalH+'</td>'
        +'<td class="rank-val">'+totalAll+'</td><td></td></tr>';
      h += '</tbody></table>';

    // ── LOGROS ─────────────────────────────────────────────────────────
    } else if (type==='achievements') {
      // Top 10 achievement points
      h = '<div class="sec-hdr" style="margin-bottom:16px"><h2>&#x1F3C6; Top <span>Logros</span></h2></div>';
      if (d.top && d.top.length) {
        h += '<table class="rank-table"><thead><tr>'
          +'<th>#</th><th>Personaje</th><th>Clase</th><th>Raza</th><th>Puntos</th>'
          +'</tr></thead><tbody>';
        d.top.forEach(function(r,i){
          var pos = i<3?'<span class="rank-pos top3">'+MEDALS[i]+'</span>':'<span class="rank-pos">'+(i+1)+'</span>';
          var ico=CLASS_ICONS[r.class||0], clsN=CLASS_NAMES[r.class||0]||'?', clsC=CLASS_COLORS[r.class||0]||'#fff';
          h += '<tr><td>'+pos+'</td><td class="rank-name">'+escH(r.name)+'</td>'
            +'<td><span style="color:'+clsC+'">'+ico+' '+escH(clsN)+'</span></td>'
            +'<td>'+escH(RACE_NAMES[r.race||0]||'?')+'</td>'
            +'<td class="rank-val">'+r.pts+' pts</td></tr>';
        });
        h += '</tbody></table>';
      } else { h += '<div class="empty">Sin datos de logros</div>'; }

      // Absolute first to 80 on the server
      if (d.absoluteFirst) {
        var af=d.absoluteFirst;
        var afDt=af.date?new Date(af.date*1000).toLocaleDateString('es-ES',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}):'--';
        var afClsC=CLASS_COLORS[af.class||0]||'#fff', afIco=CLASS_ICONS[af.class||0]||'', afClsN=CLASS_NAMES[af.class||0]||'?';
        var afFct=RACE_FACTION[af.race]===1?'🔵':'🔴';
        h += '<div style="margin-top:28px;margin-bottom:24px;border:2px solid var(--gold);border-radius:12px;padding:20px 24px;background:rgba(201,162,61,.08);display:flex;align-items:center;gap:18px">'
          +'<div style="font-size:36px;line-height:1">&#x1F451;</div>'
          +'<div>'
          +'<div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--gold);font-weight:700;margin-bottom:4px">Primer personaje nivel 80 del servidor</div>'
          +'<div style="font-size:20px;font-weight:800;color:#fff;margin-bottom:4px">'+escH(af.name)+'</div>'
          +'<div style="font-size:13px;color:var(--muted)"><span style="color:'+afClsC+'">'+afIco+' '+escH(afClsN)+'</span>'
          +' &nbsp;'+afFct+' '+escH(RACE_NAMES[af.race||0]||'?')
          +'&nbsp;&nbsp;&#x1F4C5; '+afDt+'</div>'
          +'</div></div>';
      }

      // First to 80 per class+race
      if (d.first80 && d.first80.length) {
        h += '<div class="sec-hdr" style="margin-top:32px;margin-bottom:16px"><h2>&#x1F31F; Primeros en <span>Nivel 80</span></h2></div>';
        // Group by class
        var byClass = {}, order = [];
        d.first80.forEach(function(r){
          if (!byClass[r.class]) { byClass[r.class]=[]; order.push(r.class); }
          byClass[r.class].push(r);
        });
        h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px">';
        order.forEach(function(cls){
          var clsC=CLASS_COLORS[cls]||'#fff', ico=CLASS_ICONS[cls]||'?', clsN=CLASS_NAMES[cls]||'?';
          h += '<div class="dl-card" style="padding:16px">'
            +'<div style="font-size:15px;font-weight:700;color:'+clsC+';margin-bottom:10px">'+ico+' '+escH(clsN)+'</div>'
            +'<table style="width:100%;font-size:12px;border-collapse:collapse">'
            +'<tr style="color:var(--muted)"><th style="text-align:left;padding-bottom:4px">Personaje</th><th style="text-align:left">Raza</th><th style="text-align:right">Fecha</th></tr>';
          byClass[cls].forEach(function(r){
            var dt = r.date ? new Date(r.date*1000).toLocaleDateString('es-ES',{day:'2-digit',month:'2-digit',year:'numeric'}) : '--';
            var fct = RACE_FACTION[r.race]===1 ? '🔵' : '🔴';
            h += '<tr><td style="padding:3px 0;font-weight:600">'+escH(r.name)+'</td>'
              +'<td>'+fct+' '+escH(RACE_NAMES[r.race||0]||'?')+'</td>'
              +'<td style="text-align:right;color:var(--muted)">'+dt+'</td></tr>';
          });
          h += '</table></div>';
        });
        h += '</div>';
      } else { h += '<div class="empty" style="margin-top:16px">No hay personajes en nivel 80 aun</div>'; }
    }

    c.innerHTML = h || '<div class="empty">Sin datos disponibles</div>';
  }).catch(function(){ c.innerHTML='<div class="empty">Error al cargar rankings</div>'; });
}

// ── ACCOUNT ─────────────────────────────────────────────
function loadAccount() {
  var c = document.getElementById('acc-content');
  if (!TOKEN) { c.innerHTML='<div class="empty" style="padding:60px 0">&#x1F510; <a onclick="openLogin()" style="color:var(--gold);cursor:pointer">Inicia sesion</a> para ver tu cuenta</div>'; return; }
  c.innerHTML = '<div class="empty">Cargando...</div>';
  pFetch('/api/portal/account').then(function(d){
    if (!d.ok) { c.innerHTML='<div class="empty">Error al cargar cuenta</div>'; return; }

    // ── Helper: info row ─────────────────────────────
    function infoRow(label, value, extra) {
      return '<tr>'
        +'<td style="padding:10px 0;color:var(--muted);font-size:13px;width:220px;vertical-align:top">'+label+'</td>'
        +'<td style="padding:10px 0;font-size:13px;font-weight:600">'+(extra||'')+escH(String(value))+'</td>'
        +'</tr>';
    }
    function badge(ok, trueLabel, falseLabel) {
      return ok
        ? '<span style="background:rgba(34,197,94,.15);color:#22c55e;font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700">'+trueLabel+'</span>'
        : '<span style="background:rgba(107,112,153,.12);color:var(--muted);font-size:11px;padding:2px 8px;border-radius:10px">'+falseLabel+'</span>';
    }

    // Format joindate: "HH:MM:SS DD-MM-YYYY"
    function fmtJoin(s) {
      if (!s) return '--';
      var m = s.match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
      if (!m) return s;
      return m[4]+':'+m[5]+':'+m[6]+' '+m[3]+'-'+m[2]+'-'+m[1];
    }

    var h = '';

    // ── OPCIONES DE CUENTA ────────────────────────────────
    h += '<div class="sec-hdr" style="margin-bottom:16px"><h2>&#x2699; Opciones de <span>Cuenta</span></h2></div>';
    h += '<div class="opt-grid">'
      +'<div class="opt-card" onclick="document.getElementById(\'modal-chpass\').classList.add(\'open\')">'
      +'<div class="opt-ico">&#x1F504;</div><div class="opt-title">Cambiar Contrasena</div>'
      +'<div class="opt-desc">Actualiza tu contrasena de acceso</div></div>'

      +'<div class="opt-card" onclick="open2FA('+d.has2FA+')">'
      +'<div class="opt-ico">&#x1F4F1;</div><div class="opt-title">2FA Verificacion</div>'
      +'<div class="opt-desc">'+(d.has2FA?'<span style=\"color:var(--green)\">Activado</span>':'<span style=\"color:var(--muted)\">Desactivado</span>')+'</div></div>'

      +'<div class="opt-card" onclick="openTransfer(10)">'
      +'<div class="opt-ico">&#x1F4E4;</div><div class="opt-title">Transferir PD</div>'
      +'<div class="opt-desc">Envia PD a otra cuenta (10% comision)</div></div>'

      +'<div class="opt-card" onclick="openTrade()">'
      +'<div class="opt-ico">&#x2696;</div><div class="opt-title">Comercio PD/Oro</div>'
      +'<div class="opt-desc">Intercambia PD por oro del juego</div></div>'

      +'<div class="opt-card" onclick="openPromo()">'
      +'<div class="opt-ico">&#x1F381;</div><div class="opt-title">Codigo Promo</div>'
      +'<div class="opt-desc">Canjea un codigo por PD o PV</div></div>'

      +'<div class="opt-card" onclick="openVote()">'
      +'<div class="opt-ico">&#x1F5F3;</div><div class="opt-title">Votar</div>'
      +'<div class="opt-desc">Vota y gana PV gratis</div></div>'

      +'<div class="opt-card" onclick="openStripe()">'
      +'<div class="opt-ico">&#x1F4B3;</div><div class="opt-title">Comprar PD</div>'
      +'<div class="opt-desc">Adquiere PD con tarjeta via Stripe</div></div>'
      +'</div>';

    // ── DATOS BÁSICOS ────────────────────────────────
    h += '<div class="sec-hdr" style="margin-bottom:20px"><h2>&#x1F464; Datos <span>Basicos</span></h2></div>';
    h += '<div class="dl-card" style="margin-bottom:24px;padding:4px 24px">'
      +'<table style="width:100%;border-collapse:collapse">';
    h += infoRow('Nombre de la cuenta:', d.accName||'--');
    h += infoRow('Correo de registro:', d.regMail||'--');
    h += infoRow('Correo actual:', d.curMail||'--');
    h += infoRow('Fecha de registro:', fmtJoin(d.joindate));
    h += infoRow('Ultima IP (web):', d.lastWebIp||'--');
    h += infoRow('Ultima IP (Servidor):', d.lastSrvIp||'--');
    h += '</table></div>';

    // ── ESTADO DE CUENTA ─────────────────────────────
    h += '<div class="sec-hdr" style="margin-top:8px;margin-bottom:20px"><h2>&#x1F6E1; Estado de <span>Cuenta</span></h2></div>';
    h += '<div class="dl-card" style="margin-bottom:24px;padding:4px 24px">'
      +'<table style="width:100%;border-collapse:collapse">';
    // PD | PV
    h += infoRow('PD / PV:',
      '',
      '<span style="color:var(--gold);font-weight:800">PD: '+escH(String(d.donatePts||0))+'</span>'
      +' <span style="color:var(--muted);margin:0 6px">|</span>'
      +'<span style="color:#60a5fa;font-weight:800">PV: '+escH(String(d.votePts||0))+'</span> ');
    // 2FA
    h += infoRow('2FA (Verificacion en 2 pasos):', '',
      badge(d.has2FA, 'Activado', 'Desactivado')+' ');
    // Cuenta baneada
    var banCell = d.isBanned
      ? '<span style="background:rgba(239,68,68,.15);color:#ef4444;font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700">Si</span>'
      : '<span style="background:rgba(107,112,153,.12);color:var(--muted);font-size:11px;padding:2px 8px;border-radius:10px">No</span>';
    h += infoRow('Cuenta baneada:', '', banCell+' ');
    // Cuenta reclutada
    h += infoRow('Cuenta reclutada:', '', badge(d.isRecruited, 'Si', 'No')+' ');
    // Amigos reclutados
    h += infoRow('Amigos reclutados:', d.friendsRecruited||0);
    h += '</table></div>';

    // ── OPCIONES DE PERSONAJES ───────────────────────────────────
    _acctChars = d.chars || [];
    h += '<div class="sec-hdr" style="margin-top:8px;margin-bottom:20px"><h2>&#x1F9D9; Opciones de <span>Personajes</span></h2></div>';
    if (!d.chars||!d.chars.length) {
      h += '<div class="empty">No tienes personajes. Inicia el juego para crear uno.</div>';
    } else {
      h += '<div class="char-grid">';
      d.chars.forEach(function(ch){
        var ico = CLASS_ICONS[ch.class||0]||'?';
        var clsN= CLASS_NAMES[ch.class||0]||'?';
        var safeN = ch.name.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
        h += '<div class="char-card">'
          +'<div class="online-badge'+(ch.online?' on':'')+'"></div>'
          +'<div class="class-ico">'+ico+'</div>'
          +'<div class="char-name">'+escH(ch.name)+'</div>'
          +'<div class="char-sub">Nv '+ch.level+' '+escH(clsN)+'</div>'
          +'<div class="char-sub" style="margin-top:4px">'+(ch.online?'<span style="color:var(--green)">&#x25CF; En linea</span>':'Desconectado')+'</div>'
          +'<button class="btn btn-gold btn-sm" style="margin-top:10px;width:100%;font-size:12px" '
          +'onclick="openCharMgmt('+ch.guid+',\''+safeN+'\','+ch.level+','+ch.class+','+ch.online+')">&#x2699; Gestionar</button>'
          +'</div>';
      });
      h += '</div>';
    }
    h += '<div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">'
      +'<button class="btn btn-ghost btn-sm" onclick="openDeletedCharsView()">&#x267B; Recuperar personaje borrado</button>'
      +'<button class="btn btn-ghost btn-sm" onclick="openShopView()">&#x1F6CD; Tienda</button>'
      +'</div>';

    // ── HISTORIALES ──────────────────────────────────────
    h += '<div class="sec-hdr" style="margin-top:24px;margin-bottom:14px"><h2>&#x1F4DC; <span>Historiales</span></h2></div>';
    h += '<div style="display:flex;gap:10px;flex-wrap:wrap">'
      +'<button class="btn btn-ghost btn-sm" onclick="openHistoryModal(\'pdpv\')">&#x1F4B0; PD / PV</button>'
      +'<button class="btn btn-ghost btn-sm" onclick="openHistoryModal(\'transaction\')">&#x1F4CB; Transacciones</button>'
      +'<button class="btn btn-ghost btn-sm" onclick="openHistoryModal(\'security\')">&#x1F6E1; Seguridad</button>'
      +'</div>';

    c.innerHTML = h;
  }).catch(function(){ c.innerHTML='<div class="empty">Error de conexion</div>'; });
}

// ── DOWNLOADS ────────────────────────────────────────────
function downloadRealmlist() {
  var content = 'set realmlist '+location.hostname;
  var a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
  a.download = 'realmlist.wtf';
  a.click();
}

// ── UTILS ────────────────────────────────────────────────
function escH(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── OPCIONES DE CUENTA ───────────────────────────────────

// 2FA
var _2faMode = 'setup'; // 'setup' or 'disable'
function open2FA(has2FA) {
  _2faMode = has2FA ? 'disable' : 'setup';
  document.getElementById('fa-loading').style.display='block';
  document.getElementById('fa-setup').style.display='none';
  document.getElementById('fa-disable').style.display='none';
  document.getElementById('modal-2fa').classList.add('open');
  if (!has2FA) {
    pFetch('/api/portal/account/2fa/setup').then(function(d){
      document.getElementById('fa-loading').style.display='none';
      if (!d.ok) { document.getElementById('fa-loading').textContent='Error al generar QR'; return; }
      document.getElementById('fa-secret-txt').textContent = (d.secret||'').replace(/(.{4})/g,'$1 ').trim();
      document.getElementById('fa-qr').src = 'https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=' + encodeURIComponent(d.otpUri||'');
      document.getElementById('fa-setup').style.display='block';
    });
  } else {
    document.getElementById('fa-loading').style.display='none';
    document.getElementById('fa-disable').style.display='block';
  }
}
function do2FAEnable() {
  var code = document.getElementById('fa-code').value.trim();
  var err = document.getElementById('fa-err');
  err.style.display='none';
  if (code.length!==6) { err.textContent='Ingresa el codigo de 6 digitos'; err.style.display='block'; return; }
  pFetch('/api/portal/account/2fa/enable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code})})
    .then(function(d){
      if (d.ok) { closeModal('2fa'); toast('2FA activado correctamente','success'); loadAccount(); }
      else { err.textContent=d.error||'Error'; err.style.display='block'; }
    });
}
function do2FADisable() {
  var code = document.getElementById('fa-dis-code').value.trim();
  var err = document.getElementById('fa-dis-err');
  err.style.display='none';
  if (code.length!==6) { err.textContent='Ingresa el codigo de 6 digitos'; err.style.display='block'; return; }
  pFetch('/api/portal/account/2fa/disable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code})})
    .then(function(d){
      if (d.ok) { closeModal('2fa'); toast('2FA desactivado','info'); loadAccount(); }
      else { err.textContent=d.error||'Error'; err.style.display='block'; }
    });
}

// Transferir PD
var _trFeePercent = 10;
function openTransfer(fee) {
  _trFeePercent = fee||10;
  document.getElementById('tr-email').value='';
  document.getElementById('tr-amount').value='';
  document.getElementById('tr-err').style.display='none';
  document.getElementById('tr-fee-info').textContent='Comision: '+fee+'% sobre el total transferido';
  document.getElementById('modal-transfer').classList.add('open');
}
function doTransfer() {
  var email = document.getElementById('tr-email').value.trim();
  var amount = parseInt(document.getElementById('tr-amount').value)||0;
  var err = document.getElementById('tr-err');
  err.style.display='none';
  if (!email || amount<1) { err.textContent='Completa todos los campos'; err.style.display='block'; return; }
  pFetch('/api/portal/transfer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to_email:email,amount:String(amount)})})
    .then(function(d){
      if (d.ok) { closeModal('transfer'); toast('Transferidos '+amount+' PD (comision: '+d.fee+' PD)','success'); loadAccount(); }
      else { err.textContent=d.error||'Error'; err.style.display='block'; }
    });
}

// Comercio PD/Oro
var _tradeInfo = null, _tradeMode = 'buy';
function openTrade() {
  document.getElementById('modal-trade').classList.add('open');
  document.getElementById('trade-err').style.display='none';
  pFetch('/api/portal/trade/info').then(function(d){
    if (!d.ok) return;
    _tradeInfo = d;
    document.getElementById('trade-rates-txt').textContent =
      'Comprar PD: '+d.buyRate+' oro/PD | Vender PD: '+d.sellRate+' oro/PD';
    var sel = document.getElementById('trade-char');
    sel.innerHTML='';
    (d.chars||[]).forEach(function(c){
      var opt=document.createElement('option');
      opt.value=c.guid;
      opt.textContent=c.name+' (Nv '+c.level+') — '+Math.floor(c.money/10000)+' oro';
      sel.appendChild(opt);
    });
    tradeCalc();
  });
  document.getElementById('trade-pd').oninput = tradeCalc;
}
function tradeTab(mode) {
  _tradeMode = mode;
  document.getElementById('trade-tab-buy').classList.toggle('active', mode==='buy');
  document.getElementById('trade-tab-sell').classList.toggle('active', mode==='sell');
  document.getElementById('trade-pd-lbl').textContent = mode==='buy' ? 'PD a comprar' : 'PD a vender';
  document.getElementById('trade-btn').textContent = mode==='buy' ? 'Comprar PD con Oro' : 'Vender PD por Oro';
  tradeCalc();
}
function tradeCalc() {
  if (!_tradeInfo) return;
  var pd = parseInt(document.getElementById('trade-pd').value)||0;
  var rate = _tradeMode==='buy' ? (_tradeInfo.buyRate||50) : (_tradeInfo.sellRate||40);
  var gold = pd * rate;
  document.getElementById('trade-calc').textContent = pd>0 ? (
    _tradeMode==='buy' ? 'Coste: '+gold+' oro → ganas '+pd+' PD'
                       : 'Vendes '+pd+' PD → recibes '+gold+' oro'
  ) : '';
}
function doTrade() {
  var charGuid = document.getElementById('trade-char').value;
  var pdAmount = parseInt(document.getElementById('trade-pd').value)||0;
  var err = document.getElementById('trade-err');
  err.style.display='none';
  if (!charGuid || pdAmount<1) { err.textContent='Selecciona personaje e introduce una cantidad'; err.style.display='block'; return; }
  var url = _tradeMode==='buy' ? '/api/portal/trade/buy' : '/api/portal/trade/sell';
  pFetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({char_guid:charGuid,pd_amount:String(pdAmount)})})
    .then(function(d){
      if (d.ok) {
        closeModal('trade');
        if (_tradeMode==='buy') toast('Compraste '+d.pdGained+' PD por '+d.goldCost+' oro','success');
        else toast('Vendiste '+d.pdSold+' PD, recibiste '+d.goldGain+' oro','success');
        loadAccount();
      } else { err.textContent=d.error||'Error'; err.style.display='block'; }
    });
}

// Codigo Promocional
function openPromo() {
  document.getElementById('promo-code').value='';
  document.getElementById('promo-msg').style.display='none';
  document.getElementById('modal-promo').classList.add('open');
}
function doPromo() {
  var code = document.getElementById('promo-code').value.trim().toUpperCase();
  var msg = document.getElementById('promo-msg');
  msg.style.display='none';
  if (!code) return;
  pFetch('/api/portal/promo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code})})
    .then(function(d){
      msg.style.display='block';
      if (d.ok) {
        var txt = 'Codigo canjeado!';
        if (d.pd>0) txt += ' +'+d.pd+' PD';
        if (d.pv>0) txt += ' +'+d.pv+' PV';
        msg.style.color='var(--green)'; msg.textContent=txt;
        loadAccount();
      } else { msg.style.color='var(--red)'; msg.textContent=d.error||'Error'; }
    });
}

// Votar
function openVote() {
  document.getElementById('vote-sites').innerHTML='<div style="text-align:center;color:var(--muted);padding:30px">Cargando...</div>';
  document.getElementById('modal-vote').classList.add('open');
  pFetch('/api/portal/vote').then(function(d){
    if (!d.ok || !d.sites) return;
    var h='';
    d.sites.forEach(function(s){
      h += '<div class="dl-card" style="margin-bottom:12px;padding:14px 18px;display:flex;align-items:center;gap:16px">'
        +'<div style="flex:1"><div style="font-weight:700;font-size:14px">'+escH(s.name)+'</div>'
        +'<div style="font-size:12px;color:var(--muted)">Recompensa: <span style="color:#60a5fa;font-weight:700">+'+s.pv+' PV</span></div></div>'
        +(s.canVote
          ? '<a href="'+escH(s.url)+'" target="_blank" class="btn btn-outline btn-sm" onclick="setTimeout(function(){claimVote(\''+escH(s.key)+'\')},3000)">Votar</a>'
          : '<span style="font-size:11px;color:var(--muted);background:var(--bg);padding:4px 10px;border-radius:8px">Ya votaste</span>')
        +'</div>';
    });
    document.getElementById('vote-sites').innerHTML = h||'<div style="color:var(--muted);padding:20px">Sin sitios disponibles</div>';
  });
}
function claimVote(siteKey) {
  pFetch('/api/portal/vote/claim',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_key:siteKey})})
    .then(function(d){
      if (d.ok) { toast('+'+d.pv+' PV reclamados!','success'); loadAccount(); openVote(); }
      else toast(d.error||'Error al reclamar voto','error');
    });
}

// Stripe / Comprar PD
function openStripe() {
  document.getElementById('stripe-pkgs').innerHTML='<div style="text-align:center;color:var(--muted);padding:30px">Cargando...</div>';
  document.getElementById('stripe-err').style.display='none';
  document.getElementById('modal-stripe').classList.add('open');
  fetch('/api/portal/stripe/packages').then(function(r){return r.json();}).then(function(pkgs){
    if (!pkgs||!pkgs.length) return;
    var h='<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">';
    pkgs.forEach(function(p){
      var price = (p.cents/100).toFixed(2);
      h += '<div class="dl-card" style="padding:20px 12px;text-align:center;cursor:pointer;border:1px solid var(--bdr)" onclick="buyStripe(\''+p.id+'\')">'
        +'<div style="font-size:24px;font-weight:900;color:var(--gold)">'+p.pd+'</div>'
        +'<div style="font-size:11px;color:var(--muted);margin-bottom:8px">PD</div>'
        +'<div style="font-size:16px;font-weight:700">$'+price+'</div>'
        +'</div>';
    });
    h += '</div><p style="font-size:11px;color:var(--muted);margin-top:16px;text-align:center">Pagos procesados de forma segura via Stripe</p>';
    document.getElementById('stripe-pkgs').innerHTML = h;
  }).catch(function(){ document.getElementById('stripe-pkgs').innerHTML='<div style="color:var(--red)">Error al cargar paquetes</div>'; });
}
function buyStripe(pkg) {
  var err = document.getElementById('stripe-err');
  err.style.display='none';
  pFetch('/api/portal/stripe/checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:pkg})})
    .then(function(d){
      if (d.ok && d.url) { window.location.href = d.url; }
      else if (d.ok && d.stub) { err.style.color='var(--muted)'; err.textContent='Stripe en configuracion: '+d.message; err.style.display='block'; }
      else { err.style.color='var(--red)'; err.textContent=d.error||'Error'; err.style.display='block'; }
    });
}

// ── OPCIONES DE PERSONAJES ──────────────────────────────
var _acctChars = [];
var _cmgmtGuid = 0, _cmgmtName = '', _cmgmtLevel = 0, _cmgmtClass = 0, _cmgmtOnline = false;
var _cmgmtAction = '';
var CHAR_SVC_COSTS = {
  char_unstuck_cost:0, char_revive_cost:0, char_rename_cost:100,
  char_customize_cost:150, char_race_change_cost:500, char_faction_change_cost:800,
  char_boost70_cost:2000, char_restore_deleted_cost:200, char_transfer_cost:500,
  char_gold_rate:10
};

function cmgmtShowView(v) {
  ['main','quest','form','deleted','shop'].forEach(function(id){
    document.getElementById('cmgmt-view-'+id).style.display=(id===v)?'':'none';
  });
}
function openCharMgmt(guid, name, level, cls, online) {
  _cmgmtGuid=guid; _cmgmtName=name; _cmgmtLevel=level; _cmgmtClass=cls; _cmgmtOnline=online;
  var ico=CLASS_ICONS[cls||0]||'?';
  var stHtml=online
    ?'<span style="color:var(--green);font-size:11px">&#x25CF; En linea</span>'
    :'<span style="color:var(--muted);font-size:11px">&#x25CF; Desconectado</span>';
  document.getElementById('cmgmt-char-hdr').innerHTML=
    '<div style="display:flex;align-items:center;gap:12px;padding-bottom:14px;border-bottom:1px solid var(--bdr)">'
    +'<div style="font-size:32px">'+ico+'</div>'
    +'<div><div style="font-size:16px;font-weight:800">'+escH(name)+'</div>'
    +'<div style="font-size:12px;color:var(--muted);margin-top:2px">Nivel '+level+' &bull; '+stHtml+'</div>'
    +'</div></div>';
  document.getElementById('modal-char-mgmt').classList.add('open');
  cmgmtShowView('main');
  buildCharServices();
}
function openDeletedCharsView() {
  _cmgmtGuid=0; _cmgmtName='';
  document.getElementById('cmgmt-char-hdr').innerHTML=
    '<div style="font-size:16px;font-weight:800;padding-bottom:14px;border-bottom:1px solid var(--bdr)">&#x267B; Recuperar personaje borrado</div>';
  document.getElementById('modal-char-mgmt').classList.add('open');
  cmgmtShowView('deleted');
  loadDeletedChars();
}
function openShopView() {
  _cmgmtGuid=0; _cmgmtName='';
  document.getElementById('cmgmt-char-hdr').innerHTML=
    '<div style="font-size:16px;font-weight:800;padding-bottom:14px;border-bottom:1px solid var(--bdr)">&#x1F6CD; Tienda de Objetos</div>';
  document.getElementById('modal-char-mgmt').classList.add('open');
  cmgmtShowView('shop');
  loadShopItems();
}
function cmgmtBack() {
  if (_cmgmtGuid) { cmgmtShowView('main'); } else { closeModal('char-mgmt'); }
}

function buildCharServices() {
  var cards=[
    {ico:'&#x1F512;',name:'Desbloquear',desc:'Ciudad segura',action:'unstuck',ck:'char_unstuck_cost',off:true},
    {ico:'&#x1F35E;',name:'Revivir',desc:'Resucita al login',action:'revive',ck:'char_revive_cost',off:false},
    {ico:'&#x270F;', name:'Renombrar',desc:'Nuevo nombre',action:'rename',ck:'char_rename_cost',off:false},
    {ico:'&#x1F48E;',name:'Personalizar',desc:'Cambio look',action:'customize',ck:'char_customize_cost',off:false},
    {ico:'&#x1F9EC;',name:'Cambiar Raza',desc:'Nueva raza',action:'race_change',ck:'char_race_change_cost',off:false},
    {ico:'&#x2694;', name:'Cambiar Facción',desc:'Alianza/Horda',action:'faction_change',ck:'char_faction_change_cost',off:false},
    {ico:'&#x2B06;', name:'Nivel 70',desc:'Boost al 70',action:'boost70',ck:'char_boost70_cost',off:true},
    {ico:'&#x1F947;',name:'Adquirir Oro',desc:'PD por oro',action:'gold',ck:null,off:true},
    {ico:'&#x1F4CB;',name:'Mis Misiones',desc:'Ver misiones',action:'quests',ck:null,off:false},
    {ico:'&#x1F4E4;',name:'Transferir',desc:'A otra cuenta',action:'transfer',ck:'char_transfer_cost',off:true},
    {ico:'&#x1F4E6;',name:'Rec. Items',desc:'Solicitar recuperacion',action:'recovery',ck:null,off:false},
    {ico:'&#x1F381;',name:'Enviar Regalo',desc:'Oro a otro jugador',action:'gift',ck:null,off:false}
  ];
  var h='<div class="char-svc-grid">';
  cards.forEach(function(c){
    var cost=c.ck?CHAR_SVC_COSTS[c.ck]:0;
    var costLbl=c.ck?(cost>0?cost+' PD':'Gratis'):(c.action==='gold'||c.action==='gift'?'PD/Oro':'Gratis');
    var noteHtml=(c.off&&_cmgmtOnline)?'<div class="svc-note">Requiere offline</div>':'';
    h+='<div class="char-svc-card" onclick="cmgmtOpenService(\''+c.action+'\')"><div class="svc-ico">'+c.ico+'</div>'
      +'<div class="svc-name">'+c.name+'</div>'
      +'<div class="svc-cost">'+escH(costLbl)+'</div>'+noteHtml+'</div>';
  });
  h+='</div>';
  document.getElementById('cmgmt-view-main').innerHTML=h;
}

function cmgmtOpenService(action) {
  _cmgmtAction=action;
  var err=document.getElementById('cmgmt-form-err');
  if(err) err.style.display='none';

  if(action==='quests'){
    cmgmtShowView('quest');
    document.getElementById('cmgmt-quest-list').innerHTML='<div style="padding:20px;text-align:center;color:var(--muted)">Cargando...</div>';
    pFetch('/api/portal/char/quests?guid='+_cmgmtGuid).then(function(d){
      if(!d.ok){document.getElementById('cmgmt-quest-list').innerHTML='<div style="padding:12px;color:var(--red)">'+escH(d.error||'Error')+'</div>';return;}
      if(!d.quests||!d.quests.length){document.getElementById('cmgmt-quest-list').innerHTML='<div style="padding:16px;text-align:center;color:var(--muted)">Sin misiones activas</div>';return;}
      var qh='';
      d.quests.forEach(function(q){
        var scls=q.status===2?'color:var(--green)':q.status===3?'color:var(--red)':'color:var(--muted)';
        qh+='<div class="quest-item"><span>'+escH(q.title)+'</span><span style="'+scls+';white-space:nowrap;margin-left:8px">'+escH(q.sl)+' (Nv'+q.level+')</span></div>';
      });
      document.getElementById('cmgmt-quest-list').innerHTML=qh;
    });
    return;
  }
  if(action==='recovery'){
    document.getElementById('cmgmt-form-title').textContent='📦 Recuperar Items';
    document.getElementById('cmgmt-form-body').innerHTML=
      '<div style="font-size:12px;color:var(--muted);margin-bottom:12px">Describe los items que perdiste. Un GM los revisara y entregara si es posible.</div>'
      +'<div class="form-row"><label>Descripcion</label><textarea id="cmgmt-recov-desc" placeholder="Nombre del item, fecha aproximada, contexto..."></textarea></div>';
    document.getElementById('cmgmt-confirm-btn').textContent='Enviar Solicitud';
    cmgmtShowView('form'); return;
  }
  if(action==='gift'){
    document.getElementById('cmgmt-form-title').textContent='🎁 Enviar Regalo de Oro';
    document.getElementById('cmgmt-form-body').innerHTML=
      '<div class="form-row"><label>Nombre del personaje destino</label><input type="text" id="cmgmt-gift-char" placeholder="Nombre exacto del personaje"></div>'
      +'<div class="form-row"><label>Cantidad de oro</label><input type="number" id="cmgmt-gift-gold" min="1" max="100000" placeholder="1-100000"></div>'
      +'<div style="font-size:11px;color:var(--muted)">El personaje destino debe estar desconectado. Costo: 1 PD por '+CHAR_SVC_COSTS.char_gold_rate+' oro.</div>';
    document.getElementById('cmgmt-confirm-btn').textContent='Enviar Regalo';
    cmgmtShowView('form'); return;
  }
  if(action==='transfer'){
    var cost=CHAR_SVC_COSTS.char_transfer_cost||500;
    document.getElementById('cmgmt-form-title').textContent='📤 Transferir Personaje';
    document.getElementById('cmgmt-form-body').innerHTML=
      '<div style="font-size:12px;color:var(--muted);margin-bottom:12px">Transfiere "'+escH(_cmgmtName)+'" a otra cuenta. El personaje debe estar desconectado.</div>'
      +'<div class="form-row"><label>Email de la cuenta destino</label><input type="email" id="cmgmt-tr-email" placeholder="destino@email.com"></div>'
      +'<div style="font-size:12px;color:var(--gold);margin-top:8px">Costo: '+cost+' PD</div>';
    document.getElementById('cmgmt-confirm-btn').textContent='Transferir';
    cmgmtShowView('form'); return;
  }
  if(action==='gold'){
    var rate=CHAR_SVC_COSTS.char_gold_rate||10;
    document.getElementById('cmgmt-form-title').textContent='🥇 Adquirir Oro';
    document.getElementById('cmgmt-form-body').innerHTML=
      '<div style="font-size:12px;color:var(--muted);margin-bottom:12px">El personaje debe estar desconectado. Tasa: '+rate+' oro por PD.</div>'
      +'<div class="form-row"><label>Cantidad de oro</label><input type="number" id="cmgmt-gold-amt" min="1" max="100000" placeholder="1-100000"></div>';
    document.getElementById('cmgmt-confirm-btn').textContent='Comprar Oro';
    cmgmtShowView('form'); return;
  }
  // Generic at-login / positional actions
  var titles={unstuck:'Desbloquear Personaje',revive:'Revivir Personaje',rename:'Renombrar Personaje',
    customize:'Personalizar Apariencia',race_change:'Cambiar de Raza',
    faction_change:'Cambiar de Faccion',boost70:'Subir a Nivel 70'};
  var descs={
    unstuck:'Teleporta al personaje a la ciudad principal de su faccion. Debe estar desconectado.',
    revive:'Activa resurreccion al proximo inicio de sesion.',
    rename:'El personaje eligira un nuevo nombre al conectarse.',
    customize:'El personaje podra cambiar apariencia (cara, pelo, genero) al conectarse.',
    race_change:'El personaje cambiara de raza al conectarse (misma faccion).',
    faction_change:'El personaje cambiara de faccion (Alianza/Horda) al conectarse.',
    boost70:'Sube instantaneamente a nivel 70. Solo si el personaje es menor de nivel 70. Debe estar desconectado.'
  };
  var costKeys={unstuck:'char_unstuck_cost',revive:'char_revive_cost',rename:'char_rename_cost',
    customize:'char_customize_cost',race_change:'char_race_change_cost',
    faction_change:'char_faction_change_cost',boost70:'char_boost70_cost'};
  var cost=costKeys[action]!==undefined?CHAR_SVC_COSTS[costKeys[action]]||0:0;
  document.getElementById('cmgmt-form-title').textContent=titles[action]||action;
  document.getElementById('cmgmt-form-body').innerHTML=
    '<div style="font-size:13px;color:var(--muted);margin-bottom:16px">'+escH(descs[action]||'')+'</div>'
    +(cost>0?'<div style="font-size:14px;font-weight:700;color:var(--gold)">Costo: '+cost+' PD</div>'
             :'<div style="font-size:12px;color:var(--green)">Gratis</div>');
  document.getElementById('cmgmt-confirm-btn').textContent='Confirmar';
  cmgmtShowView('form');
}

function cmgmtDoAction() {
  var action=_cmgmtAction;
  var err=document.getElementById('cmgmt-form-err');
  err.style.display='none';

  if(action==='recovery'){
    var desc=(document.getElementById('cmgmt-recov-desc').value||'').trim();
    if(!desc){err.textContent='Escribe una descripcion';err.style.display='block';return;}
    pFetch('/api/portal/char/recovery-request',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({guid:_cmgmtGuid,description:desc})})
      .then(function(d){
        if(d.ok){cmgmtBack();toast('Solicitud enviada. Un GM la revisara.','success');}
        else{err.textContent=d.error||'Error';err.style.display='block';}
      });
    return;
  }
  if(action==='gift'){
    var toChar=(document.getElementById('cmgmt-gift-char').value||'').trim();
    var goldAmt=parseInt(document.getElementById('cmgmt-gift-gold').value)||0;
    if(!toChar||goldAmt<1){err.textContent='Completa todos los campos';err.style.display='block';return;}
    pFetch('/api/portal/char/gift',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({to_char:toChar,gold:goldAmt})})
      .then(function(d){
        if(d.ok){cmgmtBack();toast('Regalo enviado: '+goldAmt+' oro a '+escH(toChar)+'. Costo: '+d.cost+' PD','success');loadAccount();}
        else{err.textContent=d.error||'Error';err.style.display='block';}
      });
    return;
  }
  if(action==='transfer'){
    var email=(document.getElementById('cmgmt-tr-email').value||'').trim();
    if(!email){err.textContent='Ingresa el email de destino';err.style.display='block';return;}
    pFetch('/api/portal/char/transfer',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({guid:_cmgmtGuid,target_email:email})})
      .then(function(d){
        if(d.ok){closeModal('char-mgmt');toast('Personaje transferido. Costo: '+d.cost+' PD','success');loadAccount();}
        else{err.textContent=d.error||'Error';err.style.display='block';}
      });
    return;
  }
  if(action==='gold'){
    var gamt=parseInt(document.getElementById('cmgmt-gold-amt').value)||0;
    if(gamt<1){err.textContent='Ingresa una cantidad valida';err.style.display='block';return;}
    pFetch('/api/portal/char/action',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({guid:_cmgmtGuid,action:'gold',amount:gamt})})
      .then(function(d){
        if(d.ok){cmgmtBack();toast(gamt+' oro entregado. Costo: '+d.cost+' PD','success');loadAccount();}
        else{err.textContent=d.error||'Error';err.style.display='block';}
      });
    return;
  }
  // Generic (at_login flags, unstuck, boost70)
  pFetch('/api/portal/char/action',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({guid:_cmgmtGuid,action:action,amount:0})})
    .then(function(d){
      if(d.ok){
        cmgmtBack();
        var msgs={unstuck:'Personaje movido a ciudad principal.',revive:'Resurrecion activada para el proximo login.',
          rename:'Renombrado activado para el proximo login.',customize:'Personalizacion activada para el proximo login.',
          race_change:'Cambio de raza activado para el proximo login.',
          faction_change:'Cambio de faccion activado para el proximo login.',boost70:'Nivel actualizado a 70.'};
        toast((msgs[action]||'Accion completada.')+(d.cost>0?' (Costo: '+d.cost+' PD)':''),'success');
        if(d.cost>0) loadAccount();
      } else {err.textContent=d.error||'Error';err.style.display='block';}
    });
}

// Deleted character recovery
function loadDeletedChars() {
  var el=document.getElementById('cmgmt-deleted-list');
  if(!el) return;
  el.innerHTML='<div style="padding:20px;text-align:center;color:var(--muted)">Cargando...</div>';
  pFetch('/api/portal/char/deleted').then(function(d){
    if(!d.ok){el.innerHTML='<div style="padding:12px;color:var(--red)">'+escH(d.error||'Error')+'</div>';return;}
    if(!d.chars||!d.chars.length){el.innerHTML='<div style="padding:20px;text-align:center;color:var(--muted)">No hay personajes borrados en tu cuenta</div>';return;}
    var cost=CHAR_SVC_COSTS.char_restore_deleted_cost||200;
    var h='<div style="font-size:11px;color:var(--muted);margin-bottom:10px">Costo de restauracion: '+cost+' PD por personaje</div>';
    d.chars.forEach(function(c){
      var ico=CLASS_ICONS[c.class||0]||'?';
      var safeN=(c.name||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");
      h+='<div style="display:flex;align-items:center;gap:12px;padding:10px;border-bottom:1px solid var(--bdr)">'
        +'<div style="font-size:22px">'+ico+'</div>'
        +'<div style="flex:1"><div style="font-weight:700">'+escH(c.name)+'</div>'
        +'<div style="font-size:11px;color:var(--muted)">Nivel '+c.level+'</div></div>'
        +'<button class="btn btn-gold btn-sm" onclick="doRestoreChar('+c.guid+',\''+safeN+'\')">Restaurar</button>'
        +'</div>';
    });
    el.innerHTML=h;
  });
}
function doRestoreChar(guid,name) {
  var err=document.getElementById('cmgmt-deleted-err');
  err.style.display='none';
  pFetch('/api/portal/char/restore',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({guid:guid})})
    .then(function(d){
      if(d.ok){toast(escH(d.name||name)+' restaurado. Costo: '+d.cost+' PD','success');loadDeletedChars();loadAccount();}
      else{err.textContent=d.error||'Error';err.style.display='block';}
    });
}

// Item shop
function loadShopItems() {
  var el=document.getElementById('cmgmt-shop-content');
  if(!el) return;
  el.innerHTML='<div style="padding:20px;text-align:center;color:var(--muted)">Cargando...</div>';
  pFetch('/api/portal/shop/items').then(function(d){
    if(!d.ok){el.innerHTML='<div style="padding:12px;color:var(--red)">'+escH(d.error||'Error')+'</div>';return;}
    if(!d.items||!d.items.length){
      el.innerHTML='<div style="padding:24px;text-align:center;color:var(--muted)">La tienda esta vacia por el momento.</div>';
      return;
    }
    var charOpts='';
    (_acctChars||[]).forEach(function(c){charOpts+='<option value="'+c.guid+'">'+escH(c.name)+' (Nv'+c.level+')</option>';});
    var h='<div class="form-row"><label>Enviar a personaje</label><select id="shop-char-sel">'+charOpts+'</select></div>'
      +'<div class="shop-grid">';
    d.items.forEach(function(item){
      h+='<div class="shop-item"><div class="si-name">'+escH(item.name)+'</div>'
        +'<div class="si-desc">'+escH(item.desc||'')+'</div>'
        +'<div class="si-price">'+item.price+' PD</div>'
        +'<button class="btn btn-gold btn-sm" style="width:100%;font-size:11px" onclick="doShopBuy('+item.id+')">Comprar</button>'
        +'</div>';
    });
    h+='</div>';
    el.innerHTML=h;
  });
}
function doShopBuy(itemId) {
  var err=document.getElementById('cmgmt-shop-err');
  err.style.display='none';
  var sel=document.getElementById('shop-char-sel');
  var charGuid=sel?parseInt(sel.value):0;
  if(!charGuid){err.textContent='Selecciona un personaje';err.style.display='block';return;}
  pFetch('/api/portal/shop/buy',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({item_id:itemId,guid:charGuid,count:1})})
    .then(function(d){
      if(d.ok){toast(d.msg||'Compra realizada. Costo: '+d.cost+' PD','success');loadAccount();}
      else{err.textContent=d.error||'Error';err.style.display='block';}
    });
}

// ── FORO ─────────────────────────────────────────────────
var _fCatId=0, _fCatName='', _fThrId=0, _fThrLocked=false;
var _fThreadsPage=0, _fPostsPage=0, _fIsMod=false;

function loadForum() {
  forumShowView('cats');
  forumLoadCats();
}
function forumShowView(v) {
  ['cats','threads','thread','newthread'].forEach(function(n){
    var el=document.getElementById('forum-view-'+n);
    if(el) el.style.display=(n===v?'':'none');
  });
  forumUpdateBC(v);
}
function forumUpdateBC(v) {
  var bc=document.getElementById('forum-bc');
  if(!bc) return;
  if(v==='cats') {
    bc.innerHTML='<span style="color:var(--muted)">Foro</span>';
  } else if(v==='threads') {
    bc.innerHTML='<span class="crumb" onclick="loadForum()">Foro</span>'
      +' <span style="color:var(--muted)">&rsaquo;</span> <span style="color:var(--text)">'+escH(_fCatName)+'</span>';
  } else if(v==='thread') {
    bc.innerHTML='<span class="crumb" onclick="loadForum()">Foro</span>'
      +' <span style="color:var(--muted)">&rsaquo;</span> <span class="crumb" onclick="forumBack()">'+escH(_fCatName)+'</span>';
  } else if(v==='newthread') {
    bc.innerHTML='<span class="crumb" onclick="loadForum()">Foro</span>'
      +' <span style="color:var(--muted)">&rsaquo;</span> <span class="crumb" onclick="forumBack()">'+escH(_fCatName)+'</span>'
      +' <span style="color:var(--muted)">&rsaquo; Nuevo Tema</span>';
  }
}
function forumBack(){forumOpenCat(_fCatId,_fCatName,_fThreadsPage);}

function forumLoadCats() {
  var el=document.getElementById('forum-cats-list');
  if(!el) return;
  el.innerHTML='<div class="forum-empty">Cargando...</div>';
  fetch('/api/forum/categories').then(function(r){return r.json();}).then(function(d){
    if(!d||!d.length){el.innerHTML='<div class="forum-empty">No hay categorias disponibles.</div>';return;}
    var h='';
    d.forEach(function(c){
      var safeN=escH(c.name);
      h+='<div class="forum-cat-row" onclick="forumOpenCat('+c.id+',\''+safeN+'\',0)">'
        +'<div class="forum-cat-ico">'+escH(c.icon||'&#x1F4AC;')+'</div>'
        +'<div class="forum-cat-body"><div class="forum-cat-name">'+safeN+'</div>'
        +(c.desc?'<div class="forum-cat-desc">'+escH(c.desc)+'</div>':'')+'</div>'
        +'<div class="forum-cat-meta"><div>'+c.threads+' temas</div><div>'+c.posts+' respuestas</div></div>'
        +'</div>';
    });
    el.innerHTML=h;
  }).catch(function(){el.innerHTML='<div class="forum-empty" style="color:var(--red)">Error al cargar categorias.</div>';});
}

function forumOpenCat(id, name, page) {
  _fCatId=id; _fCatName=name; _fThreadsPage=page||0;
  document.getElementById('forum-cat-title').innerHTML=escH(name);
  var nb=document.getElementById('forum-btn-new');
  if(nb) nb.style.display=TOKEN?'':'none';
  forumShowView('threads');
  forumLoadThreads();
}
function forumLoadThreads() {
  var el=document.getElementById('forum-threads-list');
  if(!el) return;
  el.innerHTML='<div class="forum-empty">Cargando...</div>';
  fetch('/api/forum/threads?cat='+_fCatId+'&page='+_fThreadsPage)
  .then(function(r){return r.json();}).then(function(d){
    if(!d.threads||!d.threads.length){
      el.innerHTML='<div class="forum-empty">No hay temas aun.<br><small style="color:var(--muted)">Se el primero en publicar.</small></div>';
      document.getElementById('forum-threads-pager').innerHTML=''; return;
    }
    var h='';
    d.threads.forEach(function(t){
      var badges='';
      if(t.pinned) badges+='<span class="forum-badge pin">&#x1F4CC;</span> ';
      if(t.locked) badges+='<span class="forum-badge lock">&#x1F512;</span> ';
      var safeT=t.title.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
      h+='<div class="forum-thread-row" onclick="forumOpenThread('+t.id+',\''+safeT+'\','+t.locked+')">'
        +'<div><div class="forum-thread-name">'+badges+escH(t.title)+'</div>'
        +'<div class="forum-thread-sub">Por <strong>'+escH(t.author)+'</strong> &bull; '+escH(t.ts)+'</div></div>'
        +'<div class="forum-thread-stat"><span class="n">'+t.views+'</span>vistas</div>'
        +'<div class="forum-thread-stat"><span class="n">'+t.replies+'</span>respuestas</div>'
        +'</div>';
    });
    el.innerHTML=h;
    var pg=document.getElementById('forum-threads-pager');
    var pages=d.pages||1;
    if(pages>1){
      pg.innerHTML=(_fThreadsPage>0?'<button class="btn btn-ghost btn-sm" style="margin:4px" onclick="forumOpenCat(_fCatId,_fCatName,'+(_fThreadsPage-1)+')">&#x2190; Anterior</button>':'')+
        ' Pag. '+(_fThreadsPage+1)+'/'+pages+' '+
        (_fThreadsPage<pages-1?'<button class="btn btn-ghost btn-sm" style="margin:4px" onclick="forumOpenCat(_fCatId,_fCatName,'+(_fThreadsPage+1)+')">Siguiente &#x2192;</button>':'');
    } else {pg.innerHTML='';}
  }).catch(function(){el.innerHTML='<div class="forum-empty" style="color:var(--red)">Error al cargar.</div>';});
}

function forumOpenThread(id, title, locked) {
  _fThrId=id; _fThrLocked=!!locked; _fPostsPage=0;
  document.getElementById('forum-thread-title').textContent=title;
  forumShowView('thread');
  forumLoadPosts();
}
function forumLoadPosts() {
  var el=document.getElementById('forum-posts-list');
  if(!el) return;
  el.innerHTML='<div style="padding:30px;text-align:center;color:var(--muted)">Cargando...</div>';
  fetch('/api/forum/thread?id='+_fThrId+'&page='+_fPostsPage)
  .then(function(r){return r.json();}).then(function(d){
    _fIsMod=d.is_mod||false;
    _fThrLocked=d.locked||false;
    // Thread actions bar
    var actEl=document.getElementById('forum-thread-actions');
    if(actEl){
      var ab='<button class="btn btn-ghost btn-sm" onclick="forumScrollReply()">&#x1F4AC; Responder</button>';
      if(_fIsMod){
        ab+=' <button class="btn btn-ghost btn-sm" onclick="forumModPin()">&#x1F4CC; '+(d.pinned?'Desfijar':'Fijar')+'</button>'
          +' <button class="btn btn-ghost btn-sm" onclick="forumModLock()">&#x1F512; '+(d.locked?'Abrir':'Cerrar')+'</button>'
          +' <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="forumModDelThread()">&#x1F5D1; Borrar Tema</button>';
      }
      actEl.innerHTML=ab;
    }
    if(!d.posts||!d.posts.length){
      el.innerHTML='<div style="padding:30px;text-align:center;color:var(--muted)">Sin publicaciones.</div>';
    } else {
      var h=''; var offset=_fPostsPage*15;
      d.posts.forEach(function(p,i){
        var isOp=(offset+i===0);
        h+='<div class="forum-post-box">'
          +'<div class="forum-post-hdr">'
          +'<div><div class="forum-post-author">'+escH(p.author)
          +(isOp?' <span style="font-size:10px;background:rgba(201,162,61,.15);color:var(--gold);padding:1px 7px;border-radius:4px;font-weight:700">OP</span>':'')+'</div>'
          +'<div class="forum-post-meta">'+escH(p.ts)+' &bull; #'+(offset+i+1)+'</div></div>'
          +'<div style="display:flex;gap:6px;align-items:center">'
          +(_fIsMod?'<button class="btn btn-ghost btn-sm" style="padding:2px 8px;font-size:11px;color:var(--red)" onclick="forumModDelPost('+p.id+')">&#x1F5D1;</button>':'')
          +'</div></div>'
          +'<div class="forum-post-body">'+escH(p.content)+'</div>'
          +'</div>';
      });
      el.innerHTML=h;
    }
    var pg=document.getElementById('forum-posts-pager');
    var pages=d.pages||1;
    if(pages>1){
      pg.innerHTML=(_fPostsPage>0?'<button class="btn btn-ghost btn-sm" style="margin:4px" onclick="forumGoPage('+(_fPostsPage-1)+')">&#x2190; Anterior</button>':'')+
        ' Pag. '+(_fPostsPage+1)+'/'+pages+' '+
        (_fPostsPage<pages-1?'<button class="btn btn-ghost btn-sm" style="margin:4px" onclick="forumGoPage('+(_fPostsPage+1)+')">Siguiente &#x2192;</button>':'');
    } else {if(pg) pg.innerHTML='';}
    // Reply area
    var ra=document.getElementById('forum-reply-area');
    if(ra){
      if(!TOKEN){
        ra.innerHTML='<div class="dl-card" style="text-align:center;padding:20px;color:var(--muted)">&#x1F512; <a onclick="openLogin()" style="color:var(--gold);cursor:pointer">Inicia sesion</a> para responder</div>';
      } else if(_fThrLocked){
        ra.innerHTML='<div class="dl-card" style="text-align:center;padding:16px;color:var(--muted)">&#x1F512; Este tema esta cerrado</div>';
      } else {
        ra.innerHTML='<div class="dl-card" id="forum-reply-box">'
          +'<div style="font-size:15px;font-weight:700;margin-bottom:14px">&#x1F4AC; Responder</div>'
          +'<div class="form-row"><textarea id="forum-reply-text" placeholder="Escribe tu respuesta..." rows="6" maxlength="10000"></textarea></div>'
          +'<div id="forum-reply-err" style="color:var(--red);font-size:12px;margin-top:8px;display:none"></div>'
          +'<button class="btn btn-gold" style="margin-top:12px" onclick="forumSubmitReply()">Publicar Respuesta</button>'
          +'</div>';
      }
    }
  }).catch(function(){el.innerHTML='<div style="padding:30px;text-align:center;color:var(--red)">Error al cargar.</div>';});
}
function forumGoPage(p){_fPostsPage=p;forumLoadPosts();}
function forumScrollReply(){
  if(!TOKEN){openLogin();return;}
  if(_fThrLocked){toast('Este tema esta cerrado','info');return;}
  var el=document.getElementById('forum-reply-box')||document.getElementById('forum-reply-area');
  if(el) el.scrollIntoView({behavior:'smooth'});
}
function forumOpenNewThread(){
  if(!TOKEN){openLogin();return;}
  document.getElementById('forum-new-title').value='';
  document.getElementById('forum-new-body').value='';
  document.getElementById('forum-new-err').style.display='none';
  forumShowView('newthread');
}
function forumSubmitThread(){
  var title=document.getElementById('forum-new-title').value.trim();
  var body=document.getElementById('forum-new-body').value.trim();
  var err=document.getElementById('forum-new-err');
  err.style.display='none';
  if(title.length<3){err.textContent='El titulo debe tener al menos 3 caracteres';err.style.display='block';return;}
  if(body.length<10){err.textContent='El contenido debe tener al menos 10 caracteres';err.style.display='block';return;}
  pFetch('/api/forum/thread/new',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({cat_id:_fCatId,title:title,content:body})})
  .then(function(d){
    if(d.ok){toast('Tema publicado','success');forumBack();}
    else{err.textContent=d.error||'Error al publicar';err.style.display='block';}
  });
}
function forumSubmitReply(){
  var ta=document.getElementById('forum-reply-text');
  var err=document.getElementById('forum-reply-err');
  if(!ta) return;
  var text=ta.value.trim();
  if(err) err.style.display='none';
  if(text.length<2){if(err){err.textContent='Escribe algo antes de publicar';err.style.display='block';}return;}
  pFetch('/api/forum/post/new',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({thread_id:_fThrId,content:text})})
  .then(function(d){
    if(d.ok){toast('Respuesta publicada','success');ta.value='';forumLoadPosts();}
    else{if(err){err.textContent=d.error||'Error';err.style.display='block';}}
  });
}
function forumModPin(){
  pFetch('/api/forum/thread/pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:_fThrId})})
  .then(function(d){if(d.ok){toast(d.pinned?'Tema fijado':'Tema desfijado','success');forumLoadPosts();}else{toast(d.error||'Error','error');}});
}
function forumModLock(){
  pFetch('/api/forum/thread/lock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:_fThrId})})
  .then(function(d){if(d.ok){toast(d.locked?'Tema cerrado':'Tema abierto','success');forumLoadPosts();}else{toast(d.error||'Error','error');}});
}
function forumModDelThread(){
  if(!confirm('Borrar este tema y todas sus respuestas?')) return;
  pFetch('/api/forum/thread/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:_fThrId})})
  .then(function(d){if(d.ok){toast('Tema eliminado','info');forumBack();}else{toast(d.error||'Error','error');}});
}
function forumModDelPost(id){
  if(!confirm('Borrar esta publicacion?')) return;
  pFetch('/api/forum/post/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
  .then(function(d){if(d.ok){toast('Publicacion eliminada','info');forumLoadPosts();}else{toast(d.error||'Error','error');}});
}

// ── WEB CHAT ─────────────────────────────────────────────
var _wChatCharGuid=0, _wChatCharName='', _wChatAfterId=0;
var _wChatFilter='all', _wChatTimer=null, _wChatPollPending=false;

var _wcCls={say:'say',yell:'yell',guild:'guild',officer:'officer',
  whisper:'whisper',whisper_out:'whisper',whisper_in:'whisper',
  party:'party',raid:'raid',raid_warning:'yell',
  instance:'party',battleground:'party',emote:'emote',channel:'chan'};

var _wcTypeTag={say:'',yell:'[Grita] ',guild:'',officer:'',
  whisper_out:'',whisper_in:'',
  party:'[Party] ',raid:'[Raid] ',raid_warning:'[Aviso] ',
  instance:'[Inst] ',battleground:'[BG] ',emote:'',channel:''};

var _chanLabels={'1':'General','2':'Trade','22':'Def.Local','25':'LFG','26':'Guild Rec.'};
function _chanLabel(cn){ return _chanLabels[cn]||cn||'?'; }

function loadWebChat() {
  wchatRefreshChars();
  if (_wChatCharGuid && !_wChatTimer)
    _wChatTimer = setInterval(wchatPoll, 3000);
}

function wchatRefreshChars() {
  var el = document.getElementById('wchat-char-list');
  if (!TOKEN) {
    el.innerHTML = '<span style="font-size:12px;color:var(--muted)">Inicia sesion para ver tus personajes</span>';
    return;
  }
  pFetch('/api/portal/chat/chars').then(function(d){
    if (!Array.isArray(d)||!d.length){
      el.innerHTML='<span style="font-size:12px;color:var(--muted)">Sin personajes en la cuenta</span>'; return;
    }
    var h='';
    d.forEach(function(c){
      var cls='wchat-char-pill'+(c.online?' is-online':' is-offline')+(c.guid===_wChatCharGuid?' is-selected':'');
      h+='<div class="'+cls+'" onclick="wchatSelectChar('+c.guid+',\''+escH(c.name)+'\')">'
        +(c.online?'&#x1F7E2;':'&#x26AB;')+' '+escH(c.name)
        +' <span style="font-size:10px;opacity:.6">Nv'+c.level+'</span>'
        +(c.online?'':' <span style="font-size:10px;opacity:.5">(offline)</span>')
        +'</div>';
    });
    el.innerHTML=h;
  }).catch(function(){
    el.innerHTML='<span style="font-size:12px;color:var(--red)">Error al cargar personajes</span>';
  });
}

function wchatSelectChar(guid, name) {
  _wChatCharGuid=guid; _wChatCharName=name; _wChatAfterId=0; _wChatPollPending=false;
  wchatRefreshChars();
  document.getElementById('wchat-input-area').style.display='flex';
  document.getElementById('wchat-status-bar').style.display='none';
  var log=document.getElementById('wchat-log');
  log.innerHTML='<div data-placeholder style="padding:20px;text-align:center;color:var(--muted);font-size:12px">Cargando historial...</div>';
  if (_wChatTimer) clearInterval(_wChatTimer);
  wchatPoll();
  _wChatTimer=setInterval(wchatPoll, 3000);
}

function wchatPoll() {
  if (!_wChatCharGuid || _wChatPollPending) return;
  _wChatPollPending=true;
  fetch('/api/chat/events?char_guid='+_wChatCharGuid+'&after_id='+_wChatAfterId)
    .then(function(r){return r.json();})
    .then(function(d){
      var log=document.getElementById('wchat-log');
      var ph=log.querySelector('[data-placeholder]');
      if(ph){
        ph.remove();
        if(!d||!d.events||d.events.length===0){
          log.innerHTML='<div style="padding:30px;text-align:center;color:var(--muted);font-size:12px">Sin mensajes recientes. Los mensajes del juego apareceran aqui en tiempo real.</div>';
          return;
        }
      }
      if(!d||!d.events||d.events.length===0) return;
      var wasBottom=(log.scrollTop+log.clientHeight>=log.scrollHeight-40);
      d.events.forEach(function(e){
        if(e.id>_wChatAfterId) _wChatAfterId=e.id;
        wchatRenderMsg(e,log);
      });
      if(wasBottom) log.scrollTop=log.scrollHeight;
      var msgs=log.querySelectorAll('.wchat-msg');
      if(msgs.length>400) for(var i=0;i<msgs.length-400;i++) msgs[i].remove();
    }).catch(function(){
      var log=document.getElementById('wchat-log');
      var ph=log.querySelector('[data-placeholder]');
      if(ph){ ph.remove(); log.innerHTML='<div style="padding:20px;text-align:center;color:var(--red);font-size:12px">Error al conectar.</div>'; }
    }).finally(function(){
      _wChatPollPending=false;
    });
}

function wchatRenderMsg(e, log) {
  var t=e.chat_type||'say';
  var cls=_wcCls[t]||'say';
  // Apply filter
  if(_wChatFilter!=='all'){
    var fmap={say:'say',yell:'yell',guild:'guild',officer:'officer',whisper:'whisper',party:'party',raid:'party',channel:'chan'};
    if(fmap[_wChatFilter] && cls!==fmap[_wChatFilter] && !(fmap[_wChatFilter]==='party'&&cls==='raid')) return;
    if(!fmap[_wChatFilter] && cls!==_wChatFilter) return;
  }
  if(!log) log=document.getElementById('wchat-log');
  // Remove initial placeholder
  var phs=log.querySelectorAll('[data-placeholder]');
  phs.forEach(function(p){p.remove();});

  var ts=''; if(e.ts){ var ti=e.ts.indexOf(' '); ts=(ti>=0?e.ts.substring(ti+1):e.ts).substring(0,5); }
  var tsHtml=ts?'<span class="wchat-ts">['+ts+']</span>':'';
  var tag=t==='channel'?('['+_chanLabel(e.channel_name)+'] '):(_wcTypeTag[t]||'');
  var tagHtml=tag?'<span class="wchat-type-tag">'+escH(tag)+'</span>':'';
  var senderHtml=''; var body=escH(e.message);

  if(t==='emote'){
    senderHtml='<span class="wchat-sender">'+escH(e.char_name)+'</span> ';
  } else if(t==='whisper_out'){
    senderHtml='<span class="wchat-sender">'+escH(e.char_name||_wChatCharName)+'</span>'
      +' &#x2192; <span class="wchat-sender">'+escH(e.target_name)+'</span>: ';
  } else if(t==='whisper_in'){
    senderHtml='<span class="wchat-sender">'+escH(e.target_name)+'</span>'
      +' &#x2192; <span class="wchat-sender">'+escH(e.char_name)+'</span>: ';
  } else {
    senderHtml='<span class="wchat-sender">'+escH(e.char_name)+'</span>: ';
  }

  var div=document.createElement('div');
  div.className='wchat-msg '+cls;
  div.innerHTML=tsHtml+tagHtml+senderHtml+body;
  log.appendChild(div);
}

function wchatSetFilter(f) {
  _wChatFilter=f;
  document.querySelectorAll('.wchat-tab').forEach(function(t){ t.classList.toggle('active',t.dataset.filter===f); });
}

function wchatLoadChannels() {
  var sel=document.getElementById('wchat-channel-sel');
  fetch('/api/chat/channels')
    .then(function(r){return r.json();})
    .then(function(d){
      if(!d||!d.length)return;
      sel.innerHTML='';
      d.forEach(function(c){
        var o=document.createElement('option');
        o.value=c.value; o.textContent=c.name; sel.appendChild(o);
      });
    }).catch(function(){
      sel.innerHTML='<option value="General">General (1)</option><option value="Trade">Trade (2)</option>';
    });
}

function wchatTypeChange() {
  var t=document.getElementById('wchat-type').value;
  var tgt=document.getElementById('wchat-target');
  var csel=document.getElementById('wchat-channel-sel');
  if(t==='whisper'){
    tgt.style.display=''; tgt.placeholder='Nombre del jugador...'; tgt.value='';
    csel.style.display='none';
  } else if(t==='channel'){
    tgt.style.display='none'; tgt.value='';
    csel.style.display='';
    if(!csel._loaded){ csel._loaded=true; wchatLoadChannels(); }
  } else {
    tgt.style.display='none'; tgt.value='';
    csel.style.display='none';
  }
}

function wchatSend() {
  if(!TOKEN){toast('Inicia sesion primero','warning');return;}
  if(!_wChatCharGuid){toast('Selecciona un personaje','warning');return;}
  var type=document.getElementById('wchat-type').value;
  var msg=document.getElementById('wchat-msg').value.trim();
  var target=document.getElementById('wchat-target').value.trim();
  var chanVal=document.getElementById('wchat-channel-sel').value||'';
  if(!msg) return;
  if(type==='whisper'&&!target){toast('Escribe el nombre del destinatario','warning');return;}
  if(type==='channel'&&!chanVal){toast('Selecciona un canal','warning');return;}
  var btn=document.querySelector('#wchat-input-area .btn-gold');
  if(btn){btn.disabled=true;}
  pFetch('/api/portal/chat/send',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({char_guid:_wChatCharGuid,chat_type:type,message:msg,
      target:type==='whisper'?target:'',
      channel:type==='channel'?chanVal:''})
  }).then(function(d){
    if(d.ok){
      document.getElementById('wchat-msg').value='';
      var fakeTs=(new Date()).toISOString().replace('T',' ');
      wchatRenderMsg({id:0,ts:fakeTs,chat_type:type==='whisper'?'whisper_out':type,
        char_name:_wChatCharName,target_name:target,message:msg,
        channel_name:type==='channel'?chanVal:''});
      var log=document.getElementById('wchat-log');
      log.scrollTop=log.scrollHeight;
    } else { toast(d.error||'Error al enviar','error'); }
  }).catch(function(){toast('Error de red','error');})
  .finally(function(){if(btn)btn.disabled=false;});
}

// ── HISTORIALES ──────────────────────────────────────────
var _histCat='pdpv', _histPage=0, _histPages=0;
function openHistoryModal(cat) {
  _histCat=cat||'pdpv'; _histPage=0;
  document.querySelectorAll('.hist-tab').forEach(function(t){
    t.classList.toggle('active', t.getAttribute('data-cat')===_histCat);
  });
  document.getElementById('modal-history').classList.add('open');
  loadHistoryData();
}
function switchHistTab(cat) {
  _histCat=cat; _histPage=0;
  document.querySelectorAll('.hist-tab').forEach(function(t){
    t.classList.toggle('active', t.getAttribute('data-cat')===cat);
  });
  loadHistoryData();
}
function loadHistoryData() {
  var el=document.getElementById('hist-list');
  if (!el) return;
  el.innerHTML='<div style="padding:20px;text-align:center;color:var(--muted)">Cargando...</div>';
  pFetch('/api/portal/history?category='+encodeURIComponent(_histCat)+'&page='+_histPage)
  .then(function(d){
    _histPages=d.pages||1;
    if (!d.items||!d.items.length) {
      el.innerHTML='<div style="padding:24px;text-align:center;color:var(--muted)">Sin registros.</div>';
      document.getElementById('hist-pagination').innerHTML=''; return;
    }
    var h='';
    d.items.forEach(function(e){
      var amtCls=e.amount>0?'pos':(e.amount<0?'neg':'');
      var amtTxt=e.amount===0?'':(e.amount>0?'+':'')+e.amount;
      var meta=[]; if(e.ts) meta.push(escH(e.ts)); if(e.ip) meta.push(escH(e.ip)); if(e.extra) meta.push(escH(e.extra));
      h+='<div class="hist-item">'
        +'<div class="hi-desc">'+escH(e.desc)
        +(meta.length?'<span class="hi-meta">'+meta.join(' &bull; ')+'</span>':'')
        +'</div>'
        +(amtTxt?'<div class="hi-amt '+amtCls+'">'+escH(amtTxt)+'</div>':'')
        +'</div>';
    });
    el.innerHTML=h;
    var pg=document.getElementById('hist-pagination');
    if (_histPages>1) {
      pg.innerHTML='Pag. '+(_histPage+1)+'/'+_histPages
        +(_histPage>0?' <button class="btn btn-ghost btn-sm" style="padding:3px 10px" onclick="histPrev()">&#x2190;</button>':'')
        +(_histPage<_histPages-1?' <button class="btn btn-ghost btn-sm" style="padding:3px 10px" onclick="histNext()">&#x2192;</button>':'');
    } else { pg.innerHTML=''; }
  }).catch(function(){el.innerHTML='<div style="padding:20px;text-align:center;color:var(--red)">Error al cargar.</div>';});
}
function histPrev(){if(_histPage>0){_histPage--;loadHistoryData();}}
function histNext(){if(_histPage<_histPages-1){_histPage++;loadHistoryData();}}

// ── INIT ─────────────────────────────────────────────────
updateNavAuth();
navTo('home');
</script>
</body>
</html>
)PORTAL";

// ============================================================================
// Embedded single-page admin dashboard
// ============================================================================
static char const* k_Html = R"ADMIN(<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BNetServer &mdash; Administracion</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0e0f1a;--sb:#0b0c17;--card:#141523;--bdr:#1e2035;--text:#e8eaf6;--muted:#6b7099;--accent:#4f7cff;--green:#22c55e;--yellow:#f59e0b;--red:#ef4444;--hdr:#0d0e1b;--hover:rgba(255,255,255,.05)}
body{display:flex;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;min-height:100vh}
/* Sidebar */
.sb{width:220px;min-height:100vh;background:var(--sb);border-right:1px solid var(--bdr);display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:0;height:100vh;overflow-y:auto}
.sb-logo{display:flex;align-items:center;gap:10px;padding:18px 16px;border-bottom:1px solid var(--bdr)}
.logo-box{width:30px;height:30px;background:var(--accent);border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:15px}
.sb-logo span{font-weight:700;font-size:15px}
.nav-sec{padding:12px 10px 4px}
.nav-lbl{font-size:10px;font-weight:600;letter-spacing:1.1px;color:var(--muted);text-transform:uppercase;padding:0 6px;margin-bottom:6px}
.nav-link{display:flex;align-items:center;gap:9px;padding:7px 10px;border-radius:7px;cursor:pointer;color:var(--muted);transition:all .12s;margin-bottom:1px;user-select:none}
.nav-link:hover{background:var(--hover);color:var(--text)}
.nav-link.active{background:rgba(79,124,255,.13);color:var(--accent)}
.nav-link .ic{width:16px;text-align:center;font-size:13px;flex-shrink:0}
.badge-live{margin-left:auto;background:var(--green);color:#fff;font-size:9px;padding:1px 6px;border-radius:8px;font-weight:700;animation:blink 1.8s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.5}}
/* Main */
.main{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}
.hdr{background:var(--hdr);border-bottom:1px solid var(--bdr);padding:0 22px;height:52px;display:flex;align-items:center;gap:14px;flex-shrink:0}
.hdr-title{font-size:15px;font-weight:600;flex:1}
.hdr-sub{font-size:12px;color:var(--muted);margin-top:1px}
.hdr-acts{display:flex;align-items:center;gap:12px;margin-left:auto}
.hdr-usr{display:flex;flex-direction:column;align-items:flex-end}
.hdr-usr .u-name{font-weight:600;font-size:12px}
.hdr-usr .u-role{font-size:11px;color:var(--muted)}
.avatar{width:30px;height:30px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px}
/* Content */
.content{flex:1;overflow-y:auto;padding:20px}
/* Page system */
.page{display:none}
.page.active{display:block}
.pg-hdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px}
.pg-hdr h1{font-size:20px;font-weight:700}
.pg-hdr p{color:var(--muted);font-size:12px;margin-top:2px}
/* Stat cards */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:18px;display:flex;justify-content:space-between;align-items:flex-start}
.si .lbl{font-size:11px;color:var(--muted);margin-bottom:5px}
.si .val{font-size:24px;font-weight:700;line-height:1}
.si .sub{font-size:11px;margin-top:5px}
.ico{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.ico-b{background:rgba(79,124,255,.12)}
.ico-g{background:rgba(34,197,94,.12)}
.ico-p{background:rgba(168,85,247,.12)}
.ico-y{background:rgba(245,158,11,.12)}
/* Mid grid */
.mid-grid{display:grid;grid-template-columns:1fr 340px;gap:14px;margin-bottom:20px}
/* Cards */
.card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:18px}
.card-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.card-ttl{font-size:14px;font-weight:600}
/* Info rows */
.info-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--bdr);font-size:13px}
.info-row:last-child{border-bottom:none}
.info-row .k{color:var(--muted)}
/* Chart */
#actChart{width:100%;display:block}
/* Buttons */
.btn{padding:7px 14px;border-radius:7px;border:none;font-size:12px;font-weight:500;cursor:pointer;display:inline-flex;align-items:center;gap:5px;transition:opacity .12s;font-family:inherit}
.btn:hover{opacity:.82}
.btn-primary{background:var(--accent);color:#fff}
.btn-outline{background:transparent;border:1px solid var(--bdr);color:var(--text)}
.btn-danger{background:var(--red);color:#fff}
.btn-warn{background:var(--yellow);color:#000}
.btn-success{background:var(--green);color:#fff}
.btn-sm{padding:4px 10px;font-size:11px;border-radius:5px}
/* Tables */
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table th{text-align:left;padding:9px 12px;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--bdr)}
.data-table td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.03);vertical-align:middle}
.data-table tbody tr:hover{background:var(--hover)}
.data-table td.mono{font-family:Consolas,monospace;font-size:12px}
.data-table td.muted{color:var(--muted)}
/* Badges */
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700}
.badge-green{background:rgba(34,197,94,.15);color:var(--green)}
.badge-red{background:rgba(239,68,68,.15);color:var(--red)}
.badge-blue{background:rgba(79,124,255,.15);color:#7ba4ff}
.badge-yellow{background:rgba(245,158,11,.15);color:var(--yellow)}
/* Log entries */
.log-entry{display:flex;align-items:baseline;gap:8px;padding:7px 14px;border-bottom:1px solid rgba(255,255,255,.025);font-size:12px}
.log-entry:last-child{border-bottom:none}
.log-lvl{font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;white-space:nowrap;min-width:42px;text-align:center;flex-shrink:0}
.lv-info{background:rgba(79,124,255,.15);color:#7ba4ff}
.lv-warn{background:rgba(245,158,11,.15);color:#fbbf24}
.lv-error{background:rgba(239,68,68,.15);color:#f87171}
.lv-debug{background:rgba(107,114,128,.15);color:#9ca3af}
.lv-fatal{background:rgba(239,68,68,.28);color:#ff5555}
.log-txt{flex:1;color:var(--muted);line-height:1.45;font-family:Consolas,monospace;word-break:break-all}
.log-time{color:var(--muted);font-size:10px;white-space:nowrap;flex-shrink:0;margin-left:auto}
/* Log card */
.log-card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;overflow:hidden}
.log-card .card-hdr{padding:12px 16px;border-bottom:1px solid var(--bdr);margin-bottom:0}
.log-body{overflow-y:auto}
/* Bottom grid */
.bot-grid{display:grid;grid-template-columns:1fr 300px;gap:14px;margin-bottom:20px}
/* Realm cards */
.realm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.realm-card-full{background:var(--card);border:1px solid var(--bdr);border-radius:10px;overflow:hidden}
.rc-hdr{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--bdr)}
.rc-hdr h3{font-size:14px;font-weight:600;flex:1}
.rc-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.dot-g{background:var(--green);box-shadow:0 0 5px var(--green)}
.dot-r{background:var(--red)}
.dot-y{background:var(--yellow)}
.rc-body{padding:14px 16px}
.rc-row{display:flex;justify-content:space-between;padding:5px 0;font-size:12px}
.rc-row .rk{color:var(--muted)}
.rc-foot{padding:12px 16px;border-top:1px solid var(--bdr);display:flex;gap:8px}
/* Dashboard realm row */
.realm-row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:13px}
.realm-row:last-child{border-bottom:none}
.rstatus{display:flex;align-items:center;gap:6px;font-size:12px}
/* Toolbar / filter row */
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.search-box{display:flex;align-items:center;gap:6px;background:rgba(255,255,255,.04);border:1px solid var(--bdr);border-radius:7px;padding:6px 12px;flex:1;min-width:200px}
.search-box input{border:none;background:transparent;color:var(--text);font-size:13px;outline:none;flex:1;font-family:inherit}
.filter-btn{padding:5px 12px;border-radius:6px;border:1px solid var(--bdr);background:transparent;color:var(--muted);font-size:11px;cursor:pointer;font-family:inherit;transition:all .12s}
.filter-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.filter-btn:hover:not(.active){background:var(--hover);color:var(--text)}
/* Pagination */
.pager{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.pager-info{color:var(--muted);font-size:12px;margin-left:auto}
/* Full log page */
.log-page-wrap{background:var(--card);border:1px solid var(--bdr);border-radius:10px;overflow:hidden}
.log-page-hdr{display:flex;align-items:center;gap:8px;padding:12px 16px;border-bottom:1px solid var(--bdr);flex-wrap:wrap}
.log-full{height:calc(100vh - 280px);min-height:300px;overflow-y:auto}
/* Config */
.config-section{margin-bottom:22px}
.config-section h3{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:10px}
/* Maintenance */
.maint-banner{border-radius:10px;padding:28px 24px;margin-bottom:20px;display:flex;align-items:center;gap:20px;border:1px solid}
.maint-banner.off{background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.25)}
.maint-banner.on{background:rgba(245,158,11,.08);border-color:rgba(245,158,11,.35)}
.maint-ico{font-size:40px;flex-shrink:0}
.maint-info{flex:1}
.maint-info h2{font-size:18px;font-weight:700;margin-bottom:4px}
.maint-info p{font-size:13px;color:var(--muted);line-height:1.5}
.toggle-wrap{display:flex;align-items:center;gap:10px;cursor:pointer}
.toggle-track{width:52px;height:28px;border-radius:14px;background:rgba(255,255,255,.1);position:relative;transition:background .2s;border:1px solid var(--bdr)}
.toggle-track.on{background:var(--yellow);border-color:var(--yellow)}
.toggle-thumb{width:22px;height:22px;border-radius:50%;background:#fff;position:absolute;top:2px;left:2px;transition:left .2s;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.toggle-track.on .toggle-thumb{left:26px}
.toggle-lbl{font-weight:600;font-size:14px}
/* Quick actions bottom */
.qa-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.qa-card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:16px 14px;display:flex;flex-direction:column;gap:5px}
.qa-ico{width:36px;height:36px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px;margin-bottom:3px}
.qa-ico-b{background:rgba(79,124,255,.12)}
.qa-ico-g{background:rgba(34,197,94,.12)}
.qa-ico-y{background:rgba(245,158,11,.12)}
.qa-ico-r{background:rgba(239,68,68,.12)}
.qa-ico-p{background:rgba(168,85,247,.12)}
.qa-card h4{font-size:12px;font-weight:600}
.qa-card p{font-size:11px;color:var(--muted);flex:1;line-height:1.4}
/* Live dot */
.live-dot{display:inline-block;width:6px;height:6px;background:var(--green);border-radius:50%;margin-right:4px;animation:blink 1.5s infinite}
/* Modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:24px;min-width:360px;max-width:480px;width:90%}
.modal h2{font-size:16px;font-weight:700;margin-bottom:16px}
.modal-row{margin-bottom:14px}
.modal-row label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}
.modal-row input,.modal-row select,.modal-row textarea{width:100%;background:rgba(255,255,255,.05);border:1px solid var(--bdr);border-radius:6px;padding:8px 12px;color:var(--text);font-size:13px;font-family:inherit;outline:none}
.modal-row input:focus,.modal-row select:focus,.modal-row textarea:focus{border-color:var(--accent)}
.modal-row select option{background:var(--card)}
.modal-foot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
/* Chat monitor log entries */
.cm-entry{padding:2px 0;border-bottom:1px solid rgba(255,255,255,.04);white-space:pre-wrap;word-break:break-word}
.cm-ts{color:var(--muted)}
.cm-zone{color:#5b8dd9;font-size:11px}
.cm-say{color:#e8eaf6}.cm-yell{color:var(--yellow);font-weight:600}
.cm-emote{color:var(--muted);font-style:italic}
.cm-whisper_out{color:#d4aaff}.cm-whisper_in{color:#aacfff}
.cm-guild{color:#39d353}.cm-officer{color:#00c8b4}
.cm-party{color:#7ec8e3}.cm-raid{color:#ff9f43}.cm-raid_warning{color:var(--red);font-weight:700}
.cm-instance{color:#b48eff}.cm-channel{color:#5fd7e8}.cm-bg{color:#b3e060}
/* Toast */
.toast{position:fixed;bottom:24px;right:24px;padding:11px 18px;border-radius:8px;font-size:13px;font-weight:500;z-index:999;opacity:0;pointer-events:none;transition:opacity .25s;border:1px solid transparent}
.toast.show{opacity:1}
.toast.success{background:#0d2e1a;color:var(--green);border-color:var(--green)}
.toast.error{background:#2e0d0d;color:var(--red);border-color:var(--red)}
.toast.warn{background:#2e1f0d;color:var(--yellow);border-color:var(--yellow)}
.toast.info{background:#0d162e;color:#7ba4ff;border-color:var(--accent)}
/* Progress bar */
.prog-bar{height:4px;background:rgba(255,255,255,.06);border-radius:2px;margin-top:4px;min-width:80px}
.prog-fill{height:100%;border-radius:2px;background:var(--accent);transition:width .5s}
/* Scrollbar */
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:2px}
/* Responsive */
@media(max-width:1050px){.stat-grid{grid-template-columns:repeat(2,1fr)}.mid-grid,.bot-grid{grid-template-columns:1fr}.qa-grid{grid-template-columns:repeat(3,1fr)}}
/* Players page */
.player-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.player-card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:14px;cursor:pointer;transition:border-color .15s}
.player-card:hover{border-color:var(--accent)}
.pc-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.pc-avatar{width:40px;height:40px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.pc-name{font-weight:600;font-size:14px}
.pc-sub{font-size:11px;color:var(--muted);margin-top:2px}
.pc-info{display:flex;flex-direction:column;gap:5px;font-size:12px}
.pc-row{display:flex;justify-content:space-between}
.pc-row .pk{color:var(--muted)}
.faction-a{color:#5abeff}
.faction-h{color:#ff5a5a}
/* Detail modal */
.detail-modal{max-width:820px;width:96%;max-height:90vh;overflow:hidden;display:flex;flex-direction:column;padding:20px 20px 0 20px}
.detail-head{display:flex;align-items:center;gap:12px;padding-bottom:14px;border-bottom:1px solid var(--bdr);flex-shrink:0}
.detail-tabs{display:flex;gap:0;border-bottom:1px solid var(--bdr);flex-shrink:0;overflow-x:auto}
.detail-tab{padding:10px 14px;font-size:12px;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;white-space:nowrap;transition:all .12s}
.detail-tab:hover{color:var(--text)}
.detail-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.detail-body{flex:1;overflow-y:auto;padding:16px 0}
.tab-pane{display:none}
.tab-pane.active{display:block}
/* Item cells */
.item-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:6px}
.item-cell{background:rgba(255,255,255,.04);border:1px solid var(--bdr);border-radius:6px;padding:6px 8px;font-size:11px}
.item-cell:hover{border-color:rgba(255,255,255,.18)}
.item-qty{font-size:10px;color:var(--muted)}
/* Skill bars */
.skill-bar-wrap{margin-bottom:10px}
.skill-bar-hdr{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px}
.skill-bar-bg{height:6px;background:rgba(255,255,255,.07);border-radius:3px}
.skill-bar-fill{height:100%;border-radius:3px;background:var(--accent)}
/* Achievement */
.ach-item{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.ach-item:last-child{border-bottom:none}
.ach-pts{background:rgba(245,158,11,.15);color:var(--yellow);font-size:10px;padding:2px 6px;border-radius:4px;white-space:nowrap;margin-left:auto;flex-shrink:0}
/* Mail */
.mail-item{background:rgba(255,255,255,.03);border:1px solid var(--bdr);border-radius:7px;padding:10px 12px;margin-bottom:8px}
.mail-subj{font-weight:500;font-size:13px;margin-bottom:4px}
.mail-meta{font-size:11px;color:var(--muted);display:flex;gap:12px;flex-wrap:wrap}
/* XP bar */
.xp-bar-bg{height:8px;background:rgba(255,255,255,.07);border-radius:4px;overflow:hidden;margin-top:4px}
.xp-bar-fill{height:100%;background:linear-gradient(90deg,#7c3aed,#a855f7);border-radius:4px}
/* Guild bank tab buttons */
.gbank-tabs{display:flex;gap:6px;margin-bottom:10px;overflow-x:auto;flex-wrap:wrap}
.gbank-tab-btn{padding:4px 12px;border-radius:5px;border:1px solid var(--bdr);background:transparent;color:var(--muted);font-size:11px;cursor:pointer;font-family:inherit;white-space:nowrap}
.gbank-tab-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
/* Page-level tab bar (players online/offline, etc.) */
.pg-tab-bar{display:flex;gap:0;border-bottom:1px solid var(--bdr);margin-bottom:16px}
.pg-tab{padding:10px 20px;font-size:13px;font-weight:500;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;transition:all .12s;white-space:nowrap}
.pg-tab:hover{color:var(--text)}
.pg-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
/* Offline placeholder */
.offline-hint{color:var(--muted);padding:32px 0;text-align:center;font-size:13px}
/* Pagination */
.pag-bar{display:flex;align-items:center;gap:5px;padding:18px 0;flex-wrap:wrap}
.pag-btn{padding:5px 10px;border:1px solid var(--bdr);border-radius:5px;background:transparent;color:var(--muted);cursor:pointer;font-size:12px;font-family:inherit;transition:all .12s;line-height:1.4}
.pag-btn:hover{background:rgba(255,255,255,.07);color:var(--text)}
.pag-btn.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.pag-sep{color:var(--muted);font-size:12px;padding:0 2px}
.pag-info{margin-left:auto;font-size:11px;color:var(--muted)}
</style>
</head>
<body>
<!-- Sidebar -->
<nav class="sb">
  <div class="sb-logo">
    <div class="logo-box">&#x2694;</div>
    <span>BNetServer</span>
  </div>
  <div class="nav-sec">
    <div class="nav-lbl">Panel de Control</div>
    <div class="nav-link active" data-page="dashboard"><span class="ic">&#x229E;</span>Resumen</div>
    <div class="nav-link" data-page="status"><span class="ic">&#x25CE;</span>Estado del Servidor</div>
  </div>
  <div class="nav-sec">
    <div class="nav-lbl">Gestion</div>
    <div class="nav-link" data-page="accounts"><span class="ic">&#x1F464;</span>Cuentas</div>
    <div class="nav-link" data-page="players"><span class="ic">&#x1F3AE;</span>Jugadores</div>
    <div class="nav-link" data-page="realms"><span class="ic">&#x1F30D;</span>Reinos</div>
    <div class="nav-link" data-page="rollback"><span class="ic">&#x1F504;</span>Rollback</div>
    <div class="nav-link" data-page="chatmon"><span class="ic">&#x1F4AC;</span>Chat Monitor</div>
    <div class="nav-link" data-page="news"><span class="ic">&#x1F4F0;</span>Noticias</div>
    <div class="nav-link" data-page="logs"><span class="ic">&#x1F4CB;</span>Logs <span class="badge-live">EN VIVO</span></div>
  </div>
  <div class="nav-sec">
    <div class="nav-lbl">Sistema</div>
    <div class="nav-link" data-page="maintenance"><span class="ic">&#x1F6A7;</span>Mantenimiento</div>
    <div class="nav-link" data-page="config"><span class="ic">&#x2699;</span>Configuracion</div>
    <div class="nav-link" data-page="security"><span class="ic">&#x1F512;</span>Seguridad</div>
  </div>
</nav>
<!-- Main -->
<div class="main">
  <div class="hdr">
    <div>
      <div class="hdr-title" id="pg-title">Resumen</div>
      <div class="hdr-sub" id="pg-sub">Vista general del servidor</div>
    </div>
    <div class="hdr-acts">
      <div class="hdr-usr"><span class="u-name">Administrador</span><span class="u-role">SuperAdmin</span></div>
      <div class="avatar">A</div>
    </div>
  </div>
  <div class="content">

    <!-- ===================== PAGE: DASHBOARD ===================== -->
    <div id="pg-dashboard" class="page active">
      <div class="stat-grid">
        <div class="stat-card">
          <div class="si"><div class="lbl">Estado del Servidor</div><div class="val" id="s-status" style="font-size:16px">&#x2014;</div><div class="sub" id="s-sub">Verificando...</div></div>
          <div class="ico ico-g">&#x1F6E1;</div>
        </div>
        <div class="stat-card">
          <div class="si"><div class="lbl">Sesiones Battle.net</div><div class="val" id="s-sess">0</div><div class="sub" style="color:var(--muted)">Conexiones activas</div></div>
          <div class="ico ico-b">&#x1F465;</div>
        </div>
        <div class="stat-card">
          <div class="si"><div class="lbl">Reinos Activos</div><div class="val" id="s-realms">&#x2014;</div><div class="sub" id="s-realms-sub" style="color:var(--muted)">Cargando...</div></div>
          <div class="ico ico-p">&#x1F30D;</div>
        </div>
        <div class="stat-card">
          <div class="si"><div class="lbl">Tiempo de Actividad</div><div class="val" style="font-size:18px" id="s-uptime">&#x2014;</div><div class="sub" style="color:var(--muted)">Desde el inicio</div></div>
          <div class="ico ico-y">&#x23F1;</div>
        </div>
      </div>
      <div class="mid-grid">
        <div class="card">
          <div class="card-hdr"><span class="card-ttl">Actividad de Sesiones (24h)</span></div>
          <canvas id="actChart" height="140"></canvas>
        </div>
        <div class="card">
          <div class="card-hdr"><span class="card-ttl">Informacion del Servidor</span></div>
          <div class="info-row"><span class="k">Version</span><span id="i-ver">&#x2014;</span></div>
          <div class="info-row"><span class="k">Puerto BNet</span><span id="i-bnet">&#x2014;</span></div>
          <div class="info-row"><span class="k">Puerto HTTP</span><span id="i-http">&#x2014;</span></div>
          <div class="info-row"><span class="k">Puerto TACT</span><span id="i-tact">&#x2014;</span></div>
          <div class="info-row"><span class="k">Puerto Admin</span><span id="i-admin">&#x2014;</span></div>
          <div class="info-row"><span class="k">Inicio</span><span id="i-start">&#x2014;</span></div>
          <div class="info-row">
            <div><span class="k">Sesiones</span><div class="prog-bar"><div class="prog-fill" id="sess-bar" style="width:0%"></div></div></div>
            <span id="sess-pct" style="font-size:12px">0</span>
          </div>
        </div>
      </div>
      <div class="bot-grid">
        <div class="log-card">
          <div class="card-hdr"><span class="card-ttl">Actividad Reciente</span><span style="font-size:11px;color:var(--green)"><span class="live-dot"></span>En vivo</span></div>
          <div class="log-body" id="dash-log-list" style="max-height:240px"></div>
        </div>
        <div class="card">
          <div class="card-hdr"><span class="card-ttl">Reinos</span></div>
          <div id="dash-realm-list"></div>
        </div>
      </div>
      <div class="qa-grid">
        <div class="qa-card"><div class="qa-ico qa-ico-b">&#x1F464;</div><h4>Cuentas</h4><p>Gestiona cuentas de jugadores</p><button class="btn btn-outline" style="margin-top:4px" onclick="nav('accounts')">Gestionar</button></div>
        <div class="qa-card"><div class="qa-ico qa-ico-p">&#x1F30D;</div><h4>Reinos</h4><p>Configura y gestiona reinos</p><button class="btn btn-outline" style="margin-top:4px" onclick="nav('realms')">Gestionar</button></div>
        <div class="qa-card"><div class="qa-ico qa-ico-y">&#x1F4CB;</div><h4>Ver Logs</h4><p>Revisa los logs del servidor</p><button class="btn btn-outline" style="margin-top:4px" onclick="nav('logs')">Ver Logs</button></div>
        <div class="qa-card"><div class="qa-ico qa-ico-r">&#x26A0;</div><h4>Detener</h4><p>Detiene el servidor de forma segura</p><button class="btn btn-danger" style="margin-top:4px" onclick="stopServer()">Detener</button></div>
        <div class="qa-card"><div class="qa-ico qa-ico-g">&#x2699;</div><h4>Configuracion</h4><p>Ajustes del servidor BNetServer</p><button class="btn btn-outline" style="margin-top:4px" onclick="nav('config')">Ver Config</button></div>
      </div>
    </div>

    <!-- ===================== PAGE: STATUS ===================== -->
    <div id="pg-status" class="page">
      <div class="pg-hdr"><div><h1>Estado del Servidor</h1><p>Informacion detallada del estado actual</p></div></div>
      <div class="stat-grid">
        <div class="stat-card"><div class="si"><div class="lbl">Estado</div><div class="val" id="st-status" style="font-size:16px">&#x2014;</div><div class="sub" id="st-sub"></div></div><div class="ico ico-g">&#x1F6E1;</div></div>
        <div class="stat-card"><div class="si"><div class="lbl">Sesiones</div><div class="val" id="st-sess">0</div><div class="sub" style="color:var(--muted)">Conexiones Battle.net</div></div><div class="ico ico-b">&#x1F465;</div></div>
        <div class="stat-card"><div class="si"><div class="lbl">Uptime</div><div class="val" id="st-uptime" style="font-size:18px">&#x2014;</div><div class="sub" style="color:var(--muted)">Tiempo activo</div></div><div class="ico ico-y">&#x23F1;</div></div>
        <div class="stat-card"><div class="si"><div class="lbl">Version</div><div class="val" id="st-ver" style="font-size:13px;margin-top:4px">&#x2014;</div><div class="sub" style="color:var(--muted)">Build</div></div><div class="ico ico-p">&#x1F4E6;</div></div>
      </div>
      <div class="mid-grid">
        <div class="card"><div class="card-hdr"><span class="card-ttl">Puertos de Red</span></div>
          <div class="info-row"><span class="k">Battle.net</span><span id="st-bnet" class="mono">&#x2014;</span></div>
          <div class="info-row"><span class="k">REST Login</span><span id="st-http" class="mono">&#x2014;</span></div>
          <div class="info-row"><span class="k">TACT CDN</span><span id="st-tact" class="mono">&#x2014;</span></div>
          <div class="info-row"><span class="k">Admin Panel</span><span id="st-admin" class="mono">&#x2014;</span></div>
        </div>
        <div class="card"><div class="card-hdr"><span class="card-ttl">Acciones Rapidas</span></div>
          <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px">
            <button class="btn btn-outline" onclick="nav('logs')">&#x1F4CB; Ver Logs en Vivo</button>
            <button class="btn btn-outline" onclick="nav('realms')">&#x1F30D; Ver Reinos</button>
            <button class="btn btn-outline" onclick="nav('accounts')">&#x1F464; Gestionar Cuentas</button>
            <button class="btn btn-danger" onclick="stopServer()">&#x25A0; Detener Servidor</button>
          </div>
        </div>
      </div>
    </div>

    <!-- ===================== PAGE: ACCOUNTS ===================== -->
    <div id="pg-accounts" class="page">
      <div class="pg-hdr">
        <div><h1>Gestion de Cuentas</h1><p>Lista y administracion de cuentas Battle.net</p></div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-success" onclick="openCreateModal()">&#x2B; Nueva Cuenta</button>
          <button class="btn btn-primary" onclick="loadAccounts(0,'')">&#x21BB; Actualizar</button>
        </div>
      </div>
      <div class="toolbar">
        <div class="search-box">
          <span>&#x1F50D;</span>
          <input type="text" id="acc-q" placeholder="Buscar por usuario o email..." onkeydown="if(event.key==='Enter')loadAccounts(0,this.value)">
        </div>
        <button class="btn btn-primary" onclick="loadAccounts(0,document.getElementById('acc-q').value)">Buscar</button>
      </div>
      <div class="card" style="overflow:hidden;padding:0">
        <table class="data-table">
          <thead><tr><th>ID</th><th>Usuario</th><th>Email</th><th>Ultima IP</th><th>Ultimo Acceso</th><th>Estado</th><th>Acciones</th></tr></thead>
          <tbody id="acc-tbody"><tr><td colspan="7" style="text-align:center;padding:30px;color:var(--muted)">Cargando cuentas...</td></tr></tbody>
        </table>
      </div>
      <div id="acc-pager" style="display:flex;align-items:center;gap:8px;margin-top:12px;flex-wrap:wrap"></div>
    </div>

    <!-- ===================== PAGE: REALMS ===================== -->
    <div id="pg-realms" class="page">
      <div class="pg-hdr">
        <div><h1>Gestion de Reinos</h1><p>Estado y control de los reinos del servidor</p></div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-outline" onclick="loadRealmsPage()">&#x21BB; Actualizar</button>
          <button class="btn btn-primary" onclick="openAddRealmModal()">&#x2B; Añadir Reino</button>
        </div>
      </div>
      <div id="realm-grid" class="realm-grid"></div>
    </div>

    <!-- ===================== PAGE: LOGS ===================== -->
    <div id="pg-logs" class="page">
      <div class="pg-hdr"><div><h1>Logs del Servidor</h1><p>Registro de actividad en tiempo real</p></div></div>
      <div class="log-page-wrap">
        <div class="log-page-hdr">
          <button class="filter-btn active" data-level="ALL" onclick="setLvl(this)">Todo</button>
          <button class="filter-btn" data-level="INFO" onclick="setLvl(this)">INFO</button>
          <button class="filter-btn" data-level="WARN" onclick="setLvl(this)">WARN</button>
          <button class="filter-btn" data-level="ERROR" onclick="setLvl(this)">ERROR</button>
          <button class="filter-btn" data-level="FATAL" onclick="setLvl(this)">FATAL</button>
          <button class="filter-btn" data-level="DEBUG" onclick="setLvl(this)">DEBUG</button>
          <div class="search-box" style="max-width:260px;margin-left:8px">
            <span>&#x1F50D;</span>
            <input type="text" id="log-search" placeholder="Filtrar texto..." oninput="renderFullLogs()">
          </div>
          <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
            <label style="font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px;cursor:pointer">
              <input type="checkbox" id="log-scroll" checked onchange="logAutoScroll=this.checked"> Auto-scroll
            </label>
            <button class="btn btn-outline btn-sm" onclick="clearFullLogs()">Limpiar</button>
          </div>
        </div>
        <div class="log-full" id="log-full"></div>
      </div>
    </div>

    <!-- ===================== PAGE: MAINTENANCE ===================== -->
    <div id="pg-maintenance" class="page">
      <div class="pg-hdr"><div><h1>Modo Mantenimiento</h1><p>Activa el mantenimiento para bloquear el acceso de jugadores</p></div></div>
      <div id="maint-banner" class="maint-banner off">
        <div class="maint-ico" id="maint-ico">&#x1F7E2;</div>
        <div class="maint-info">
          <h2 id="maint-title">Servidor abierto</h2>
          <p id="maint-desc">Todos los jugadores pueden acceder al servidor normalmente.</p>
        </div>
        <div style="display:flex;flex-direction:column;align-items:center;gap:10px">
          <div class="toggle-wrap" onclick="toggleMaintenance()" id="maint-toggle" style="flex-direction:column">
            <div class="toggle-track" id="toggle-track"><div class="toggle-thumb"></div></div>
            <span class="toggle-lbl" id="toggle-lbl" style="font-size:12px;color:var(--muted)">Desactivado</span>
          </div>
          <button class="btn btn-sm btn-outline" onclick="loadMaintenance()">&#x21BB; Actualizar</button>
        </div>
      </div>
      <div class="card" style="margin-bottom:14px">
        <div class="card-hdr"><span class="card-ttl">Que hace el modo mantenimiento</span></div>
        <div class="info-row"><span class="k">Jugadores activos</span><span>Se expulsan del servidor inmediatamente (GMs nivel 1+ no son afectados)</span></div>
        <div class="info-row"><span class="k">Nuevos logins</span><span>Se bloquean para cuentas sin nivel GM (los GMs pueden seguir accediendo)</span></div>
        <div class="info-row"><span class="k">GMs (nivel &ge; 1)</span><span>No se ven afectados: pueden entrar y jugar normalmente</span></div>
        <div class="info-row" style="border-bottom:none"><span class="k">Reactivacion</span><span>Desactivar el modo mantenimiento restaura el acceso para todos</span></div>
      </div>
    </div>

    <!-- ===================== PAGE: CONFIG ===================== -->
    <div id="pg-config" class="page">
      <div class="pg-hdr"><div><h1>Configuracion del Servidor</h1><p>Valores de configuracion actuales (solo lectura)</p></div></div>
      <div id="config-content"></div>
    </div>

    <!-- ===================== PAGE: SECURITY ===================== -->
    <div id="pg-security" class="page">
      <div class="pg-hdr"><div><h1>Seguridad</h1><p>Cuentas baneadas y gestion de seguridad</p></div></div>
      <div class="toolbar">
        <div class="search-box">
          <span>&#x1F50D;</span>
          <input type="text" id="ban-q" placeholder="Buscar cuentas baneadas..." onkeydown="if(event.key==='Enter')loadBanned(0,this.value)">
        </div>
        <button class="btn btn-primary" onclick="loadBanned(0,document.getElementById('ban-q').value)">Buscar</button>
      </div>
      <div class="card" style="overflow:hidden;padding:0">
        <table class="data-table">
          <thead><tr><th>Cuenta</th><th>Razon</th><th>Baneado por</th><th>Fecha Ban</th><th>Expira</th><th>Acciones</th></tr></thead>
          <tbody id="ban-tbody"><tr><td colspan="6" style="text-align:center;padding:30px;color:var(--muted)">Cargando bans...</td></tr></tbody>
        </table>
      </div>
      <div id="ban-pager" style="display:flex;align-items:center;gap:8px;margin-top:12px;flex-wrap:wrap"></div>
    </div>

    <!-- ===================== PAGE: PLAYERS ===================== -->
    <div id="pg-players" class="page">
      <div class="pg-hdr">
        <div><h1>Jugadores</h1><p>Gestiona y busca jugadores del servidor</p></div>
        <div style="display:flex;align-items:center;gap:8px">
          <span id="players-count" style="font-size:12px;color:var(--muted)"></span>
          <button class="btn btn-outline" style="font-size:11px" id="btn-refresh-players" onclick="refreshPlayersTab()">&#x21BB; Actualizar</button>
        </div>
      </div>
      <!-- Tab bar -->
      <div class="pg-tab-bar">
        <div class="pg-tab active" id="ptab-online" onclick="switchPlayersTab('online')">&#x1F7E2; En Linea</div>
        <div class="pg-tab" id="ptab-offline" onclick="switchPlayersTab('offline')">&#x26AA; Desconectados</div>
      </div>
      <!-- Online section -->
      <div id="psec-online">
        <div class="toolbar">
          <div class="search-box">
            <span style="color:var(--muted);font-size:14px">&#x1F50D;</span>
            <input type="text" id="players-search" placeholder="Buscar jugador..." oninput="renderPlayers()" autocomplete="off">
          </div>
          <button class="filter-btn active" onclick="setFactionFilter(0,this)">Todos</button>
          <button class="filter-btn" onclick="setFactionFilter(1,this)">Alianza</button>
          <button class="filter-btn" onclick="setFactionFilter(2,this)">Horda</button>
        </div>
        <div id="players-grid" class="player-grid">
          <p style="color:var(--muted);padding:20px">Cargando jugadores...</p>
        </div>
      </div>
      <!-- Offline section -->
      <div id="psec-offline" style="display:none">
        <div class="toolbar">
          <div class="search-box" style="flex:1;max-width:380px">
            <span style="color:var(--muted);font-size:14px">&#x1F50D;</span>
            <input type="text" id="offline-search" placeholder="Nombre (vacio = todos)..." autocomplete="off"
              oninput="offlineInputHandler()"
              onkeydown="if(event.key==='Enter'){clearTimeout(_offlineT);doOfflineSearch();}">
          </div>
          <button class="btn btn-primary" onclick="doOfflineSearch()">Buscar</button>
        </div>
        <div id="offline-grid" class="player-grid">
          <p class="offline-hint">Escribe un nombre o deja vacio y pulsa Buscar para ver todos.</p>
        </div>
        <div id="offline-pagination"></div>
      </div>
    </div>

  </div><!-- end .content -->
</div><!-- end .main -->

<!-- Ban Modal -->
<div class="modal-overlay" id="ban-modal">
  <div class="modal">
    <h2>Banear Cuenta</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:16px">Cuenta: <strong id="ban-name" style="color:var(--text)"></strong></p>
    <div class="modal-row">
      <label>Razon del ban</label>
      <input type="text" id="ban-reason" placeholder="Especifica el motivo...">
    </div>
    <div class="modal-row">
      <label>Duracion</label>
      <select id="ban-dur">
        <option value="0">Permanente</option>
        <option value="3600">1 hora</option>
        <option value="21600">6 horas</option>
        <option value="86400">24 horas</option>
        <option value="259200">3 dias</option>
        <option value="604800">7 dias</option>
        <option value="2592000">30 dias</option>
      </select>
    </div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeBanModal()">Cancelar</button>
      <button class="btn btn-danger" onclick="submitBan()">Banear</button>
    </div>
  </div>
</div>

<!-- Create Account Modal -->
<div class="modal-overlay" id="create-modal">
  <div class="modal">
    <h2>Crear Nueva Cuenta</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:16px">El email sera el usuario de login Battle.net</p>
    <div class="modal-row">
      <label>Email <span style="color:var(--muted)">(login Battle.net)</span></label>
      <input type="email" id="create-email" placeholder="usuario@ejemplo.com">
    </div>
    <div class="modal-row">
      <label>Contrasena</label>
      <input type="password" id="create-pass" placeholder="Minimo 1 caracter">
    </div>
    <div class="modal-row">
      <label>Confirmar contrasena</label>
      <input type="password" id="create-pass2" placeholder="Repite la contrasena">
    </div>
    <div id="create-error" style="color:var(--red);font-size:12px;margin-top:-6px;display:none"></div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeCreateModal()">Cancelar</button>
      <button class="btn btn-success" onclick="submitCreateAccount()">Crear Cuenta</button>
    </div>
  </div>
</div>

<!-- Edit Account Modal -->
<div class="modal-overlay" id="edit-modal">
  <div class="modal" style="max-width:520px">
    <h2>Editar Cuenta</h2>
    <p style="color:var(--muted);font-size:12px;margin-bottom:16px">Cuenta: <strong id="edit-name" style="color:var(--text)"></strong> <span style="color:var(--muted)">(ID: <span id="edit-id-lbl"></span>)</span></p>
    <div class="modal-row">
      <label>Email <span style="color:var(--muted)">(login Battle.net)</span></label>
      <input type="email" id="edit-email" placeholder="usuario@ejemplo.com">
    </div>
    <div class="modal-row">
      <label>Nueva contrasena <span style="color:var(--muted)">(dejar vacio para no cambiar)</span></label>
      <input type="password" id="edit-pass" placeholder="Nueva contrasena...">
    </div>
    <div class="modal-row">
      <label>Confirmar contrasena</label>
      <input type="password" id="edit-pass2" placeholder="Repite la nueva contrasena...">
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="modal-row" style="margin-bottom:0">
        <label>Expansion</label>
        <select id="edit-exp">
          <option value="0">Classic (0)</option>
          <option value="1">The Burning Crusade (1)</option>
          <option value="2">Wrath of the Lich King (2)</option>
        </select>
      </div>
      <div class="modal-row" style="margin-bottom:0">
        <label>Nivel GM</label>
        <select id="edit-gm">
          <option value="0">Jugador (0)</option>
          <option value="1">Moderador (1)</option>
          <option value="2">Game Master (2)</option>
          <option value="3">Administrador (3)</option>
        </select>
      </div>
    </div>
    <div class="modal-row" style="margin-top:12px">
      <label>Rol RBAC <span style="color:var(--muted);font-size:11px">(permisos en juego)</span></label>
      <select id="edit-rbac">
        <option value="0">Sin rol adicional (0)</option>
        <option value="199">Jugador (199)</option>
        <option value="198">Moderador (198)</option>
        <option value="197">Game Master (197)</option>
        <option value="196">Administrador (196)</option>
      </select>
    </div>
    <div id="edit-error" style="color:var(--red);font-size:12px;margin-top:10px;display:none"></div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeEditModal()">Cancelar</button>
      <button class="btn btn-primary" onclick="submitEditAccount()">Guardar Cambios</button>
    </div>
  </div>
</div>

<!-- Add Realm Modal -->
<div class="modal-overlay" id="add-realm-modal">
  <div class="modal" style="max-width:500px">
    <h2>Añadir Reino</h2>
    <div class="modal-row"><label>Nombre</label><input type="text" id="ar-name" placeholder="Mi Reino" maxlength="32"></div>
    <div class="modal-row"><label>Direccion IP Externa</label><input type="text" id="ar-addr" placeholder="127.0.0.1"></div>
    <div class="modal-row"><label>Direccion IP Local</label><input type="text" id="ar-laddr" placeholder="127.0.0.1"></div>
    <div class="modal-row"><label>Puerto</label><input type="number" id="ar-port" value="8085" min="1" max="65535"></div>
    <div class="modal-row">
      <label>Tipo</label>
      <select id="ar-type">
        <option value="0">Normal</option>
        <option value="1">PvP</option>
        <option value="6">RP</option>
        <option value="8">RP-PvP</option>
      </select>
    </div>
    <div class="modal-row">
      <label>Nivel de acceso minimo</label>
      <select id="ar-sec">
        <option value="0">Jugador (todos)</option>
        <option value="1">Moderador</option>
        <option value="2">Game Master</option>
        <option value="3">Administrador</option>
      </select>
    </div>
    <div id="ar-error" style="display:none;color:var(--red);font-size:12px;margin-top:8px"></div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeAddRealmModal()">Cancelar</button>
      <button class="btn btn-primary" id="ar-submit" onclick="submitAddRealm()">Crear Reino</button>
    </div>
  </div>
</div>

<!-- Edit Realm Modal -->
<div class="modal-overlay" id="edit-realm-modal">
  <div class="modal" style="max-width:500px">
    <h2>Editar Reino</h2>
    <input type="hidden" id="er-id">
    <div class="modal-row"><label>Nombre</label><input type="text" id="er-name" maxlength="32"></div>
    <div class="modal-row"><label>Direccion IP Externa</label><input type="text" id="er-addr"></div>
    <div class="modal-row"><label>Direccion IP Local</label><input type="text" id="er-laddr"></div>
    <div class="modal-row"><label>Puerto</label><input type="number" id="er-port" min="1" max="65535"></div>
    <div class="modal-row">
      <label>Tipo</label>
      <select id="er-type">
        <option value="0">Normal</option>
        <option value="1">PvP</option>
        <option value="6">RP</option>
        <option value="8">RP-PvP</option>
      </select>
    </div>
    <div class="modal-row">
      <label>Nivel de acceso minimo</label>
      <select id="er-sec">
        <option value="0">Jugador (todos)</option>
        <option value="1">Moderador</option>
        <option value="2">Game Master</option>
        <option value="3">Administrador</option>
      </select>
    </div>
    <div id="er-error" style="display:none;color:var(--red);font-size:12px;margin-top:8px"></div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeEditRealmModal()">Cancelar</button>
      <button class="btn btn-primary" id="er-submit" onclick="submitEditRealm()">Guardar Cambios</button>
    </div>
  </div>
</div>

<!-- RBAC Reload Confirm Modal -->
<div class="modal-overlay" id="rbac-reload-modal">
  <div class="modal" style="max-width:420px">
    <h2>Recargar RBAC</h2>
    <p style="color:var(--muted);font-size:13px;margin-bottom:16px">Los cambios de RBAC se han guardado.<br>El servidor esta encendido. <strong style="color:var(--text)">Deseas aplicar los cambios ahora?</strong><br><span style="font-size:11px;color:var(--muted)">Si no se recarga, surtiran efecto en el proximo login del jugador.</span></p>
    <div id="rbac-reload-result" style="display:none;padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px"></div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeRbacReloadModal()">No, mas tarde</button>
      <button class="btn btn-primary" id="rbac-reload-btn" onclick="doRbacReload()">Si, recargar ahora</button>
    </div>
  </div>
</div>

<!-- Player Detail Modal -->
<div class="modal-overlay" id="player-modal">
  <div class="modal detail-modal">
    <div class="detail-head">
      <div id="pm-avatar" class="pc-avatar" style="font-size:22px;flex-shrink:0">&#x1F464;</div>
      <div style="flex:1;min-width:0">
        <div id="pm-name" style="font-size:16px;font-weight:700"></div>
        <div id="pm-sub" style="font-size:12px;color:var(--muted);margin-top:2px"></div>
      </div>
      <div id="pm-guild-badge" style="font-size:12px;text-align:right;margin-left:8px"></div>
      <button class="btn btn-outline" style="margin-left:12px;padding:5px 11px;flex-shrink:0" onclick="closePlayerModal()">&#x2715;</button>
    </div>
    <div class="detail-tabs">
      <div class="detail-tab active" data-tab="info">Informacion</div>
      <div class="detail-tab" data-tab="ach">Logros</div>
      <div class="detail-tab" data-tab="prof">Profesiones</div>
      <div class="detail-tab" data-tab="inv">Inventario</div>
      <div class="detail-tab" data-tab="bank">Banco</div>
      <div class="detail-tab" data-tab="mail">Correo</div>
      <div class="detail-tab" data-tab="guild">Hermandad</div>
    </div>
    <div class="detail-body">
      <div id="pm-info"  class="tab-pane active"></div>
      <div id="pm-ach"   class="tab-pane"></div>
      <div id="pm-prof"  class="tab-pane"></div>
      <div id="pm-inv"   class="tab-pane"></div>
      <div id="pm-bank"  class="tab-pane"></div>
      <div id="pm-mail"  class="tab-pane"></div>
      <div id="pm-guild" class="tab-pane"></div>
    </div>
  </div>
</div>

    <!-- ===================== PAGE: ROLLBACK ===================== -->
    <div id="pg-rollback" class="page">
      <div class="pg-hdr">
        <div><h1>Rollback / Snapshots</h1><p>Copias de seguridad y restauracion de personajes</p></div>
      </div>
      <!-- Scope + search -->
      <div class="card" style="margin-bottom:14px;padding:14px 16px">
        <div style="display:flex;gap:24px;margin-bottom:12px;font-size:13px;flex-wrap:wrap">
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="radio" name="rb-scope" value="char" checked onchange="rbScopeChange()"> Por personaje
          </label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="radio" name="rb-scope" value="account" onchange="rbScopeChange()"> Por cuenta
          </label>
          <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
            <input type="radio" name="rb-scope" value="ip" onchange="rbScopeChange()"> Por IP
          </label>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <div class="search-box" style="flex:0 0 auto;width:320px">
            <span>&#x1F50D;</span>
            <input type="text" id="rb-inp" placeholder="Nombre del personaje..."
              onkeydown="if(event.key==='Enter')doRbSearch()">
          </div>
          <button class="btn btn-primary" onclick="doRbSearch()">Buscar</button>
        </div>
      </div>
      <!-- Character results -->
      <div id="rb-chars-wrap" style="display:none;margin-bottom:14px">
        <div class="card" style="overflow:hidden;padding:0">
          <table class="data-table">
            <thead><tr><th>Personaje</th><th>Nv</th><th>Clase</th><th>Cuenta</th><th>Snapshots</th><th>Acciones</th></tr></thead>
            <tbody id="rb-chars-tbody"></tbody>
          </table>
        </div>
        <div id="rb-bulk-bar" style="display:none;margin-top:10px">
          <button class="btn btn-primary" style="font-size:12px" onclick="doBulkCreateSnapshot()">&#x1F4BE; Snapshot de todos los personajes</button>
        </div>
      </div>
      <!-- Snapshot list for selected target -->
      <div id="rb-snaps-wrap" style="display:none">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
          <div>
            <span style="font-weight:600;font-size:14px" id="rb-snaps-hdr">Snapshots</span>
            <span style="font-size:12px;color:var(--muted);margin-left:8px" id="rb-snaps-sub"></span>
          </div>
          <button class="btn btn-primary" style="font-size:12px" onclick="openRbCreate()">+ Crear Snapshot</button>
        </div>
        <div class="card" style="overflow:hidden;padding:0">
          <table class="data-table">
            <thead><tr><th>Fecha y Hora</th><th>Tipo</th><th>Etiqueta</th><th>Tama&#xF1;o</th><th>Acciones</th></tr></thead>
            <tbody id="rb-snaps-tbody"><tr><td colspan="5" style="text-align:center;padding:20px;color:var(--muted)">Selecciona un personaje arriba</td></tr></tbody>
          </table>
        </div>
        <div id="rb-snaps-pager" style="margin-top:10px"></div>
      </div>
    </div>

    <!-- ===================== PAGE: CHAT MONITOR ===================== -->
    <div id="pg-chatmon" class="page">
      <div class="pg-hdr">
        <div><h1>Monitor de Chat</h1><p>Chat en tiempo real por personaje</p></div>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn btn-outline" style="font-size:12px" onclick="cmClear()">Limpiar</button>
          <button id="cm-toggle-btn" class="btn btn-primary" style="font-size:12px" onclick="cmToggle()">&#x25B6; Iniciar Monitor</button>
        </div>
      </div>
      <!-- Search -->
      <div class="card" style="padding:14px 16px;margin-bottom:14px">
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <div class="search-box" style="flex:1;min-width:220px">
            <span>&#x1F50D;</span>
            <input type="text" id="cm-inp" placeholder="Nombre del personaje..." onkeydown="if(event.key==='Enter')cmSearch()">
          </div>
          <button class="btn btn-primary" onclick="cmSearch()">Buscar</button>
        </div>
        <div id="cm-search-results" style="margin-top:10px"></div>
      </div>
      <!-- Character info + filters -->
      <div id="cm-info-bar" style="display:none;background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:12px 16px;margin-bottom:14px">
        <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
          <div>
            <span id="cm-online-dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);margin-right:6px"></span>
            <strong id="cm-char-name" style="font-size:15px"></strong>
          </div>
          <div style="font-size:12px;color:var(--muted)">Nivel: <strong id="cm-char-level" style="color:var(--text)"></strong></div>
          <div style="font-size:12px;color:var(--muted)">Zona: <strong id="cm-char-zone" style="color:var(--accent)"></strong></div>
          <div style="font-size:12px;color:var(--muted)">Guild: <strong id="cm-char-guild" style="color:var(--green)"></strong></div>
        </div>
        <div style="margin-top:10px;display:flex;gap:12px;flex-wrap:wrap;font-size:12px">
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="say" checked> Say</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="yell" checked> Yell</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="emote" checked> Emote</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="whisper_out" checked> Whisper &#x2192;</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="whisper_in" checked> Whisper &#x2190;</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="guild" checked> Guild</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="officer" checked> Officer</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="party" checked> Party</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="raid" checked> Raid</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="raid_warning" checked> Raid Warning</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="instance" checked> Instancia</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="channel" checked> Canal</label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer"><input type="checkbox" class="cm-filter" value="bg" checked> Battleground</label>
        </div>
      </div>
      <!-- Chat log -->
      <div id="cm-log" style="background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:10px 14px;font-family:monospace;font-size:12px;line-height:1.6;min-height:300px;max-height:60vh;overflow-y:auto">
        <div style="color:var(--muted);padding:20px 0;text-align:center">Busca un personaje y haz click en Iniciar Monitor para ver su chat en tiempo real.</div>
      </div>
    </div>

    <!-- ===================== PAGE: NEWS MANAGEMENT ===================== -->
    <div id="pg-news" class="page">
      <div class="pg-hdr">
        <div><h1>Gestion de Noticias</h1><p>Publicar y editar articulos del portal de usuarios</p></div>
        <button class="btn btn-primary" onclick="newsAdminNew()">&#x2B; Nueva Noticia</button>
      </div>
      <div class="toolbar">
        <div class="search-box" style="max-width:340px">
          <span>&#x1F50D;</span>
          <input type="text" id="na-search" placeholder="Buscar por titulo..." oninput="newsAdminLoad(0)">
        </div>
        <select id="na-filter-cat" onchange="newsAdminLoad(0)" style="background:rgba(255,255,255,.04);border:1px solid var(--bdr);color:var(--text);border-radius:6px;padding:6px 10px;font-size:12px;outline:none">
          <option value="">Todas las categorias</option>
          <option value="general">General</option>
          <option value="parches">Parches</option>
          <option value="eventos">Eventos</option>
          <option value="mantenimiento">Mantenimiento</option>
          <option value="actualizacion">Actualizacion</option>
        </select>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="data-table" id="na-table">
          <thead><tr>
            <th style="width:40px">#</th>
            <th>Titulo</th>
            <th>Categoria</th>
            <th>Autor</th>
            <th>Destacada</th>
            <th>Fecha</th>
            <th style="width:120px">Acciones</th>
          </tr></thead>
          <tbody id="na-tbody"><tr><td colspan="7" style="text-align:center;padding:32px;color:var(--muted)">Cargando...</td></tr></tbody>
        </table>
      </div>
      <div style="display:flex;justify-content:center;margin-top:14px" id="na-pager"></div>
    </div>

<!-- News: Edit/Create modal -->
<div class="modal-overlay" id="modal-news-edit">
  <div class="modal" style="max-width:640px;width:96%">
    <h2 id="ne-title">Nueva Noticia</h2>
    <input type="hidden" id="ne-id" value="0">
    <div class="modal-row">
      <label>Titulo</label>
      <input type="text" id="ne-titletxt" maxlength="255" placeholder="Titulo de la noticia">
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="modal-row">
        <label>Categoria</label>
        <select id="ne-cat">
          <option value="general">General</option>
          <option value="parches">Parches</option>
          <option value="eventos">Eventos</option>
          <option value="mantenimiento">Mantenimiento</option>
          <option value="actualizacion">Actualizacion</option>
        </select>
      </div>
      <div class="modal-row">
        <label>Autor</label>
        <input type="text" id="ne-author" maxlength="100" placeholder="Staff">
      </div>
    </div>
    <div class="modal-row">
      <label>Resumen (excerpt)</label>
      <input type="text" id="ne-summary" maxlength="300" placeholder="Breve descripcion para la lista de noticias">
    </div>
    <div class="modal-row">
      <label>URL de Imagen (opcional)</label>
      <input type="text" id="ne-image" maxlength="500" placeholder="https://...">
    </div>
    <div class="modal-row">
      <label>Contenido completo</label>
      <textarea id="ne-content" rows="8" placeholder="Texto completo del articulo. Se permiten saltos de linea." style="resize:vertical"></textarea>
    </div>
    <div class="modal-row" style="display:flex;align-items:center;gap:8px;margin-bottom:0">
      <input type="checkbox" id="ne-featured">
      <label for="ne-featured" style="margin-bottom:0;text-transform:none;font-size:13px;cursor:pointer">Destacar en el slider de la pagina principal</label>
    </div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="document.getElementById('modal-news-edit').classList.remove('open')">Cancelar</button>
      <button class="btn btn-primary" onclick="newsAdminSave()">Guardar Noticia</button>
    </div>
  </div>
</div>

<!-- Rollback: Confirm restore modal -->
<div class="modal-overlay" id="modal-rb-restore">
  <div class="modal">
    <h2>&#x26A0; Restaurar Snapshot</h2>
    <p style="font-size:13px;margin-bottom:10px">Restaurar el snapshot del <strong id="rb-restore-date"></strong> para <strong id="rb-restore-char"></strong>.</p>
    <div style="background:rgba(255,180,0,.1);border:1px solid rgba(255,180,0,.4);border-radius:6px;padding:10px;font-size:12px;color:var(--yellow);margin-bottom:14px">
      &#x26A0; Esta accion sobreescribira el estado actual del personaje. Si esta conectado sera expulsado automaticamente. La cuenta quedara bloqueada durante el proceso.
    </div>
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;margin-bottom:4px">
      <input type="checkbox" id="rb-auto-bkp" checked> Crear backup automatico antes de restaurar
    </label>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="document.getElementById('modal-rb-restore').classList.remove('open')">Cancelar</button>
      <button class="btn" style="background:var(--red);color:#fff;border:1px solid var(--red)" onclick="confirmRbRestore()">Restaurar</button>
    </div>
  </div>
</div>

<!-- Rollback: Create snapshot modal -->
<div class="modal-overlay" id="modal-rb-create">
  <div class="modal">
    <h2>Crear Snapshot</h2>
    <p style="font-size:12px;color:var(--muted);margin-bottom:14px">Personaje: <strong id="rb-create-charname"></strong></p>
    <div class="modal-row">
      <label>Etiqueta (opcional)</label>
      <input type="text" id="rb-create-label" maxlength="200" placeholder="Ej: antes de raid, copia limpia...">
    </div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="document.getElementById('modal-rb-create').classList.remove('open')">Cancelar</button>
      <button class="btn btn-primary" onclick="confirmRbCreate()">Crear Snapshot</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
// ── State ──────────────────────────────────────────────
var CUR='dashboard', logSeq=0, dashSeq=0, logFilter='ALL', logAutoScroll=true;
var allLogs=[], accCurPage=0, accCurQ='', banCurPage=0, banCurQ='';
var banTargetId=0, banTargetName='';
var dashTimer=0, logTimer=0, statusTimer=0;
var sesHist=new Array(24).fill(0);
var chartCtx=null;

// ── Navigation ──────────────────────────────────────────
var pgMeta={
  dashboard:{title:'Resumen',sub:'Vista general del servidor'},
  status:{title:'Estado del Servidor',sub:'Informacion detallada y puertos'},
  accounts:{title:'Gestion de Cuentas',sub:'Administra cuentas Battle.net'},
  players:{title:'Jugadores en Linea',sub:'Jugadores conectados al servidor'},
  realms:{title:'Gestion de Reinos',sub:'Estado y control de reinos'},
  logs:{title:'Logs del Servidor',sub:'Registro de actividad en tiempo real'},
  maintenance:{title:'Modo Mantenimiento',sub:'Control de acceso al servidor'},
  config:{title:'Configuracion',sub:'Parametros de configuracion actuales'},
  security:{title:'Seguridad',sub:'Cuentas baneadas y seguridad'},
  rollback:{title:'Rollback / Snapshots',sub:'Copias de seguridad y restauracion de personajes'},
  chatmon:{title:'Monitor de Chat',sub:'Chat en tiempo real de personajes'},
  news:{title:'Gestion de Noticias',sub:'Articulos del portal de usuarios'}
};

function nav(page){
  if(!document.getElementById('pg-'+page))return;
  document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
  document.getElementById('pg-'+page).classList.add('active');
  document.querySelectorAll('.nav-link').forEach(function(n){
    n.classList.toggle('active',n.dataset.page===page);
  });
  CUR=page;
  var m=pgMeta[page]||{title:page,sub:''};
  document.getElementById('pg-title').textContent=m.title;
  document.getElementById('pg-sub').textContent=m.sub;
  if(page==='dashboard')   startDash();
  if(page==='status')      startStatus();
  if(page==='accounts')    loadAccounts(0,'');
  if(page==='players')     loadPlayers();
  if(page==='realms')      loadRealmsPage();
  if(page==='logs')        startLogs();
  if(page==='maintenance') loadMaintenance();
  if(page==='config')      loadConfig();
  if(page==='security')    loadBanned(0,'');
  if(page==='rollback')    initRollbackPage();
  if(page==='chatmon')    initChatMonitor();
  if(page==='news')       newsAdminLoad(0);
}

document.querySelectorAll('.nav-link[data-page]').forEach(function(n){
  n.addEventListener('click',function(){nav(this.dataset.page);});
});

// ── Toast ────────────────────────────────────────────────
function toast(msg,type){
  var t=document.getElementById('toast');
  t.textContent=msg; t.className='toast show '+(type||'info');
  clearTimeout(t._t); t._t=setTimeout(function(){t.classList.remove('show');},3500);
}

// ── API ──────────────────────────────────────────────────
function apiFetch(url,opts){
  return fetch(url,opts).then(function(r){
    if(!r.ok)throw new Error('HTTP '+r.status);
    return r.json();
  });
}

// ── Chart ────────────────────────────────────────────────
function drawChart(canvas,data){
  var W=canvas.offsetWidth,H=canvas.offsetHeight||140;
  canvas.width=W; canvas.height=H;
  var c=canvas.getContext('2d');
  var p={t:8,r:8,b:24,l:28},w=W-p.l-p.r,h=H-p.t-p.b;
  var mx=Math.max.apply(null,data.concat([4]));
  c.clearRect(0,0,W,H);
  c.strokeStyle='rgba(255,255,255,.04)'; c.lineWidth=1;
  for(var i=0;i<=4;i++){
    var y=p.t+h*i/4;
    c.beginPath();c.moveTo(p.l,y);c.lineTo(p.l+w,y);c.stroke();
    c.fillStyle='rgba(255,255,255,.25)';c.font='9px Segoe UI';c.textAlign='right';
    c.fillText(Math.round(mx*(4-i)/4),p.l-3,y+3);
  }
  var now=new Date();
  c.textAlign='center';c.fillStyle='rgba(255,255,255,.25)';
  for(var j=0;j<5;j++){
    var x=p.l+w*j/4;
    var hh=new Date(now.getTime()-((4-j)*6*3600000));
    c.fillText(('0'+hh.getHours()).slice(-2)+':00',x,H-3);
  }
  var g=c.createLinearGradient(0,p.t,0,p.t+h);
  g.addColorStop(0,'rgba(79,124,255,.25)');g.addColorStop(1,'rgba(79,124,255,.02)');
  c.beginPath();
  data.forEach(function(v,i){
    var x=p.l+w*i/(data.length-1),y=p.t+h-h*v/mx;
    if(i===0)c.moveTo(x,y);else c.lineTo(x,y);
  });
  c.lineTo(p.l+w,p.t+h);c.lineTo(p.l,p.t+h);c.closePath();
  c.fillStyle=g;c.fill();
  c.beginPath();c.strokeStyle='#4f7cff';c.lineWidth=2;c.lineJoin='round';
  data.forEach(function(v,i){
    var x=p.l+w*i/(data.length-1),y=p.t+h-h*v/mx;
    if(i===0)c.moveTo(x,y);else c.lineTo(x,y);
  });
  c.stroke();
}

// ── Dashboard ────────────────────────────────────────────
function startDash(){
  clearInterval(dashTimer);
  refreshDash();
  dashTimer=setInterval(refreshDash,3000);
}

function refreshDash(){
  apiFetch('/api/status').then(applyStatus).catch(function(){});
  apiFetch('/api/logs?since='+dashSeq).then(function(d){
    if(d.entries&&d.entries.length)applyDashLogs(d.entries);
  }).catch(function(){});
  apiFetch('/api/realms').then(applyDashRealms).catch(function(){});
}

function applyStatus(d){
  var ok=d.running;
  var statEl=function(id){return document.getElementById(id);};
  var setEl=function(id,v){var e=statEl(id);if(e)e.textContent=v;};
  var setColor=function(id,c){var e=statEl(id);if(e)e.style.color=c;};

  setEl('s-status',ok?'En linea':'Detenido'); setColor('s-status',ok?'var(--green)':'var(--red)');
  setEl('s-sub',ok?'Funcionando correctamente':'Servidor detenido'); setColor('s-sub',ok?'var(--green)':'var(--red)');
  setEl('s-sess',d.sessions); setEl('s-uptime',d.uptime);
  setEl('i-ver',d.version); setEl('i-bnet',d.bnetPort); setEl('i-http',d.httpPort);
  setEl('i-tact',d.tactPort>0?d.tactPort:'N/A'); setEl('i-start',d.startTime||'--');
  var adminPort=location.port||window.location.port;
  setEl('i-admin',adminPort||'--');
  var pct=Math.min(d.sessions*10,100);
  var bar=document.getElementById('sess-bar');if(bar)bar.style.width=pct+'%';
  setEl('sess-pct',d.sessions);
  sesHist.shift();sesHist.push(d.sessions);
  var cv=document.getElementById('actChart');if(cv)drawChart(cv,sesHist);
  // Status page
  setEl('st-status',ok?'En linea':'Detenido'); setColor('st-status',ok?'var(--green)':'var(--red)');
  setEl('st-sub',ok?'Operativo':'Detenido'); setColor('st-sub',ok?'var(--green)':'var(--red)');
  setEl('st-sess',d.sessions); setEl('st-uptime',d.uptime); setEl('st-ver',d.version);
  setEl('st-bnet',d.bnetPort); setEl('st-http',d.httpPort);
  setEl('st-tact',d.tactPort>0?d.tactPort:'N/A'); setEl('st-admin',adminPort||'--');
}

function applyDashLogs(entries){
  var list=document.getElementById('dash-log-list');
  if(!list)return;
  var atBot=list.scrollHeight-list.scrollTop<=list.clientHeight+30;
  entries.forEach(function(e){
    if(e.seq>dashSeq)dashSeq=e.seq;
    if(e.seq>logSeq)logSeq=e.seq;
    allLogs.push(e);
    var div=document.createElement('div');div.className='log-entry';
    var lm={INFO:'lv-info',WARN:'lv-warn',ERROR:'lv-error',FATAL:'lv-fatal',DEBUG:'lv-debug',TRACE:'lv-debug'};
    div.innerHTML='<span class="log-lvl '+(lm[e.level]||'lv-debug')+'">'+e.level+'</span>'
      +'<span class="log-txt">'+esc(e.text)+'</span><span class="log-time">'+e.time+'</span>';
    list.appendChild(div);
  });
  while(list.children.length>80)list.removeChild(list.firstChild);
  if(atBot)list.scrollTop=list.scrollHeight;
  while(allLogs.length>2000)allLogs.shift();
}

function applyDashRealms(d){
  var el=document.getElementById('s-realms'),sl=document.getElementById('s-realms-sub');
  var list=document.getElementById('dash-realm-list');
  if(!d.realms)return;
  if(el)el.textContent=d.realms.length;
  var online=d.realms.filter(function(r){return r.online;}).length;
  if(sl)sl.textContent=online+' en linea';
  if(!list)return;
  list.innerHTML='';
  if(!d.realms.length){list.innerHTML='<p style="color:var(--muted);font-size:12px;padding:8px 0">Sin reinos</p>';return;}
  d.realms.forEach(function(r){
    var row=document.createElement('div');row.className='realm-row';
    row.innerHTML='<div style="font-weight:500;font-size:13px">'+esc(r.name)+'</div>'
      +'<div class="rstatus"><div class="rc-dot '+(r.online?'dot-g':'dot-r')+'"></div>'
      +'<span style="color:'+(r.online?'var(--green)':'var(--muted)')+'">'+
      (r.online?'Online':'Offline')+'</span></div>';
    list.appendChild(row);
  });
}

// ── Status page ──────────────────────────────────────────
function startStatus(){
  clearInterval(statusTimer);
  apiFetch('/api/status').then(applyStatus).catch(function(){});
  statusTimer=setInterval(function(){apiFetch('/api/status').then(applyStatus).catch(function(){});},5000);
}

// ── Accounts ─────────────────────────────────────────────
function loadAccounts(page,q){
  accCurPage=page; accCurQ=q;
  var tbody=document.getElementById('acc-tbody');
  tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--muted)">Cargando...</td></tr>';
  var url='/api/accounts?page='+page;
  if(q)url+='&q='+encodeURIComponent(q);
  apiFetch(url).then(function(d){
    tbody.innerHTML='';
    if(!d.accounts||!d.accounts.length){
      tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--muted)">Sin resultados</td></tr>';
      renderAccPager(0,0,0);return;
    }
    d.accounts.forEach(function(a){
      var tr=document.createElement('tr');
      var badge=a.banned?'<span class="badge badge-red">Baneado</span>':'<span class="badge badge-green">Activo</span>';
      var banBtn=a.banned
        ?'<button class="btn btn-sm btn-success" onclick="unbanAcc('+a.id+',\''+esc(a.username)+'\')">Desbanear</button>'
        :'<button class="btn btn-sm btn-danger" onclick="openBanModal('+a.id+',\''+esc(a.username)+'\')">Banear</button>';
      var btn='<div style="display:flex;gap:4px">'
        +'<button class="btn btn-sm btn-primary" onclick="openEditModal('+a.id+',\''+esc(a.username)+'\')">Editar</button>'
        +banBtn+'</div>';
      tr.innerHTML='<td>'+a.id+'</td>'
        +'<td style="font-weight:500">'+esc(a.username)+'</td>'
        +'<td class="muted">'+esc(a.email)+'</td>'
        +'<td class="mono muted">'+esc(a.lastIp||'--')+'</td>'
        +'<td class="muted">'+esc(a.lastLogin||'--')+'</td>'
        +'<td>'+badge+'</td>'
        +'<td>'+btn+'</td>';
      tbody.appendChild(tr);
    });
    renderAccPager(d.page||0,d.pages||1,d.total||0);
  }).catch(function(e){
    tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:28px;color:var(--red)">Error al cargar: '+e.message+'</td></tr>';
  });
}

function renderAccPager(page,pages,total){
  var p=document.getElementById('acc-pager'); p.innerHTML='';
  var info=document.createElement('span');info.className='pager-info';
  info.textContent='Total: '+total+' cuentas';
  p.appendChild(info);
  if(pages>1){
    var wrap=document.createElement('div');wrap.className='pager';
    if(page>0){var b=document.createElement('button');b.className='btn btn-outline btn-sm';b.textContent='< Anterior';b.onclick=function(){loadAccounts(page-1,accCurQ);};wrap.appendChild(b);}
    var start=Math.max(0,page-2),end=Math.min(pages-1,page+2);
    for(var i=start;i<=end;i++){(function(idx){var b=document.createElement('button');b.className='btn btn-sm '+(idx===page?'btn-primary':'btn-outline');b.textContent=idx+1;b.onclick=function(){loadAccounts(idx,accCurQ);};wrap.appendChild(b);})(i);}
    if(page<pages-1){var b2=document.createElement('button');b2.className='btn btn-outline btn-sm';b2.textContent='Siguiente >';b2.onclick=function(){loadAccounts(page+1,accCurQ);};wrap.appendChild(b2);}
    p.prepend(wrap);
  }
}

function openBanModal(id,name){banTargetId=id;banTargetName=name;document.getElementById('ban-name').textContent=name;document.getElementById('ban-reason').value='';document.getElementById('ban-dur').value='0';document.getElementById('ban-modal').classList.add('open');}
function closeBanModal(){document.getElementById('ban-modal').classList.remove('open');}
document.getElementById('ban-modal').addEventListener('click',function(e){if(e.target===this)closeBanModal();});

function submitBan(){
  var reason=document.getElementById('ban-reason').value||'Razon no especificada';
  var dur=parseInt(document.getElementById('ban-dur').value)||0;
  apiFetch('/api/account/ban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:banTargetId,reason:reason,duration:dur})})
    .then(function(d){closeBanModal();if(d.ok){toast('Cuenta "'+banTargetName+'" baneada','success');loadAccounts(accCurPage,accCurQ);}else{toast('Error: '+(d.error||'desconocido'),'error');}})
    .catch(function(){toast('Error de conexion','error');});
}

function unbanAcc(id,name){
  if(!confirm('Desbanear la cuenta "'+name+'"?'))return;
  apiFetch('/api/account/unban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(d){if(d.ok){toast('Cuenta "'+name+'" desbaneada','success');loadAccounts(accCurPage,accCurQ);}else{toast('Error: '+(d.error||'desconocido'),'error');}})
    .catch(function(){toast('Error de conexion','error');});
}

// ── Create Account ────────────────────────────────────────
function openCreateModal(){
  document.getElementById('create-email').value='';
  document.getElementById('create-pass').value='';
  document.getElementById('create-pass2').value='';
  document.getElementById('create-error').style.display='none';
  document.getElementById('create-modal').classList.add('open');
  setTimeout(function(){document.getElementById('create-email').focus();},80);
}
function closeCreateModal(){document.getElementById('create-modal').classList.remove('open');}
document.getElementById('create-modal').addEventListener('click',function(e){if(e.target===this)closeCreateModal();});

function submitCreateAccount(){
  var email=document.getElementById('create-email').value.trim();
  var pass=document.getElementById('create-pass').value;
  var pass2=document.getElementById('create-pass2').value;
  var errEl=document.getElementById('create-error');
  errEl.style.display='none';
  if(!email){errEl.textContent='El email es obligatorio.';errEl.style.display='block';return;}
  if(!pass){errEl.textContent='La contrasena es obligatoria.';errEl.style.display='block';return;}
  if(pass!==pass2){errEl.textContent='Las contrasenas no coinciden.';errEl.style.display='block';return;}
  apiFetch('/api/account/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,password:pass})})
    .then(function(d){
      if(d.ok){
        closeCreateModal();
        toast('Cuenta "'+email+'" creada correctamente','success');
        loadAccounts(accCurPage,accCurQ);
      } else {
        errEl.textContent='Error: '+(d.error||'desconocido');
        errEl.style.display='block';
      }
    }).catch(function(){errEl.textContent='Error de conexion';errEl.style.display='block';});
}

// ── Edit Account ─────────────────────────────────────────
var editTargetId=0;
var editOrigRbac=0;

function openEditModal(id,name){
  editTargetId=id;
  document.getElementById('edit-name').textContent=name;
  document.getElementById('edit-id-lbl').textContent=id;
  document.getElementById('edit-pass').value='';
  document.getElementById('edit-pass2').value='';
  document.getElementById('edit-error').style.display='none';
  // Fetch current data
  apiFetch('/api/account/info?id='+id).then(function(d){
    if(d.error){toast('Error al cargar cuenta: '+d.error,'error');return;}
    document.getElementById('edit-email').value=d.email||'';
    document.getElementById('edit-exp').value=d.expansion||0;
    document.getElementById('edit-gm').value=d.gmLevel||0;
    editOrigRbac=d.rbacRole||0;
    document.getElementById('edit-rbac').value=d.rbacRole||0;
    document.getElementById('edit-modal').classList.add('open');
  }).catch(function(){toast('Error de conexion','error');});
}

function closeEditModal(){document.getElementById('edit-modal').classList.remove('open');}
document.getElementById('edit-modal').addEventListener('click',function(e){if(e.target===this)closeEditModal();});

function closeRbacReloadModal(){document.getElementById('rbac-reload-modal').classList.remove('open');}
document.getElementById('rbac-reload-modal').addEventListener('click',function(e){if(e.target===this)closeRbacReloadModal();});
function doRbacReload(){
  var btn=document.getElementById('rbac-reload-btn');
  var res=document.getElementById('rbac-reload-result');
  btn.disabled=true;
  apiFetch('/api/rbac/reload',{method:'POST'})
    .then(function(d){
      res.style.display='block';
      if(d.ok){res.style.background='rgba(34,197,94,.12)';res.style.color='var(--green)';res.textContent='RBAC recargado. Los cambios ya estan activos.';}
      else{res.style.background='rgba(245,158,11,.12)';res.style.color='var(--yellow)';res.textContent=(d.message||'No se pudo recargar. Ejecuta .rbac reload en la consola del worldserver.');}
      btn.style.display='none';
    }).catch(function(){
      res.style.display='block';res.style.background='rgba(239,68,68,.12)';res.style.color='var(--red)';
      res.textContent='Error de conexion al intentar recargar.';btn.disabled=false;
    });
}

function submitEditAccount(){
  var email=document.getElementById('edit-email').value.trim();
  var pass=document.getElementById('edit-pass').value;
  var pass2=document.getElementById('edit-pass2').value;
  var exp=parseInt(document.getElementById('edit-exp').value)||0;
  var gm=parseInt(document.getElementById('edit-gm').value)||0;
  var rbacRole=parseInt(document.getElementById('edit-rbac').value)||0;
  var errEl=document.getElementById('edit-error');
  errEl.style.display='none';
  if(!email){errEl.textContent='El email es obligatorio.';errEl.style.display='block';return;}
  if(pass&&pass!==pass2){errEl.textContent='Las contrasenas no coinciden.';errEl.style.display='block';return;}
  var payload={id:editTargetId,email:email,expansion:exp,gmLevel:gm,rbacRole:rbacRole};
  if(pass)payload.password=pass;
  apiFetch('/api/account/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(function(d){
      if(d.ok){
        var rbacChanged=(rbacRole!==editOrigRbac);
        closeEditModal();
        toast('Cuenta actualizada correctamente','success');
        loadAccounts(accCurPage,accCurQ);
        // If RBAC role changed and worldserver is online, offer reload
        if(rbacChanged){
          apiFetch('/api/realms').then(function(r){
            var online=(r.realms||[]).some(function(x){return x.online;});
            if(online){
              document.getElementById('rbac-reload-result').style.display='none';
              document.getElementById('rbac-reload-btn').style.display='';
              document.getElementById('rbac-reload-btn').disabled=false;
              document.getElementById('rbac-reload-modal').classList.add('open');
            }
          }).catch(function(){});
        }
      } else {
        errEl.textContent='Error: '+(d.error||'desconocido');
        errEl.style.display='block';
      }
    }).catch(function(){errEl.textContent='Error de conexion';errEl.style.display='block';});
}

// ── Realms ───────────────────────────────────────────────
function loadRealmsPage(){
  var grid=document.getElementById('realm-grid');
  grid.innerHTML='<p style="color:var(--muted);padding:20px">Cargando reinos...</p>';
  apiFetch('/api/realms').then(function(d){
    grid.innerHTML='';
    if(!d.realms||!d.realms.length){grid.innerHTML='<p style="color:var(--muted);padding:20px">Sin reinos configurados</p>';return;}
    d.realms.forEach(function(r){
      var card=document.createElement('div');card.className='realm-card-full';
      var types={0:'Normal',1:'PvP',4:'Normal',6:'RP',8:'RP-PvP',16:'FFA-PvP'};
      var tname=types[r.type]||'Tipo '+r.type;
      var online=r.online;
      card.innerHTML='<div class="rc-hdr">'
        +'<div class="rc-dot '+(online?'dot-g':'dot-r')+'"></div>'
        +'<h3>'+esc(r.name)+'</h3>'
        +'<span class="badge '+(online?'badge-green':'badge-red')+'">'+(online?'En linea':'Offline')+'</span>'
        +'</div>'
        +'<div class="rc-body">'
        +'<div class="rc-row"><span class="rk">Puerto</span><span class="mono">'+r.port+'</span></div>'
        +'<div class="rc-row"><span class="rk">Tipo</span><span>'+tname+'</span></div>'
        +'<div class="rc-row"><span class="rk">Poblacion</span><span>'+Number(r.population).toFixed(1)+'</span></div>'
        +'<div class="rc-row"><span class="rk">IP Externa</span><span class="mono" style="font-size:11px">'+esc(r.address||'-')+'</span></div>'
        +'<div class="rc-row"><span class="rk">Acceso minimo</span><span>'+(r.secLevel===0?'Jugador':r.secLevel===1?'Moderador':r.secLevel===2?'GM':'Admin')+'</span></div>'
        +'</div>'
        +'<div class="rc-foot">'
        +(online
          ?'<button class="btn btn-danger btn-sm" onclick="toggleRealm('+r.port+',true)">Poner Offline</button>'
          :'<button class="btn btn-success btn-sm" onclick="toggleRealm('+r.port+',false)">Poner Online</button>')
        +'<button class="btn btn-outline btn-sm" style="margin-left:auto" onclick=\'openEditRealmModal('+JSON.stringify(r)+')\'>&#x270E; Editar</button>'
        +'</div>';
      grid.appendChild(card);
    });
  }).catch(function(){grid.innerHTML='<p style="color:var(--red);padding:20px">Error al cargar reinos</p>';});
}

function toggleRealm(port,offline){
  var act=offline?'poner offline':'poner online';
  if(!confirm('Seguro que deseas '+act+' el reino en puerto '+port+'?'))return;
  apiFetch('/api/realms/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({port:port,offline:offline})})
    .then(function(d){if(d.ok){toast('Reino actualizado','success');setTimeout(loadRealmsPage,800);}else{toast('Error: '+(d.error||'desconocido'),'error');}})
    .catch(function(){toast('Error de conexion','error');});
}

// ── Realm modals ──────────────────────────────────────────
function openAddRealmModal(){
  document.getElementById('ar-name').value='';
  document.getElementById('ar-addr').value='';
  document.getElementById('ar-laddr').value='';
  document.getElementById('ar-port').value='8085';
  document.getElementById('ar-type').value='0';
  document.getElementById('ar-sec').value='0';
  document.getElementById('ar-error').style.display='none';
  document.getElementById('ar-submit').disabled=false;
  document.getElementById('add-realm-modal').classList.add('open');
}
function closeAddRealmModal(){document.getElementById('add-realm-modal').classList.remove('open');}
document.getElementById('add-realm-modal').addEventListener('click',function(e){if(e.target===this)closeAddRealmModal();});

function submitAddRealm(){
  var name=document.getElementById('ar-name').value.trim();
  var addr=document.getElementById('ar-addr').value.trim();
  var laddr=document.getElementById('ar-laddr').value.trim();
  var port=parseInt(document.getElementById('ar-port').value,10);
  var type=parseInt(document.getElementById('ar-type').value,10);
  var sec=parseInt(document.getElementById('ar-sec').value,10);
  var errEl=document.getElementById('ar-error');
  if(!name||!addr||!port){errEl.textContent='Nombre, IP y puerto son obligatorios.';errEl.style.display='';return;}
  document.getElementById('ar-submit').disabled=true;
  apiFetch('/api/realms/add',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:name,address:addr,localAddress:laddr||addr,port:port,type:type,secLevel:sec})})
    .then(function(d){
      if(d.ok){closeAddRealmModal();toast('Reino creado correctamente','success');setTimeout(loadRealmsPage,600);}
      else{errEl.textContent='Error: '+(d.error||'desconocido');errEl.style.display='';document.getElementById('ar-submit').disabled=false;}
    }).catch(function(){errEl.textContent='Error de conexion.';errEl.style.display='';document.getElementById('ar-submit').disabled=false;});
}

function openEditRealmModal(r){
  document.getElementById('er-id').value=r.id;
  document.getElementById('er-name').value=r.name||'';
  document.getElementById('er-addr').value=r.address||'';
  document.getElementById('er-laddr').value=r.localAddress||'';
  document.getElementById('er-port').value=r.port||8085;
  document.getElementById('er-type').value=r.type||0;
  document.getElementById('er-sec').value=r.secLevel||0;
  document.getElementById('er-error').style.display='none';
  document.getElementById('er-submit').disabled=false;
  document.getElementById('edit-realm-modal').classList.add('open');
}
function closeEditRealmModal(){document.getElementById('edit-realm-modal').classList.remove('open');}
document.getElementById('edit-realm-modal').addEventListener('click',function(e){if(e.target===this)closeEditRealmModal();});

function submitEditRealm(){
  var id=parseInt(document.getElementById('er-id').value,10);
  var name=document.getElementById('er-name').value.trim();
  var addr=document.getElementById('er-addr').value.trim();
  var laddr=document.getElementById('er-laddr').value.trim();
  var port=parseInt(document.getElementById('er-port').value,10);
  var type=parseInt(document.getElementById('er-type').value,10);
  var sec=parseInt(document.getElementById('er-sec').value,10);
  var errEl=document.getElementById('er-error');
  if(!name||!addr||!port){errEl.textContent='Nombre, IP y puerto son obligatorios.';errEl.style.display='';return;}
  document.getElementById('er-submit').disabled=true;
  apiFetch('/api/realms/update',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id,name:name,address:addr,localAddress:laddr||addr,port:port,type:type,secLevel:sec})})
    .then(function(d){
      if(d.ok){closeEditRealmModal();toast('Reino actualizado correctamente','success');setTimeout(loadRealmsPage,600);}
      else{errEl.textContent='Error: '+(d.error||'desconocido');errEl.style.display='';document.getElementById('er-submit').disabled=false;}
    }).catch(function(){errEl.textContent='Error de conexion.';errEl.style.display='';document.getElementById('er-submit').disabled=false;});
}

// ── Logs ─────────────────────────────────────────────────
function startLogs(){
  clearInterval(logTimer);
  renderFullLogs();
  logTimer=setInterval(function(){
    if(CUR!=='logs')return;
    apiFetch('/api/logs?since='+logSeq).then(function(d){
      if(!d.entries||!d.entries.length)return;
      d.entries.forEach(function(e){if(e.seq>logSeq)logSeq=e.seq;allLogs.push(e);});
      while(allLogs.length>3000)allLogs.shift();
      renderFullLogs();
    }).catch(function(){});
  },1000);
}

function renderFullLogs(){
  var container=document.getElementById('log-full');
  var search=(document.getElementById('log-search')||{}).value||'';
  var atBot=container.scrollHeight-container.scrollTop<=container.clientHeight+40;
  var filtered=allLogs.filter(function(e){
    var lo=logFilter==='ALL'||e.level===logFilter;
    var so=!search||e.text.toLowerCase().indexOf(search.toLowerCase())>=0;
    return lo&&so;
  });
  container.innerHTML='';
  var lm={INFO:'lv-info',WARN:'lv-warn',ERROR:'lv-error',FATAL:'lv-fatal',DEBUG:'lv-debug',TRACE:'lv-debug'};
  filtered.forEach(function(e){
    var div=document.createElement('div');div.className='log-entry';
    div.innerHTML='<span class="log-lvl '+(lm[e.level]||'lv-debug')+'">'+e.level+'</span>'
      +'<span class="log-txt">'+esc(e.text)+'</span><span class="log-time">'+e.time+'</span>';
    container.appendChild(div);
  });
  if(logAutoScroll&&atBot)container.scrollTop=container.scrollHeight;
}

function setLvl(btn){
  logFilter=btn.dataset.level;
  document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.toggle('active',b===btn);});
  renderFullLogs();
}

function clearFullLogs(){allLogs=[];document.getElementById('log-full').innerHTML='';}

// ── Config ───────────────────────────────────────────────
function loadConfig(){
  var el=document.getElementById('config-content');
  el.innerHTML='<p style="color:var(--muted);padding:20px">Cargando configuracion...</p>';
  apiFetch('/api/config').then(function(d){
    el.innerHTML='';
    if(!d.sections){el.innerHTML='<p style="color:var(--red)">Error al cargar</p>';return;}
    d.sections.forEach(function(sec){
      var section=document.createElement('div');section.className='config-section';
      section.innerHTML='<h3>'+esc(sec.name)+'</h3>';
      var table=document.createElement('table');table.className='data-table';
      table.innerHTML='<thead><tr><th>Parametro</th><th>Valor</th><th>Descripcion</th></tr></thead>';
      var tbody=document.createElement('tbody');
      sec.entries.forEach(function(e){
        var tr=document.createElement('tr');
        tr.innerHTML='<td class="mono">'+esc(e.key)+'</td>'
          +'<td class="mono" style="color:var(--accent)">'+esc(e.value)+'</td>'
          +'<td class="muted" style="font-size:12px">'+esc(e.desc)+'</td>';
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      var card=document.createElement('div');card.className='card';card.style.overflow='hidden';card.style.padding='0';card.appendChild(table);
      section.appendChild(card);
      el.appendChild(section);
    });
  }).catch(function(){el.innerHTML='<p style="color:var(--red);padding:20px">Error al cargar configuracion</p>';});
}

// ── Security (bans) ──────────────────────────────────────
function loadBanned(page,q){
  banCurPage=page; banCurQ=q;
  var tbody=document.getElementById('ban-tbody');
  tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--muted)">Cargando...</td></tr>';
  var url='/api/bans?page='+page;
  if(q)url+='&q='+encodeURIComponent(q);
  apiFetch(url).then(function(d){
    tbody.innerHTML='';
    if(!d.bans||!d.bans.length){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--muted)">Sin bans activos</td></tr>';return;}
    d.bans.forEach(function(b){
      var tr=document.createElement('tr');
      var expiry=b.permanent?'<span class="badge badge-red">Permanente</span>':esc(b.unbanDate);
      tr.innerHTML='<td style="font-weight:500">'+esc(b.username)+'<br><span class="muted" style="font-size:11px">ID: '+b.accountId+'</span></td>'
        +'<td class="muted">'+esc(b.reason)+'</td>'
        +'<td class="muted">'+esc(b.bannedBy)+'</td>'
        +'<td class="muted">'+esc(b.banDate)+'</td>'
        +'<td>'+expiry+'</td>'
        +'<td><button class="btn btn-sm btn-success" onclick="unbanById('+b.accountId+',\''+esc(b.username)+'\')">Desbanear</button></td>';
      tbody.appendChild(tr);
    });
  }).catch(function(e){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--red)">Error: '+e.message+'</td></tr>';});
}

function unbanById(id,name){
  if(!confirm('Desbanear la cuenta "'+name+'"?'))return;
  apiFetch('/api/account/unban',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(d){if(d.ok){toast('Cuenta desbaneada','success');loadBanned(banCurPage,banCurQ);}else{toast('Error: '+(d.error||'desconocido'),'error');}})
    .catch(function(){toast('Error de conexion','error');});
}

// ── Maintenance ───────────────────────────────────────────
function loadMaintenance(){
  apiFetch('/api/maintenance').then(applyMaintenance).catch(function(){});
}

function applyMaintenance(d){
  var on=d.active;
  var banner=document.getElementById('maint-banner');
  var ico=document.getElementById('maint-ico');
  var title=document.getElementById('maint-title');
  var desc=document.getElementById('maint-desc');
  var track=document.getElementById('toggle-track');
  var lbl=document.getElementById('toggle-lbl');
  if(!banner)return;
  if(on){
    banner.className='maint-banner on';
    ico.textContent='🚧';
    title.textContent='Servidor en mantenimiento';
    desc.textContent='Los jugadores sin nivel GM han sido expulsados y no pueden conectarse hasta que se desactive el mantenimiento.';
    track.className='toggle-track on';
    lbl.textContent='Activado';
  } else {
    banner.className='maint-banner off';
    ico.textContent='🟢';
    title.textContent='Servidor abierto';
    desc.textContent='Todos los jugadores pueden acceder al servidor normalmente.';
    track.className='toggle-track';
    lbl.textContent='Desactivado';
  }
}

function toggleMaintenance(){
  apiFetch('/api/maintenance').then(function(d){
    var newState=!d.active;
    var msg=newState
      ?'Activar modo mantenimiento? Se expulsara a todos los jugadores sin GM.'
      :'Desactivar modo mantenimiento? El servidor volvera a ser accesible para todos.';
    if(!confirm(msg))return;
    apiFetch('/api/maintenance',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newState})})
      .then(function(r){
        if(r.ok){
          toast(newState?'Modo mantenimiento activado':'Modo mantenimiento desactivado', newState?'warn':'success');
          applyMaintenance({active:newState});
        } else {
          toast('Error: '+(r.error||'desconocido'),'error');
        }
      }).catch(function(){toast('Error de conexion','error');});
  }).catch(function(){toast('Error al obtener estado','error');});
}

// ── Players ──────────────────────────────────────────────
var playersData=[];
var playersFaction=0;
var playersTab='online'; // 'online' | 'offline'

function switchPlayersTab(tab){
  playersTab=tab;
  document.getElementById('ptab-online').classList.toggle('active',tab==='online');
  document.getElementById('ptab-offline').classList.toggle('active',tab==='offline');
  document.getElementById('psec-online').style.display=tab==='online'?'':'none';
  document.getElementById('psec-offline').style.display=tab==='offline'?'':'none';
  document.getElementById('btn-refresh-players').style.display=tab==='online'?'':'none';
  document.getElementById('players-count').textContent='';
}

function refreshPlayersTab(){
  if(playersTab==='online') loadPlayers();
}
var _guildBankTabs=[];

var RACE_NAMES={1:'Humano',2:'Orco',3:'Enano',4:'Elfo Nocturno',5:'No-muerto',6:'Tauren',7:'Gnomo',8:'Troll',9:'Goblin',10:'Elfo de Sangre',11:'Draenei'};
var CLASS_NAMES={1:'Guerrero',2:'Paladin',3:'Cazador',4:'Picaro',5:'Sacerdote',6:'Caballero de la Muerte',7:'Shaman',8:'Mago',9:'Brujo',11:'Druida'};
var RACE_ICONS={1:'&#x1F9D1;',2:'&#x1F47B;',3:'&#x1F9D4;',4:'&#x1F9DD;',5:'&#x1F480;',6:'&#x1F402;',7:'&#x1F9B8;',8:'&#x1F9CC;',9:'&#x1F47A;',10:'&#x1F9E1;',11:'&#x1F47D;'};
var CLASS_COLORS={1:'#c69b3a',2:'#f48cba',3:'#aad372',4:'#fff569',5:'#ffffff',6:'#c41e3a',7:'#0070dd',8:'#3fc7eb',9:'#8788ee',11:'#ff7c0a'};
var QUALITY_COLORS={0:'#9d9d9d',1:'#ffffff',2:'#1eff00',3:'#0070dd',4:'#a335ee',5:'#ff8000',6:'#e6cc80',7:'#e6cc80'};
var PROF_NAMES={129:'Primeros Auxilios',164:'Herreria',165:'Trabajo en cuero',171:'Alquimia',182:'Herboristeria',185:'Cocina',186:'Mineria',197:'Sastreria',202:'Ingenieria',333:'Encantamiento',356:'Pesca',393:'Desuello',755:'Joyeria',773:'Inscripcion'};
var EQUIP_SLOTS={0:'Cabeza',1:'Cuello',2:'Hombros',3:'Camisa',4:'Pecho',5:'Cintura',6:'Piernas',7:'Pies',8:'Munecas',9:'Manos',10:'Anillo 1',11:'Anillo 2',12:'Amuleto 1',13:'Amuleto 2',14:'Espalda',15:'Mano dcha',16:'Mano izq',17:'Distancia',18:'Tabardo'};
var ALLIANCE_RACES=[1,3,4,7,11];
var HORDE_RACES=[2,5,6,8,9,10];

function setFactionFilter(f,btn){
  playersFaction=f;
  document.querySelectorAll('#pg-players .filter-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  renderPlayers();
}

function loadPlayers(){
  document.getElementById('players-grid').innerHTML='<p style="color:var(--muted);padding:20px">Cargando...</p>';
  apiFetch('/api/players')
    .then(function(d){playersData=d.players||[];renderPlayers();})
    .catch(function(){document.getElementById('players-grid').innerHTML='<p style="color:var(--red);padding:20px">Error al cargar jugadores.</p>';});
}

function makePlayerCard(p, extra){
  var isA=ALLIANCE_RACES.indexOf(p.race)>=0;
  var factionCls=isA?'faction-a':'faction-h';
  var factionName=isA?'Alianza':'Horda';
  var raceName=RACE_NAMES[p.race]||('Raza '+p.race);
  var className=CLASS_NAMES[p.class]||('Clase '+p.class);
  var classColor=CLASS_COLORS[p.class]||'#888';
  var icon=RACE_ICONS[p.race]||'&#x1F464;';
  var bg=isA?'rgba(90,190,255,.12)':'rgba(255,90,90,.12)';
  var card=document.createElement('div');
  card.className='player-card';
  card.onclick=function(){openPlayerDetail(p.guid);};
  card.innerHTML='<div class="pc-head"><div class="pc-avatar" style="background:'+bg+'">'+icon+'</div>'
    +'<div style="min-width:0"><div class="pc-name">'+esc(p.name)+'</div>'
    +'<div class="pc-sub"><span class="'+factionCls+'">'+factionName+'</span> &bull; <span style="color:'+classColor+'">'+raceName+' '+className+'</span></div>'
    +'</div></div>'
    +'<div class="pc-info">'
    +'<div class="pc-row"><span class="pk">Nivel</span><span style="font-weight:600;color:var(--accent)">'+p.level+'</span></div>'
    +'<div class="pc-row"><span class="pk">Zona</span><span style="font-size:11px;text-align:right;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(p.zone_name||('Zona #'+p.zone))+'</span></div>'
    +(p.guild?'<div class="pc-row"><span class="pk">Hermandad</span><span style="color:var(--yellow);font-size:11px">'+esc(p.guild)+'</span></div>':'')
    +(extra||'')
    +'</div>';
  return card;
}

function renderPlayers(){
  var q=(document.getElementById('players-search').value||'').toLowerCase();
  var grid=document.getElementById('players-grid');
  var filtered=playersData.filter(function(p){
    if(q&&p.name.toLowerCase().indexOf(q)<0)return false;
    if(playersFaction===1&&ALLIANCE_RACES.indexOf(p.race)<0)return false;
    if(playersFaction===2&&HORDE_RACES.indexOf(p.race)<0)return false;
    return true;
  });
  document.getElementById('players-count').textContent=filtered.length+' / '+playersData.length+' jugadores';
  if(!filtered.length){grid.innerHTML='<p style="color:var(--muted);padding:20px">Sin jugadores encontrados.</p>';return;}
  grid.innerHTML='';
  filtered.forEach(function(p){grid.appendChild(makePlayerCard(p));});
}

var _offlinePage=0;
var _offlineT=null;

function offlineInputHandler(){
  clearTimeout(_offlineT);
  _offlineT=setTimeout(function(){_offlinePage=0;doOfflineSearch();},320);
}

function doOfflineSearch(){
  var q=(document.getElementById('offline-search').value||'').trim();
  var grid=document.getElementById('offline-grid');
  var pagDiv=document.getElementById('offline-pagination');
  grid.innerHTML='<p style="color:var(--muted);padding:20px">Buscando...</p>';
  if(pagDiv)pagDiv.innerHTML='';
  fetch('/api/players/offline?q='+encodeURIComponent(q)+'&page='+_offlinePage)
    .then(function(r){
      if(!r.ok)throw new Error('HTTP '+r.status+' - '+r.statusText);
      return r.text();
    })
    .then(function(txt){
      var d;
      try{d=JSON.parse(txt);}catch(e){
        grid.innerHTML='<p style="color:var(--red);padding:20px">Respuesta invalida del servidor. Ver consola.</p>';
        console.error('offline JSON parse error:',e,'\nResponse text:',txt.slice(0,500));
        return;
      }
      var players=d.players||[];
      if(!players.length){
        grid.innerHTML='<p class="offline-hint">'+(q?'Sin resultados para &ldquo;'+esc(q)+'&rdquo;.':'No hay jugadores desconectados registrados.')+'</p>';
        if(pagDiv)pagDiv.innerHTML='';
        return;
      }
      grid.innerHTML='';
      players.forEach(function(p){
        var logoutAgo='';
        if(p.logout_time){
          var secs=Math.floor(Date.now()/1000)-p.logout_time;
          if(secs<60)logoutAgo='ahora';
          else if(secs<3600)logoutAgo=Math.floor(secs/60)+' min';
          else if(secs<86400)logoutAgo=Math.floor(secs/3600)+' h';
          else logoutAgo=Math.floor(secs/86400)+' dias';
        }
        var extra=logoutAgo?'<div class="pc-row"><span class="pk">Desconectado</span><span style="color:var(--muted);font-size:11px">hace '+logoutAgo+'</span></div>':'';
        grid.appendChild(makePlayerCard(p,extra));
      });
      renderOfflinePagination(d.total||0,d.page||0,d.pages||1);
    })
    .catch(function(err){
      var msg=err?err.message||String(err):'desconocido';
      console.error('offline search error:',err);
      grid.innerHTML='<p style="color:var(--red);padding:20px">Error: '+esc(msg)+'</p>';
    });
}

function renderOfflinePagination(total,page,pages){
  var el=document.getElementById('offline-pagination');
  if(!el)return;
  if(pages<=1){
    el.innerHTML=total?'<div class="pag-bar"><span class="pag-info">'+total+' jugadores</span></div>':'';
    return;
  }
  var h='<div class="pag-bar">';
  if(page>0)h+='<button class="pag-btn" onclick="goOfflinePage('+(page-1)+')">&#x2190; Anterior</button>';
  var s=Math.max(0,page-3),e=Math.min(pages-1,page+3);
  if(s>0)h+='<button class="pag-btn" onclick="goOfflinePage(0)">1</button>';
  if(s>1)h+='<span class="pag-sep">&#x2026;</span>';
  for(var i=s;i<=e;i++)h+='<button class="pag-btn'+(i===page?' active':'')+'" onclick="goOfflinePage('+i+')">'+(i+1)+'</button>';
  if(e<pages-2)h+='<span class="pag-sep">&#x2026;</span>';
  if(e<pages-1)h+='<button class="pag-btn" onclick="goOfflinePage('+(pages-1)+')">'+pages+'</button>';
  if(page<pages-1)h+='<button class="pag-btn" onclick="goOfflinePage('+(page+1)+')">Siguiente &#x2192;</button>';
  h+='<span class="pag-info">'+total+' jugadores &bull; pag. '+(page+1)+' / '+pages+'</span>';
  h+='</div>';
  el.innerHTML=h;
}

function goOfflinePage(p){
  _offlinePage=p;
  doOfflineSearch();
  document.getElementById('psec-offline').scrollIntoView({behavior:'smooth',block:'start'});
}

// ── Player Detail ─────────────────────────────────────────
function openPlayerDetail(guid){
  var modal=document.getElementById('player-modal');
  modal.classList.add('open');
  // Reset to info tab
  document.querySelectorAll('.detail-tab').forEach(function(t){t.classList.toggle('active',t.dataset.tab==='info');});
  document.querySelectorAll('.tab-pane').forEach(function(p){p.classList.toggle('active',p.id==='pm-info');});
  document.getElementById('pm-name').textContent='Cargando...';
  document.getElementById('pm-sub').textContent='';
  document.getElementById('pm-guild-badge').innerHTML='';
  document.getElementById('pm-avatar').innerHTML='&#x1F464;';
  document.getElementById('pm-avatar').style.background='rgba(255,255,255,.06)';
  ['pm-info','pm-ach','pm-prof','pm-inv','pm-bank','pm-mail','pm-guild'].forEach(function(id){
    document.getElementById(id).innerHTML='<p style="color:var(--muted);font-size:12px;padding:8px 0">Cargando...</p>';
  });
  apiFetch('/api/player/detail?guid='+guid).then(function(d){
    if(d.error){document.getElementById('pm-info').innerHTML='<p style="color:var(--red)">'+esc(d.error)+'</p>';return;}
    pmRenderInfo(d);
    pmRenderAch(d.achievements||[]);
    pmRenderProf(d.professions||[]);
    pmRenderInv(d.inventory||[]);
    pmRenderBank(d.inventory||[]);
    pmRenderMail(d.mail||[]);
    pmRenderGuild(d.guild);
  }).catch(function(){document.getElementById('pm-info').innerHTML='<p style="color:var(--red)">Error de conexion</p>';});
}
function closePlayerModal(){document.getElementById('player-modal').classList.remove('open');}
document.getElementById('player-modal').addEventListener('click',function(e){if(e.target===this)closePlayerModal();});
document.querySelectorAll('.detail-tab').forEach(function(t){
  t.addEventListener('click',function(){
    var tab=this.dataset.tab;
    document.querySelectorAll('.detail-tab').forEach(function(x){x.classList.toggle('active',x.dataset.tab===tab);});
    document.querySelectorAll('.tab-pane').forEach(function(x){x.classList.toggle('active',x.id==='pm-'+tab);});
  });
});

function pmRenderInfo(d){
  var info=d.info||{};
  var isA=ALLIANCE_RACES.indexOf(info.race)>=0;
  var fCls=isA?'faction-a':'faction-h';
  var raceName=RACE_NAMES[info.race]||('Raza '+info.race);
  var className=CLASS_NAMES[info.class]||('Clase '+info.class);
  var classColor=CLASS_COLORS[info.class]||'#888';
  var icon=RACE_ICONS[info.race]||'&#x1F464;';
  var bg=isA?'rgba(90,190,255,.12)':'rgba(255,90,90,.12)';
  document.getElementById('pm-avatar').innerHTML=icon;
  document.getElementById('pm-avatar').style.background=bg;
  document.getElementById('pm-name').textContent=info.name||'?';
  document.getElementById('pm-sub').innerHTML='<span class="'+fCls+'">'+(isA?'Alianza':'Horda')+'</span> &bull; '+raceName+' &bull; <span style="color:'+classColor+'">'+className+'</span>';
  if(d.guild&&d.guild.name)
    document.getElementById('pm-guild-badge').innerHTML='<div style="color:var(--yellow);font-weight:600;font-size:13px">'+esc(d.guild.name)+'</div><div style="color:var(--muted);font-size:11px">'+esc(d.guild.rank||'')+'</div>';
  var totalH=Math.floor((info.totaltime||0)/3600),totalM=Math.floor(((info.totaltime||0)%3600)/60);
  var g=info.gold||0,s=info.silver||0,c=info.copper||0;
  var xpPct=info.level>=80?100:0;
  var h=document.getElementById('pm-info');
  h.innerHTML='<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">'
    +'<div class="card"><div class="card-hdr"><span class="card-ttl">Estado</span></div>'
    +'<div class="info-row"><span class="k">Nivel</span><span style="font-size:20px;font-weight:700;color:var(--accent)">'+info.level+'</span></div>'
    +'<div class="info-row"><span class="k">Zona</span><span style="font-size:12px;text-align:right">'+esc(info.zone_name||'Zona #'+info.zone)+'</span></div>'
    +'<div class="info-row"><span class="k">Mapa ID</span><span>'+info.map+'</span></div>'
    +'<div class="info-row"><span class="k">Tiempo jugado</span><span>'+totalH+'h '+totalM+'m</span></div>'
    +'<div class="info-row"><span class="k">Oro</span><span style="color:var(--yellow)">'+g+'g '+s+'s '+c+'c</span></div>'
    +'</div>'
    +'<div class="card"><div class="card-hdr"><span class="card-ttl">Experiencia</span></div>'
    +(info.level>=80
      ?'<div style="padding:8px 0;color:var(--green);font-weight:600">Nivel maximo (80)</div>'
      :'<div style="padding:4px 0;font-size:12px;color:var(--muted)">XP actual: <span style="color:var(--text)">'+info.xp+'</span></div>'
       +'<div class="xp-bar-bg"><div class="xp-bar-fill" style="width:'+xpPct+'%"></div></div>')
    +'<div class="info-row" style="margin-top:10px"><span class="k">Raza</span><span>'+raceName+'</span></div>'
    +'<div class="info-row"><span class="k">Clase</span><span style="color:'+classColor+'">'+className+'</span></div>'
    +'</div>'
    +'</div>';
}

function pmRenderAch(achs){
  var h=document.getElementById('pm-ach');
  if(!achs.length){h.innerHTML='<p style="color:var(--muted);padding:8px 0">Sin logros registrados.</p>';return;}
  // Points data is only available in the server DB2 (in-memory), not in MySQL.
  // We show the count of completed achievements instead.
  h.innerHTML='<div style="margin-bottom:12px;display:flex;align-items:baseline;gap:10px">'
    +'<span style="color:var(--accent);font-weight:700;font-size:22px">'+achs.length+'</span>'
    +'<span style="color:var(--muted);font-size:12px">logros completados</span>'
    +'<span style="color:var(--muted);font-size:11px;margin-left:4px">(puntos calculados en juego)</span>'
    +'</div>'
    +'<div>'+achs.map(function(a){
      var dt=a.date?new Date(a.date*1000).toLocaleDateString('es-ES'):'-';
      return '<div class="ach-item"><div style="flex:1;min-width:0"><div style="font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(a.title||'Logro #'+a.id)+'</div>'
        +'<div style="font-size:10px;color:var(--muted)">'+dt+'</div></div>'
        +'</div>';
    }).join('')+'</div>';
}

function pmRenderProf(profs){
  var h=document.getElementById('pm-prof');
  if(!profs.length){h.innerHTML='<p style="color:var(--muted);padding:8px 0">Sin profesiones.</p>';return;}
  var primary=profs.filter(function(p){return p.slot>=0;});
  var secondary=profs.filter(function(p){return p.slot<0;});
  var renderList=function(list,title){
    if(!list.length)return '';
    return '<div style="margin-bottom:18px"><div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px">'+title+'</div>'
      +list.map(function(p){
        var name=PROF_NAMES[p.skill]||('Habilidad #'+p.skill);
        var pct=p.max>0?Math.round(p.value/p.max*100):0;
        return '<div class="skill-bar-wrap"><div class="skill-bar-hdr"><span style="font-weight:500">'+name+'</span><span style="color:var(--muted)">'+p.value+' / '+p.max+'</span></div>'
          +'<div class="skill-bar-bg"><div class="skill-bar-fill" style="width:'+pct+'%"></div></div></div>';
      }).join('')+'</div>';
  };
  h.innerHTML=renderList(primary,'Profesiones Primarias')+renderList(secondary,'Habilidades Secundarias');
}

function pmItemsHtml(list){
  if(!list.length)return '<p style="color:var(--muted);font-size:12px">Vacio</p>';
  return '<div class="item-grid">'+list.map(function(i){
    var qc=QUALITY_COLORS[i.quality]||'#fff';
    var name=i.name||('Item #'+i.entry);
    return '<div class="item-cell" title="'+esc(name)+' (ID:'+i.entry+')">'
      +'<div style="color:'+qc+';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:11px">'+esc(name)+'</div>'
      +(i.count>1?'<div class="item-qty">x'+i.count+'</div>':'')+'</div>';
  }).join('')+'</div>';
}

function pmRenderInv(items){
  var equip=items.filter(function(i){return i.bag==0&&i.slot<=18;});
  var backpack=items.filter(function(i){return i.bag==0&&i.slot>=23&&i.slot<=38;});
  var inBags=items.filter(function(i){return i.bag!=0;});
  var h=document.getElementById('pm-inv');
  var sect=function(title,list){
    return '<div style="margin-bottom:16px"><div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px">'+title+' ('+list.length+')</div>'+pmItemsHtml(list)+'</div>';
  };
  var equipWithSlot=equip.map(function(i){return Object.assign({},i,{slotName:EQUIP_SLOTS[i.slot]||('Slot '+i.slot)});});
  var equipHtml=!equip.length?'<p style="color:var(--muted);font-size:12px">Vacio</p>'
    :'<div class="item-grid">'+equipWithSlot.map(function(i){
      var qc=QUALITY_COLORS[i.quality]||'#fff';
      var name=i.name||('Item #'+i.entry);
      return '<div class="item-cell" title="'+esc(name)+' ('+i.slotName+')">'
        +'<div style="font-size:9px;color:var(--muted);margin-bottom:2px">'+i.slotName+'</div>'
        +'<div style="color:'+qc+';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:11px">'+esc(name)+'</div>'
        +'</div>';
    }).join('')+'</div>';
  h.innerHTML='<div style="margin-bottom:16px"><div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px">Equipado ('+equip.length+')</div>'+equipHtml+'</div>'
    +sect('Mochila',backpack)
    +sect('Contenido de bolsas',inBags);
}

function pmRenderBank(items){
  var bank=items.filter(function(i){return i.bag==0&&i.slot>=39&&i.slot<=74;});
  var h=document.getElementById('pm-bank');
  h.innerHTML='<div style="margin-bottom:6px;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.7px">Banco personal ('+bank.length+' objetos)</div>'+pmItemsHtml(bank);
}

function pmRenderMail(mails){
  var h=document.getElementById('pm-mail');
  if(!mails.length){h.innerHTML='<p style="color:var(--muted);padding:8px 0">Sin correos.</p>';return;}
  h.innerHTML=mails.map(function(m){
    var exp=m.expire>0?new Date(m.expire*1000).toLocaleDateString('es-ES'):'-';
    var moneyStr='';
    if(m.money>0){var g=Math.floor(m.money/10000),s=Math.floor((m.money%10000)/100),c=m.money%100;moneyStr=' &bull; <span style="color:var(--yellow)">'+g+'g '+s+'s '+c+'c</span>';}
    var itemsHtml=m.items&&m.items.length
      ?'<div style="margin-top:8px;display:flex;gap:5px;flex-wrap:wrap">'+m.items.map(function(i){
          var qc=QUALITY_COLORS[i.quality]||'#fff';
          return '<div style="background:rgba(255,255,255,.04);border:1px solid var(--bdr);border-radius:5px;padding:3px 8px;font-size:10px;color:'+qc+'">'+esc(i.name||'Item #'+i.entry)+(i.count>1?' x'+i.count:'')+'</div>';
        }).join('')+'</div>':'';
    return '<div class="mail-item"><div class="mail-subj">'+esc(m.subject||'(sin asunto)')+'</div>'
      +'<div class="mail-meta"><span>De: <strong>'+esc(m.sender||'Sistema')+'</strong></span><span>Expira: '+exp+'</span>'+moneyStr+'</div>'
      +(m.body?'<div style="margin-top:6px;font-size:11px;color:var(--muted);max-height:56px;overflow:hidden;line-height:1.4">'+esc(m.body)+'</div>':'')
      +itemsHtml+'</div>';
  }).join('');
}

function pmRenderGuild(guild){
  var h=document.getElementById('pm-guild');
  if(!guild){h.innerHTML='<p style="color:var(--muted);padding:8px 0">Este jugador no pertenece a ninguna hermandad.</p>';return;}
  var bankG=Math.floor((guild.bank_money||0)/10000);
  _guildBankTabs=guild.bank_tabs||[];
  h.innerHTML='<div class="card" style="margin-bottom:14px"><div class="card-hdr"><span class="card-ttl" style="color:var(--yellow)">'+esc(guild.name||'')+'</span></div>'
    +'<div class="info-row"><span class="k">Rango del jugador</span><span style="font-weight:500">'+esc(guild.rank||'')+'</span></div>'
    +'<div class="info-row"><span class="k">Oro del banco</span><span style="color:var(--yellow)">'+bankG+'g</span></div>'
    +(guild.motd?'<div class="info-row"><span class="k">Mensaje del dia</span><span style="font-size:11px;text-align:right;max-width:200px">'+esc(guild.motd)+'</span></div>':'')
    +'</div>'
    +(_guildBankTabs.length
      ?'<div><div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:10px">Banco de Hermandad</div>'
       +'<div class="gbank-tabs">'+_guildBankTabs.map(function(t,i){return '<button class="gbank-tab-btn'+(i===0?' active':'')+'\" onclick="switchGbankTab('+i+',this)">'+esc(t.name)+'</button>';}).join('')+'</div>'
       +'<div id="gbank-content">'+pmItemsHtml(_guildBankTabs[0]&&_guildBankTabs[0].items||[])+'</div>'
       +'</div>'
      :'<p style="color:var(--muted);font-size:12px">Sin pestanas de banco visibles.</p>');
}
function switchGbankTab(idx,btn){
  document.querySelectorAll('.gbank-tab-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  document.getElementById('gbank-content').innerHTML=pmItemsHtml(_guildBankTabs[idx]&&_guildBankTabs[idx].items||[]);
}

// ── Chat Monitor ──────────────────────────────────────────
var _cmGuid=0,_cmName='',_cmLastId=0,_cmTimer=null,_cmRunning=false;

var CM_LABELS={
  say:'Say',yell:'Yell',emote:'Emote',
  whisper_out:'Whisper →',whisper_in:'Whisper ←',
  guild:'Guild',officer:'Officer',party:'Party',
  raid:'Raid',raid_warning:'RW',instance:'Inst',channel:'Canal',bg:'BG'
};

function initChatMonitor(){
  _cmGuid=0; _cmLastId=0; _cmRunning=false;
  if(_cmTimer){clearInterval(_cmTimer);_cmTimer=null;}
  document.getElementById('cm-toggle-btn').textContent='▶ Iniciar Monitor';
  document.getElementById('cm-toggle-btn').className='btn btn-primary';
  document.getElementById('cm-info-bar').style.display='none';
  document.getElementById('cm-search-results').innerHTML='';
  document.getElementById('cm-log').innerHTML='<div style="color:var(--muted);padding:20px 0;text-align:center">Busca un personaje y haz click en Iniciar Monitor para ver su chat en tiempo real.</div>';
}

function cmSearch(){
  var q=document.getElementById('cm-inp').value.trim();
  if(!q)return;
  fetch('/api/snapshots/search?type=char&q='+encodeURIComponent(q))
    .then(function(r){return r.json();}).then(function(d){
      var el=document.getElementById('cm-search-results');
      if(!d.chars||!d.chars.length){el.innerHTML='<div style="color:var(--muted);font-size:12px">No se encontraron personajes.</div>';return;}
      var h='<div style="display:flex;flex-wrap:wrap;gap:8px">';
      d.chars.forEach(function(c){
        h+='<div style="background:var(--bg);border:1px solid var(--bdr);border-radius:8px;padding:8px 12px;cursor:pointer;font-size:12px" onclick="cmSelect('+c.guid+','+JSON.stringify(c.name)+')">'
          +'<div style="font-weight:600;color:var(--text)">'+c.name+'</div>'
          +'<div style="color:var(--muted)">Nv '+c.level+' &bull; '+c.account_name+'</div>'
          +'</div>';
      });
      h+='</div>';
      el.innerHTML=h;
    }).catch(function(){});
}

function cmSelect(guid,name){
  _cmGuid=guid; _cmName=name;
  document.getElementById('cm-char-name').textContent=name;
  document.getElementById('cm-char-level').textContent='...';
  document.getElementById('cm-char-zone').textContent='...';
  document.getElementById('cm-char-guild').textContent='';
  document.getElementById('cm-online-dot').style.background='var(--muted)';
  document.getElementById('cm-info-bar').style.display='block';
  document.getElementById('cm-search-results').innerHTML='';
}

function cmToggle(){
  if(_cmGuid===0){toast('Selecciona un personaje primero','warn');return;}
  if(_cmRunning){
    clearInterval(_cmTimer); _cmTimer=null; _cmRunning=false;
    document.getElementById('cm-toggle-btn').textContent='▶ Iniciar Monitor';
    document.getElementById('cm-toggle-btn').className='btn btn-primary';
  } else {
    _cmLastId=0; _cmRunning=true;
    document.getElementById('cm-toggle-btn').textContent='■ Detener Monitor';
    document.getElementById('cm-toggle-btn').className='btn btn-outline';
    cmPoll();
    _cmTimer=setInterval(cmPoll,1500);
  }
}

function cmClear(){
  document.getElementById('cm-log').innerHTML='';
}

function cmActiveFilters(){
  var f=[];
  document.querySelectorAll('.cm-filter:checked').forEach(function(cb){f.push(cb.value);});
  return f;
}

function cmPoll(){
  if(!_cmGuid||!_cmRunning)return;
  fetch('/api/chat/events?char_guid='+_cmGuid+'&after_id='+_cmLastId)
    .then(function(r){return r.json();}).then(function(d){
      if(d.char_info){
        var ci=d.char_info;
        document.getElementById('cm-char-level').textContent=ci.level||'?';
        document.getElementById('cm-char-zone').textContent=ci.zone||'Desconocida';
        document.getElementById('cm-char-guild').textContent=ci.guild_name||'Sin guild';
        document.getElementById('cm-online-dot').style.background=ci.online?'var(--green)':'var(--muted)';
      }
      if(d.last_id&&d.last_id>_cmLastId)_cmLastId=d.last_id;
      if(d.events&&d.events.length){
        var filters=cmActiveFilters();
        var log=document.getElementById('cm-log');
        var wasAtBottom=(log.scrollHeight-log.scrollTop-log.clientHeight)<60;
        d.events.forEach(function(ev){
          if(filters.indexOf(ev.chat_type)<0)return;
          cmAppendEvent(ev,log);
        });
        if(wasAtBottom)log.scrollTop=log.scrollHeight;
      }
    }).catch(function(){});
}

function cmAppendEvent(ev,log){
  var ts=ev.ts?ev.ts.substring(11,19):'';
  var cls='cm-'+ev.chat_type;
  var typeTag='['+( CM_LABELS[ev.chat_type]||ev.chat_type)+']';
  var zone=ev.char_zone?'['+ev.char_zone+'] ':'';
  var who=ev.char_name+(ev.char_level?' ('+ev.char_level+')':'');
  var text='';

  if(ev.chat_type==='whisper_out'){
    var rzone=ev.target_zone?'['+ev.target_zone+'] ':'';
    text=who+' → '+rzone+ev.target_name+(ev.target_level?' ('+ev.target_level+')':'')+': '+ev.message;
  } else if(ev.chat_type==='whisper_in'){
    var szone=ev.target_zone?'['+ev.target_zone+'] ':'';
    text=szone+ev.target_name+(ev.target_level?' ('+ev.target_level+')':'')+' → '+who+': '+ev.message;
  } else if(ev.chat_type==='channel'){
    typeTag='[#'+(ev.channel_name||'?')+']';
    text=zone+who+': '+ev.message;
  } else {
    text=zone+who+': '+ev.message;
  }

  var d2=document.createElement('div');
  d2.className='cm-entry '+cls;
  d2.innerHTML='<span class="cm-ts">['+ts+']</span> <span class="'+cls+'">'+typeTag+' '+escHtml(text)+'</span>';
  log.appendChild(d2);
}

function escHtml(s){
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Rollback / Snapshots ──────────────────────────────────
var _rbScope='char';
var _rbSelGuid=0,_rbSelName='',_rbSelAccId=0,_rbSelBnetId=0;
var _rbRestoreId=0,_rbGuids=[],_rbSnapsPage=0;

function initRollbackPage(){
  document.getElementById('rb-chars-wrap').style.display='none';
  document.getElementById('rb-snaps-wrap').style.display='none';
  document.getElementById('rb-inp').value='';
}

function rbScopeChange(){
  _rbScope=document.querySelector('input[name="rb-scope"]:checked').value;
  var ph={'char':'Nombre del personaje...','account':'Nombre o email de cuenta...','ip':'Direccion IP...'};
  document.getElementById('rb-inp').placeholder=ph[_rbScope]||'Buscar...';
  document.getElementById('rb-chars-wrap').style.display='none';
  document.getElementById('rb-snaps-wrap').style.display='none';
}

function doRbSearch(){
  var q=document.getElementById('rb-inp').value.trim();
  if(!q)return;
  var tbody=document.getElementById('rb-chars-tbody');
  tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--muted)">Buscando...</td></tr>';
  document.getElementById('rb-chars-wrap').style.display='block';
  document.getElementById('rb-snaps-wrap').style.display='none';
  fetch('/api/snapshots/search?type='+encodeURIComponent(_rbScope)+'&q='+encodeURIComponent(q))
    .then(function(r){return r.json();})
    .then(function(d){
      var chars=d.chars||[];
      _rbGuids=chars.map(function(c){return c.guid;});
      if(!chars.length){
        tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--muted)">Sin resultados</td></tr>';
        document.getElementById('rb-bulk-bar').style.display='none';
        return;
      }
      tbody.innerHTML='';
      chars.forEach(function(c){
        var cc=CLASS_COLORS[c.class]||'#aaa';
        var cn=CLASS_NAMES[c.class]||'Clase '+c.class;
        var tr=document.createElement('tr');
        var snapBadge=c.snap_count?'<span style="font-size:10px;background:var(--accent);color:#fff;border-radius:3px;padding:1px 5px;margin-left:6px">'+c.snap_count+'</span>':'';
        tr.innerHTML='<td><span style="font-weight:600">'+esc(c.name)+'</span>'+snapBadge+'</td>'
          +'<td>'+esc(c.level||'?')+'</td>'
          +'<td style="color:'+cc+'">'+esc(cn)+'</td>'
          +'<td style="font-size:11px;color:var(--muted)">'+esc(c.account_name||'')+'</td>'
          +'<td style="font-size:11px;color:var(--muted)">'+esc(c.snap_count||0)+'</td>'
          +'<td><div style="display:flex;gap:5px">'
            +'<button class="btn btn-outline" style="font-size:11px;padding:3px 8px" '
              +'onclick="loadRbSnaps('+c.guid+','+c.account_id+','+c.bnet_id+',\''+c.name.replace(/'/g,"\\'")+'\')">'
              +'&#x1F4C2; Ver</button>'
            +'<button class="btn btn-primary" style="font-size:11px;padding:3px 8px" '
              +'onclick="quickRbCreate('+c.guid+','+c.account_id+','+c.bnet_id+',\''+c.name.replace(/'/g,"\\'")+'\')">'
              +'&#x1F4BE;</button>'
          +'</div></td>';
        tbody.appendChild(tr);
      });
      document.getElementById('rb-bulk-bar').style.display=
        (_rbScope!=='char'&&chars.length>1)?'block':'none';
    })
    .catch(function(e){
      tbody.innerHTML='<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--red)">Error: '+esc(e.message)+'</td></tr>';
    });
}

function loadRbSnaps(guid,accId,bnetId,name){
  _rbSelGuid=guid; _rbSelName=name; _rbSelAccId=accId; _rbSelBnetId=bnetId;
  _rbSnapsPage=0;
  document.getElementById('rb-snaps-hdr').textContent='Snapshots de '+name;
  document.getElementById('rb-snaps-sub').textContent='';
  document.getElementById('rb-snaps-wrap').style.display='block';
  fetchRbSnaps(guid,0);
}

function fetchRbSnaps(guid,page){
  var tbody=document.getElementById('rb-snaps-tbody');
  tbody.innerHTML='<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--muted)">Cargando...</td></tr>';
  fetch('/api/snapshots/list?char_guid='+guid+'&page='+page)
    .then(function(r){return r.json();})
    .then(function(d){renderRbSnaps(d);})
    .catch(function(e){
      tbody.innerHTML='<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--red)">Error: '+esc(e.message)+'</td></tr>';
    });
}

function renderRbSnaps(d){
  var tbody=document.getElementById('rb-snaps-tbody');
  var snaps=d.snapshots||[];
  document.getElementById('rb-snaps-sub').textContent='('+(d.total||0)+' total)';
  if(!snaps.length){
    tbody.innerHTML='<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--muted)">Sin snapshots. Usa "+ Crear Snapshot" para crear uno.</td></tr>';
    document.getElementById('rb-snaps-pager').innerHTML='';
    return;
  }
  var TYPE_LABELS={0:'Manual',1:'Pre-Restauracion',2:'Auto'};
  var TYPE_COLORS={0:'var(--accent)',1:'var(--yellow)',2:'var(--muted)'};
  tbody.innerHTML='';
  snaps.forEach(function(s){
    var dt=s.ts?new Date(s.ts*1000).toLocaleString('es-ES'):'-';
    var tl=TYPE_LABELS[s.snap_type||0]||'Otro';
    var tc=TYPE_COLORS[s.snap_type||0]||'var(--muted)';
    var sz=s.size_bytes?(s.size_bytes>=1048576?(s.size_bytes/1048576).toFixed(1)+'MB':(s.size_bytes/1024).toFixed(1)+'KB'):'-';
    var tr=document.createElement('tr');
    tr.innerHTML='<td style="font-size:12px">'+esc(dt)+'</td>'
      +'<td><span style="font-size:11px;color:'+tc+'">'+esc(tl)+'</span></td>'
      +'<td style="font-size:12px;color:var(--muted)">'+esc(s.label||'-')+'</td>'
      +'<td style="font-size:11px;color:var(--muted)">'+esc(sz)+'</td>'
      +'<td><div style="display:flex;gap:5px">'
        +'<button class="btn btn-outline" style="font-size:11px;padding:3px 8px" '
          +'onclick="openRbRestore('+s.id+',\''+esc(dt)+'\')">&#x21A9; Restaurar</button>'
        +'<button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(220,53,69,.15);color:var(--red);border:1px solid rgba(220,53,69,.3)" '
          +'onclick="deleteRbSnap('+s.id+')">&#x1F5D1;</button>'
      +'</div></td>';
    tbody.appendChild(tr);
  });
  // Pagination
  var pager=document.getElementById('rb-snaps-pager');
  var pages=d.pages||1,page=d.page||0;
  if(pages<=1){pager.innerHTML='';return;}
  var h='<div style="display:flex;gap:6px;align-items:center">';
  if(page>0)h+='<button class="btn btn-outline" style="font-size:12px" onclick="rbSnapsGo('+(page-1)+')">&#x2190; Ant</button>';
  h+='<span style="font-size:12px;color:var(--muted)">Pagina '+(page+1)+'/'+pages+'</span>';
  if(page<pages-1)h+='<button class="btn btn-outline" style="font-size:12px" onclick="rbSnapsGo('+(page+1)+')">Sig &#x2192;</button>';
  h+='</div>';
  pager.innerHTML=h;
}

function rbSnapsGo(page){
  _rbSnapsPage=page;
  fetchRbSnaps(_rbSelGuid,page);
}

function openRbCreate(){
  document.getElementById('rb-create-charname').textContent=_rbSelName;
  document.getElementById('rb-create-label').value='';
  document.getElementById('modal-rb-create').classList.add('open');
}

function quickRbCreate(guid,accId,bnetId,name){
  _rbSelGuid=guid;_rbSelName=name;_rbSelAccId=accId;_rbSelBnetId=bnetId;
  document.getElementById('rb-create-charname').textContent=name;
  document.getElementById('rb-create-label').value='';
  document.getElementById('modal-rb-create').classList.add('open');
}

function confirmRbCreate(){
  var label=document.getElementById('rb-create-label').value.trim();
  document.getElementById('modal-rb-create').classList.remove('open');
  apiFetch('/api/snapshots/create',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({char_guid:_rbSelGuid,account_id:_rbSelAccId,bnet_id:_rbSelBnetId,label:label,snap_type:0})
  }).then(function(d){
    if(d.ok){toast('Snapshot creado correctamente','ok');if(_rbSnapsPage>=0)fetchRbSnaps(_rbSelGuid,_rbSnapsPage);}
    else toast('Error: '+(d.error||'desconocido'),'error');
  }).catch(function(e){toast('Error: '+e.message,'error');});
}

function doBulkCreateSnapshot(){
  if(!_rbGuids.length)return;
  if(!confirm('Crear snapshot de '+_rbGuids.length+' personajes?'))return;
  apiFetch('/api/snapshots/create-bulk',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({char_guids:_rbGuids,account_id:_rbSelAccId,bnet_id:_rbSelBnetId,label:'Bulk snapshot',snap_type:0})
  }).then(function(d){
    toast(d.ok?'Snapshots creados: '+d.count:'Error: '+(d.error||'?'),d.ok?'ok':'error');
  }).catch(function(e){toast('Error: '+e.message,'error');});
}

function openRbRestore(snapId,dateStr){
  _rbRestoreId=snapId;
  document.getElementById('rb-restore-date').textContent=dateStr;
  document.getElementById('rb-restore-char').textContent=_rbSelName;
  document.getElementById('rb-auto-bkp').checked=true;
  document.getElementById('modal-rb-restore').classList.add('open');
}

function confirmRbRestore(){
  var autoBackup=document.getElementById('rb-auto-bkp').checked;
  document.getElementById('modal-rb-restore').classList.remove('open');
  var tbody=document.getElementById('rb-snaps-tbody');
  tbody.innerHTML='<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--muted)">Restaurando... esto puede tardar unos segundos.</td></tr>';
  apiFetch('/api/snapshots/restore',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({snapshot_id:_rbRestoreId,auto_backup:autoBackup})
  }).then(function(d){
    if(d.ok){toast('Personaje restaurado correctamente','ok');fetchRbSnaps(_rbSelGuid,_rbSnapsPage);}
    else{toast('Error al restaurar: '+(d.error||'desconocido'),'error');fetchRbSnaps(_rbSelGuid,_rbSnapsPage);}
  }).catch(function(e){toast('Error: '+e.message,'error');fetchRbSnaps(_rbSelGuid,_rbSnapsPage);});
}

function deleteRbSnap(snapId){
  if(!confirm('Eliminar este snapshot permanentemente?'))return;
  apiFetch('/api/snapshots/delete',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({snapshot_id:snapId})
  }).then(function(d){
    if(d.ok){toast('Snapshot eliminado','ok');fetchRbSnaps(_rbSelGuid,_rbSnapsPage);}
    else toast('Error: '+(d.error||'?'),'error');
  }).catch(function(e){toast('Error: '+e.message,'error');});
}

// ── Server control ────────────────────────────────────────
function stopServer(){
  if(!confirm('Seguro que deseas detener el servidor BNetServer?\nEsto desconectara a todos los jugadores.'))return;
  apiFetch('/api/stop',{method:'POST'}).then(function(){toast('Servidor deteniendo...','warn');}).catch(function(){});
}

// ── Utils ─────────────────────────────────────────────────
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// ── Chat Monitor ──────────────────────────────────────────
var cmGuid=0,cmRunning=false,cmTimer=null,cmLastId=0;
var cmGuildId=0,cmGroupId=0;

function initChatMonitor(){
  cmGuid=0;cmRunning=false;cmLastId=0;cmGuildId=0;cmGroupId=0;
  if(cmTimer){clearInterval(cmTimer);cmTimer=null;}
  document.getElementById('cm-toggle-btn').textContent='▶ Iniciar Monitor';
  document.getElementById('cm-info-bar').style.display='none';
}

function cmSearch(){
  var q=document.getElementById('cm-inp').value.trim();
  var box=document.getElementById('cm-search-results');
  if(!q){box.innerHTML='';return;}
  box.innerHTML='<span style="color:var(--muted);font-size:12px">Buscando...</span>';
  apiFetch('/api/players?q='+encodeURIComponent(q)+'&limit=8').then(function(d){
    if(!d.players||!d.players.length){box.innerHTML='<span style="color:var(--muted);font-size:12px">Sin resultados</span>';return;}
    box.innerHTML=d.players.map(function(p){
      return '<div onclick="cmSelect('+p.guid+','+JSON.stringify(p.name)+')"'
        +' style="display:inline-block;margin:4px 6px 0 0;padding:5px 12px;background:rgba(255,255,255,.06);border:1px solid var(--bdr);border-radius:6px;cursor:pointer;font-size:13px">'
        +'<span style="color:var(--green)">&#x25CF;</span> '+esc(p.name)
        +' <span style="font-size:11px;color:var(--muted)">Nv'+p.level+'</span></div>';
    }).join('');
  }).catch(function(){box.innerHTML='<span style="color:var(--red);font-size:12px">Error</span>';});
}

function cmSelect(guid,name){
  cmGuid=guid; cmGuildId=0; cmGroupId=0;
  document.getElementById('cm-search-results').innerHTML='';
  document.getElementById('cm-inp').value=name;
  var bar=document.getElementById('cm-info-bar');
  bar.style.display='block';
  document.getElementById('cm-char-name').textContent=name;
  document.getElementById('cm-char-level').textContent='...';
  document.getElementById('cm-char-zone').textContent='...';
  document.getElementById('cm-char-guild').textContent='...';
  cmLastId=0;
}

function cmToggle(){
  if(!cmGuid){toast('Selecciona un personaje primero','warn');return;}
  cmRunning=!cmRunning;
  var btn=document.getElementById('cm-toggle-btn');
  if(cmRunning){
    btn.textContent='⏹ Detener Monitor';btn.className='btn btn-danger';
    cmPoll();
    cmTimer=setInterval(cmPoll,1500);
  } else {
    btn.textContent='▶ Iniciar Monitor';btn.className='btn btn-primary';
    if(cmTimer){clearInterval(cmTimer);cmTimer=null;}
  }
}

function cmClear(){
  document.getElementById('cm-log').innerHTML='<div style="color:var(--muted);padding:20px 0;text-align:center">Log limpiado. El monitor continua activo.</div>';
}

function cmPoll(){
  if(!cmGuid||!cmRunning)return;
  var url='/api/chat/events?char_guid='+cmGuid+'&after_id='+cmLastId;
  if(cmGuildId)url+='&guild_id='+cmGuildId;
  if(cmGroupId)url+='&group_id='+cmGroupId;
  apiFetch(url).then(function(d){
    if(d.char_info){
      var ci=d.char_info;
      document.getElementById('cm-char-level').textContent=ci.level||'?';
      document.getElementById('cm-char-zone').textContent=ci.zone||'?';
      document.getElementById('cm-char-guild').textContent=ci.guild_name||'Sin guild';
      var dot=document.getElementById('cm-online-dot');
      dot.style.background=ci.online?'var(--green)':'var(--muted)';
    }
    if(d.events&&d.events.length){
      d.events.forEach(function(ev){
        if(ev.id>cmLastId)cmLastId=ev.id;
        cmAppendEvent(ev);
      });
    }
  }).catch(function(){});
}

function cmAppendEvent(ev){
  var filters=document.querySelectorAll('.cm-filter');
  var active={};
  filters.forEach(function(f){if(f.checked)active[f.value]=true;});
  if(!active[ev.type])return;
  var log=document.getElementById('cm-log');
  var atBot=log.scrollHeight-log.scrollTop<=log.clientHeight+40;
  var div=document.createElement('div');
  div.className='cm-entry';
  var ts='['+((ev.ts||'').substring(11,19)||'--:--:--')+'] ';
  var zone='['+esc(ev.zone||'?')+'] ';
  var who=esc(ev.char_name||'?')+'('+esc(ev.char_level||'?')+')';
  var target_info=ev.target_name?(' -> '+esc(ev.target_name)+'('+esc(ev.target_level||'?')+') ['+esc(ev.target_zone||'?')+']'):'';
  var msg=esc(ev.message||'');
  var typeLabel={'say':'SAY','yell':'YELL','emote':'EMOTE','whisper_out':'WHISPER>','whisper_in':'WHISPER<',
    'guild':'GUILD','officer':'OFFICER','party':'PARTY','raid':'RAID','raid_warning':'RAID!','instance':'INST','channel':'CHAN','bg':'BG'};
  var lbl='[' +(typeLabel[ev.type]||ev.type.toUpperCase())+']';
  div.innerHTML='<span class="cm-ts">'+ts+'</span>'
    +'<span class="cm-zone">'+zone+'</span>'
    +'<span class="cm-'+ev.type+'">'+lbl+' '+who+target_info+': '+msg+'</span>';
  log.appendChild(div);
  if(atBot)log.scrollTop=log.scrollHeight;
}

// ── News Admin ────────────────────────────────────────────
var _naPage=0;

function newsAdminLoad(page){
  _naPage=page;
  var q=document.getElementById('na-search')?document.getElementById('na-search').value.trim():'';
  var cat=document.getElementById('na-filter-cat')?document.getElementById('na-filter-cat').value:'';
  var url='/api/news?page='+page+(q?'&q='+encodeURIComponent(q):'')+(cat?'&cat='+encodeURIComponent(cat):'');
  var tbody=document.getElementById('na-tbody');
  tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--muted)">Cargando...</td></tr>';
  apiFetch(url).then(function(d){
    if(!d.news||!d.news.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:32px;color:var(--muted)">No hay noticias</td></tr>';newsAdminPager(0,0);return;}
    var cats={'parches':'badge-blue','eventos':'badge-yellow','mantenimiento':'badge-red','general':'badge-blue','actualizacion':'badge-green'};
    tbody.innerHTML=d.news.map(function(n){
      return '<tr>'
        +'<td class="muted">'+n.id+'</td>'
        +'<td><strong>'+esc(n.title)+'</strong></td>'
        +'<td><span class="badge '+(cats[n.category]||'badge-blue')+'">'+esc(n.category)+'</span></td>'
        +'<td class="muted">'+esc(n.author||'Staff')+'</td>'
        +'<td style="text-align:center">'+(n.featured?'<span class="badge badge-yellow">&#x2605;</span>':'<span style="color:var(--muted)">-</span>')+'</td>'
        +'<td class="muted">'+((n.date||'').substring(0,10))+'</td>'
        +'<td><button class="btn btn-outline btn-sm" onclick="newsAdminEdit('+JSON.stringify(n)+')">Editar</button> '
        +'<button class="btn btn-danger btn-sm" onclick="newsAdminDelete('+n.id+','+JSON.stringify(n.title)+')">&#x1F5D1;</button></td>'
        +'</tr>';
    }).join('');
    newsAdminPager(page,d.pages||1);
  }).catch(function(e){toast('Error cargando noticias: '+e.message,'error');});
}

function newsAdminPager(cur,total){
  var p=document.getElementById('na-pager');
  if(!p)return;
  p.innerHTML='';
  for(var i=0;i<total;i++){
    var b=document.createElement('button');
    b.className='pag-btn'+(i===cur?' active':'');
    b.textContent=i+1;
    (function(pi){b.onclick=function(){newsAdminLoad(pi);};})(i);
    p.appendChild(b);
  }
}

function newsAdminNew(){
  document.getElementById('ne-title').textContent='Nueva Noticia';
  document.getElementById('ne-id').value='0';
  document.getElementById('ne-titletxt').value='';
  document.getElementById('ne-cat').value='general';
  document.getElementById('ne-author').value='Staff';
  document.getElementById('ne-summary').value='';
  document.getElementById('ne-image').value='';
  document.getElementById('ne-content').value='';
  document.getElementById('ne-featured').checked=false;
  document.getElementById('modal-news-edit').classList.add('open');
}

function newsAdminEdit(n){
  document.getElementById('ne-title').textContent='Editar Noticia #'+n.id;
  document.getElementById('ne-id').value=n.id;
  document.getElementById('ne-titletxt').value=n.title||'';
  document.getElementById('ne-cat').value=n.category||'general';
  document.getElementById('ne-author').value=n.author||'Staff';
  document.getElementById('ne-summary').value=n.summary||'';
  document.getElementById('ne-image').value=n.image_url||'';
  document.getElementById('ne-content').value='Cargando...';
  document.getElementById('ne-featured').checked=!!n.featured;
  document.getElementById('modal-news-edit').classList.add('open');
  apiFetch('/api/portal/news/article?id='+n.id).then(function(d){
    document.getElementById('ne-content').value=d.content||'';
  }).catch(function(){document.getElementById('ne-content').value='';});
}

function newsAdminSave(){
  var id=parseInt(document.getElementById('ne-id').value)||0;
  var title=document.getElementById('ne-titletxt').value.trim();
  if(!title){toast('El titulo es obligatorio','warn');return;}
  var payload={
    id:id,
    title:title,
    category:document.getElementById('ne-cat').value,
    author:document.getElementById('ne-author').value.trim()||'Staff',
    summary:document.getElementById('ne-summary').value.trim(),
    image_url:document.getElementById('ne-image').value.trim(),
    content:document.getElementById('ne-content').value,
    is_published:1,
    is_featured:document.getElementById('ne-featured').checked?1:0
  };
  apiFetch('/api/news/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
    .then(function(d){
      if(d.ok){
        document.getElementById('modal-news-edit').classList.remove('open');
        toast((id?'Noticia actualizada':'Noticia creada'),'success');
        newsAdminLoad(_naPage);
      } else toast('Error: '+(d.error||'?'),'error');
    }).catch(function(e){toast('Error: '+e.message,'error');});
}

function newsAdminDelete(id,title){
  if(!confirm('Eliminar la noticia "'+title+'"?\nEsta accion es irreversible.'))return;
  apiFetch('/api/news/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(d){
      if(d.ok){toast('Noticia eliminada','success');newsAdminLoad(_naPage);}
      else toast('Error: '+(d.error||'?'),'error');
    }).catch(function(e){toast('Error: '+e.message,'error');});
}

// ── Boot ──────────────────────────────────────────────────
nav('dashboard');
</script>
</body>
</html>
)ADMIN";

// ============================================================================
// Helper functions
// ============================================================================
namespace
{
// URL percent-decode
std::string UrlDecode(std::string const& s)
{
    std::string r;
    r.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '+') { r += ' '; }
        else if (s[i] == '%' && i + 2 < s.size())
        {
            auto hexval = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hexval(s[i+1]), lo = hexval(s[i+2]);
            if (hi >= 0 && lo >= 0) { r += char(hi * 16 + lo); i += 2; }
            else r += s[i];
        }
        else r += s[i];
    }
    return r;
}

// Parse query string into key→value map
std::map<std::string, std::string> ParseQuery(std::string_view target)
{
    std::map<std::string, std::string> params;
    auto pos = target.find('?');
    if (pos == std::string_view::npos) return params;
    std::string_view qs = target.substr(pos + 1);
    while (!qs.empty())
    {
        auto amp = qs.find('&');
        std::string_view pair = (amp != std::string_view::npos) ? qs.substr(0, amp) : qs;
        auto eq = pair.find('=');
        if (eq != std::string_view::npos)
            params[std::string(pair.substr(0, eq))] = UrlDecode(std::string(pair.substr(eq + 1)));
        if (amp == std::string_view::npos) break;
        qs = qs.substr(amp + 1);
    }
    return params;
}

// Escape string for JSON
std::string JsonStr(std::string const& s)
{
    std::string r = "\"";
    for (unsigned char c : s)
    {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c < 0x20)  { char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", c); r += buf; }
        else                r += c;
    }
    r += '"';
    return r;
}

// Simple JSON string extractor for POST bodies
std::string JsonGet(std::string const& json, std::string const& key)
{
    auto kpos = json.find("\"" + key + "\"");
    if (kpos == std::string::npos) return {};
    auto col = json.find(':', kpos);
    if (col == std::string::npos) return {};
    col++;
    while (col < json.size() && (json[col] == ' ' || json[col] == '\t')) col++;
    if (col >= json.size()) return {};
    if (json[col] == '"')
    {
        auto end = json.find('"', col + 1);
        if (end == std::string::npos) return {};
        return json.substr(col + 1, end - col - 1);
    }
    // numeric / bool
    auto end = json.find_first_of(",}\n", col);
    auto val = (end != std::string::npos) ? json.substr(col, end - col) : json.substr(col);
    // trim
    while (!val.empty() && (val.back() == ' ' || val.back() == '\r' || val.back() == '\n')) val.pop_back();
    return val;
}

int64_t JsonGetInt(std::string const& json, std::string const& key)
{
    auto s = JsonGet(json, key);
    if (s.empty()) return 0;
    try { return std::stoll(s); } catch (...) { return 0; }
}

// Escape a string for use inside MySQL string literals
std::string SqlEsc(std::string const& s)
{
    std::string r;
    r.reserve(s.size() * 2);
    for (unsigned char c : s)
    {
        switch (c)
        {
            case '\'':  r += "\\'";  break;
            case '"':   r += "\\\""; break;
            case '\\':  r += "\\\\"; break;
            case '\n':  r += "\\n";  break;
            case '\r':  r += "\\r";  break;
            case '\0':  r += "\\0";  break;
            case '\x1a':r += "\\Z";  break;
            default:    r += char(c); break;
        }
    }
    return r;
}

std::string UptimeStr(time_t start)
{
    if (!start) return "N/A";
    long long e = static_cast<long long>(time(nullptr) - start);
    long long d = e / 86400, h = (e % 86400) / 3600, m = (e % 3600) / 60, s = e % 60;
    char buf[64];
    if (d > 0)       snprintf(buf, sizeof(buf), "%lld d %02lld h %02lld m", d, h, m);
    else if (h > 0)  snprintf(buf, sizeof(buf), "%02lld h %02lld m %02lld s", h, m, s);
    else             snprintf(buf, sizeof(buf), "%02lld m %02lld s", m, s);
    return buf;
}

std::string StartTimeStr(time_t start)
{
    if (!start) return "N/A";
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &start);
#else
    localtime_r(&start, &tm);
#endif
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d/%02d/%04d %02d:%02d:%02d",
        tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string UnixTimeStr(uint32 t)
{
    if (!t) return "N/A";
    time_t ts = static_cast<time_t>(t);
    return StartTimeStr(ts);
}

void SetJsonHeaders(boost::beast::http::response<boost::beast::http::string_body>& resp)
{
    namespace http = boost::beast::http;
    resp.set(http::field::content_type, "application/json");
    resp.set(http::field::access_control_allow_origin, "*");
}

// ── Rollback / Snapshot helpers ───────────────────────────────────────────────

// Tables to include in character snapshots: {table_name, where_column}
static const std::pair<const char*, const char*> k_SnapTables[] = {
    {"characters",                    "guid"},
    {"character_stats",               "guid"},
    {"character_homebind",            "guid"},
    {"character_skills",              "guid"},
    {"character_spells",              "guid"},
    {"character_talent",              "guid"},
    {"character_glyphs",              "guid"},
    {"character_queststatus",         "guid"},
    {"character_queststatus_rewarded","guid"},
    {"character_queststatus_seasonal","guid"},
    {"character_reputation",          "guid"},
    {"character_achievement",         "guid"},
    {"character_achievement_progress","guid"},
    {"character_aura",                "guid"},
    {"character_aura_effect",         "guid"},
    {"character_pet",                 "owner"},
    {"character_currency",            "CharacterGuid"},
    {"character_action",              "guid"},
    {"character_inventory",           "guid"},
};

static const std::map<std::string, std::string> k_SnapTableGuidCols = {
    {"characters","guid"},{"character_stats","guid"},{"character_homebind","guid"},
    {"character_skills","guid"},{"character_spells","guid"},{"character_talent","guid"},
    {"character_glyphs","guid"},{"character_queststatus","guid"},
    {"character_queststatus_rewarded","guid"},{"character_queststatus_seasonal","guid"},
    {"character_reputation","guid"},{"character_achievement","guid"},
    {"character_achievement_progress","guid"},{"character_aura","guid"},
    {"character_aura_effect","guid"},{"character_pet","owner"},
    {"character_currency","CharacterGuid"},{"character_action","guid"},
    {"character_inventory","guid"},{"item_instance","guid"},
};

// Serialize a DB result set (with column names) as a JSON table object:
// {"cols":["c1","c2",...], "rows":[["v1","v2",...],...]]}
static std::string SerializeTable(const char* tableName, const char* guidCol, uint32 charGuid)
{
    // Get column names from information_schema
    std::string colSql = std::string("SELECT COLUMN_NAME FROM information_schema.COLUMNS"
        " WHERE TABLE_SCHEMA='characters' AND TABLE_NAME='") + SqlEsc(tableName) +
        "' ORDER BY ORDINAL_POSITION";
    auto colRes = LoginDatabase.Query(colSql.c_str());
    if (!colRes) return "";

    std::vector<std::string> cols;
    do { cols.push_back(colRes->Fetch()[0].GetString()); } while (colRes->NextRow());
    if (cols.empty()) return "";

    std::string dataSql = std::string("SELECT * FROM characters.`") + tableName +
        "` WHERE `" + guidCol + "`=" + std::to_string(charGuid);
    auto dataRes = LoginDatabase.Query(dataSql.c_str());

    std::ostringstream o;
    o << "{\"cols\":[";
    for (size_t i = 0; i < cols.size(); i++) {
        if (i) o << ',';
        o << '"' << cols[i] << '"';
    }
    o << "],\"rows\":[";
    bool firstRow = true;
    if (dataRes) {
        do {
            auto f = dataRes->Fetch();
            if (!firstRow) o << ',';
            firstRow = false;
            o << '[';
            for (uint32 i = 0; i < dataRes->GetFieldCount(); i++) {
                if (i) o << ',';
                if (f[i].IsNull()) o << "null";
                else o << JsonStr(f[i].GetString());
            }
            o << ']';
        } while (dataRes->NextRow());
    }
    o << "]}";
    return o.str();
}

// Take a snapshot of a character and store it; returns the new snapshot id (0 on error)
static uint64 TakeCharSnapshot(uint32 charGuid, uint32 accountId, uint32 bnetId,
                                std::string const& label, int snapType)
{
    // Get char name
    std::string charName;
    {
        auto r = LoginDatabase.Query(("SELECT name FROM characters.characters WHERE guid=" + std::to_string(charGuid)).c_str());
        if (r) charName = r->Fetch()[0].GetString();
    }

    std::ostringstream data;
    data << "{\"version\":2,\"guid\":" << charGuid << ",\"tables\":{";

    bool firstTable = true;
    for (auto& [tblName, guidCol] : k_SnapTables)
    {
        std::string tblJson = SerializeTable(tblName, guidCol, charGuid);
        if (tblJson.empty()) continue;
        if (!firstTable) data << ',';
        firstTable = false;
        data << '"' << tblName << "\":" << tblJson;
    }

    // Special: item_instance for items in this character's inventory
    {
        auto invRes = LoginDatabase.Query(("SELECT item FROM characters.character_inventory WHERE guid=" + std::to_string(charGuid)).c_str());
        if (invRes)
        {
            std::string itemGuids;
            do {
                if (!itemGuids.empty()) itemGuids += ',';
                itemGuids += invRes->Fetch()[0].GetString();
            } while (invRes->NextRow());

            if (!itemGuids.empty())
            {
                // Get item_instance column names
                auto colRes = LoginDatabase.Query("SELECT COLUMN_NAME FROM information_schema.COLUMNS"
                    " WHERE TABLE_SCHEMA='characters' AND TABLE_NAME='item_instance'"
                    " ORDER BY ORDINAL_POSITION");
                if (colRes)
                {
                    std::vector<std::string> cols;
                    do { cols.push_back(colRes->Fetch()[0].GetString()); } while (colRes->NextRow());

                    auto itemRes = LoginDatabase.Query(("SELECT * FROM characters.item_instance WHERE guid IN (" + itemGuids + ")").c_str());
                    if (!firstTable) data << ',';
                    firstTable = false;
                    data << "\"item_instance\":{\"cols\":[";
                    for (size_t i = 0; i < cols.size(); i++) { if (i) data << ','; data << '"' << cols[i] << '"'; }
                    data << "],\"rows\":[";
                    bool firstRow = true;
                    if (itemRes) {
                        do {
                            auto f = itemRes->Fetch();
                            if (!firstRow) data << ','; firstRow = false;
                            data << '[';
                            for (uint32 i = 0; i < itemRes->GetFieldCount(); i++) {
                                if (i) data << ',';
                                if (f[i].IsNull()) data << "null";
                                else data << JsonStr(f[i].GetString());
                            }
                            data << ']';
                        } while (itemRes->NextRow());
                    }
                    data << "]}";
                }
            }
        }
    }

    data << "}}";
    std::string jsonData = data.str();

    // Store snapshot in auth.admin_char_snapshots
    std::string insertSql =
        "INSERT INTO auth.admin_char_snapshots"
        " (bnet_account_id, game_account_id, char_guid, char_name, snapshot_time, label, snap_type, data_json)"
        " VALUES (" +
        std::to_string(bnetId) + "," +
        std::to_string(accountId) + "," +
        std::to_string(charGuid) + "," +
        "'" + SqlEsc(charName) + "'," +
        "NOW()," +
        "'" + SqlEsc(label) + "'," +
        std::to_string(snapType) + "," +
        "'" + SqlEsc(jsonData) + "')";
    LoginDatabase.DirectExecute(insertSql.c_str());

    // Return inserted ID
    if (auto r = LoginDatabase.Query("SELECT LAST_INSERT_ID()"))
        return r->Fetch()[0].GetUInt64();
    return 0;
}

// Build SQL value string from a rapidjson value (handles null)
static std::string RjSqlVal(rapidjson::Value const& v)
{
    if (v.IsNull()) return "NULL";
    return "'" + SqlEsc(v.GetString()) + "'";
}

// Restore a character from a snapshot; returns error string or "" on success
static std::string RestoreCharSnapshot(uint64 snapId, bool autoBackup)
{
    // Fetch snapshot metadata + data
    auto fetchSql = "SELECT char_guid, char_name, data_json, bnet_account_id, game_account_id"
        " FROM auth.admin_char_snapshots WHERE id=" + std::to_string(snapId);
    auto res = LoginDatabase.Query(fetchSql.c_str());
    if (!res) return "Snapshot no encontrado";

    auto f = res->Fetch();
    uint32 charGuid      = f[0].GetUInt32();
    std::string charName = f[1].GetString();
    std::string jsonData = f[2].GetString();
    uint32 bnetId        = f[3].GetUInt32();
    uint32 accountId     = f[4].GetUInt32();

    // Resolve game account ID from characters table if not stored in snapshot
    if (accountId == 0)
    {
        auto r = LoginDatabase.Query(("SELECT account FROM characters.characters WHERE guid=" + std::to_string(charGuid)).c_str());
        if (r) accountId = r->Fetch()[0].GetUInt32();
    }

    // ── Step 1: Lock account to prevent re-login ─────────────────────────────
    if (accountId)
        LoginDatabase.DirectExecute(("UPDATE auth.account SET locked=1 WHERE id=" + std::to_string(accountId)).c_str());

    // ── Step 2: Kick character if online ─────────────────────────────────────
    bool wasOnline = false;
    {
        auto r = LoginDatabase.Query(("SELECT online FROM characters.characters WHERE guid=" + std::to_string(charGuid)).c_str());
        if (r && r->Fetch()[0].GetUInt8() != 0)
        {
            wasOnline = true;
            if (accountId)
                LoginDatabase.DirectExecute(
                    ("INSERT INTO auth.admin_pending_kicks (game_account_id, reason)"
                    " VALUES (" + std::to_string(accountId) + ", 'Restauracion de personaje - admin panel')").c_str());
        }
    }

    // ── Step 3: Wait up to 15 seconds for character to go offline ─────────────
    if (wasOnline)
    {
        bool offline = false;
        for (int i = 0; i < 30 && !offline; ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto r = LoginDatabase.Query(("SELECT online FROM characters.characters WHERE guid=" + std::to_string(charGuid)).c_str());
            if (r && r->Fetch()[0].GetUInt8() == 0) offline = true;
        }
        if (!offline)
        {
            // Unlock account and abort — do not restore while player is still online
            if (accountId)
                LoginDatabase.DirectExecute(("UPDATE auth.account SET locked=0 WHERE id=" + std::to_string(accountId)).c_str());
            return "El personaje sigue conectado tras 15 segundos. La cuenta fue desbloqueada. Intenta restaurar cuando este desconectado.";
        }
    }

    // ── Step 4: Auto-backup current state before overwriting ─────────────────
    if (autoBackup)
        TakeCharSnapshot(charGuid, accountId, bnetId, "Pre-restauracion automatica", 1);

    // Parse JSON
    rapidjson::Document doc;
    doc.Parse(jsonData.c_str(), jsonData.size());
    if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("tables"))
    {
        if (accountId)
            LoginDatabase.DirectExecute(("UPDATE auth.account SET locked=0 WHERE id=" + std::to_string(accountId)).c_str());
        return "JSON de snapshot invalido";
    }

    auto& tables = doc["tables"];

    // Step 1: Delete current character_inventory items from item_instance
    {
        auto invRes = LoginDatabase.Query(("SELECT item FROM characters.character_inventory WHERE guid=" + std::to_string(charGuid)).c_str());
        if (invRes) {
            std::string itemGuids;
            do {
                if (!itemGuids.empty()) itemGuids += ',';
                itemGuids += invRes->Fetch()[0].GetString();
            } while (invRes->NextRow());
            if (!itemGuids.empty())
                LoginDatabase.DirectExecute(("DELETE FROM characters.item_instance WHERE guid IN (" + itemGuids + ")").c_str());
        }
    }
    LoginDatabase.DirectExecute(("DELETE FROM characters.character_inventory WHERE guid=" + std::to_string(charGuid)).c_str());

    // Step 2: Restore item_instance first (so inventory FK is satisfied)
    if (tables.HasMember("item_instance"))
    {
        auto& td = tables["item_instance"];
        if (td.HasMember("cols") && td.HasMember("rows") && td["rows"].IsArray())
        {
            auto& cols = td["cols"];
            std::string colList = "(";
            for (auto ci = cols.Begin(); ci != cols.End(); ++ci) {
                if (ci != cols.Begin()) colList += ',';
                colList += '`'; colList += ci->GetString(); colList += '`';
            }
            colList += ')';
            for (auto& row : td["rows"].GetArray()) {
                std::string sql = "INSERT IGNORE INTO characters.item_instance " + colList + " VALUES (";
                bool firstV = true;
                for (auto vi = row.Begin(); vi != row.End(); ++vi) {
                    if (!firstV) sql += ','; firstV = false;
                    sql += RjSqlVal(*vi);
                }
                sql += ')';
                LoginDatabase.DirectExecute(sql.c_str());
            }
        }
    }

    // Step 3: Restore each character table (skip item_instance and character_inventory — handled separately)
    for (auto it = tables.MemberBegin(); it != tables.MemberEnd(); ++it)
    {
        std::string tblName = it->name.GetString();
        if (tblName == "item_instance") continue; // done above

        auto gcIt = k_SnapTableGuidCols.find(tblName);
        if (gcIt == k_SnapTableGuidCols.end()) continue;
        std::string guidCol = gcIt->second;

        auto& tblData = it->value;
        if (!tblData.HasMember("cols") || !tblData.HasMember("rows")) continue;

        // Delete existing rows for this character
        if (tblName != "character_inventory") // already deleted above
            LoginDatabase.DirectExecute(("DELETE FROM characters.`" + tblName + "` WHERE `" + guidCol + "`=" + std::to_string(charGuid)).c_str());

        auto& cols = tblData["cols"];
        auto& rows = tblData["rows"];
        if (!rows.IsArray() || rows.Empty()) continue;

        // Build column list
        std::string colList = "(";
        for (auto ci = cols.Begin(); ci != cols.End(); ++ci) {
            if (ci != cols.Begin()) colList += ',';
            colList += '`'; colList += ci->GetString(); colList += '`';
        }
        colList += ')';

        // Insert each row
        for (auto& row : rows.GetArray()) {
            std::string sql = "INSERT IGNORE INTO characters.`" + tblName + "` " + colList + " VALUES (";
            bool firstV = true;
            for (auto vi = row.Begin(); vi != row.End(); ++vi) {
                if (!firstV) sql += ','; firstV = false;
                sql += RjSqlVal(*vi);
            }
            sql += ')';
            LoginDatabase.DirectExecute(sql.c_str());
        }
    }

    // ── Step 5: Unlock account ────────────────────────────────────────────────
    if (accountId)
        LoginDatabase.DirectExecute(("UPDATE auth.account SET locked=0 WHERE id=" + std::to_string(accountId)).c_str());

    return "";  // success
}

// ── TOTP / Base32 helpers ────────────────────────────────────────────────────
static std::string Base32Encode(Trinity::Crypto::TOTP::Secret const& data)
{
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    int buf = 0, bits = 0;
    for (uint8 b : data) {
        buf = (buf << 8) | b; bits += 8;
        while (bits >= 5) { bits -= 5; out += alpha[(buf >> bits) & 0x1F]; }
    }
    if (bits > 0) out += alpha[(buf << (5 - bits)) & 0x1F];
    return out;
}

static bool Base32Decode(std::string const& s, Trinity::Crypto::TOTP::Secret& out)
{
    out.clear();
    int buf = 0, bits = 0;
    for (char c : s) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else if (c == '=' || c == ' ') continue;
        else return false;
        buf = (buf << 5) | v; bits += 5;
        if (bits >= 8) { bits -= 8; out.push_back((uint8)(buf >> bits)); }
    }
    return true;
}

// Read a portal_config value (returns "" if not found)
static std::string PortalCfg(std::string const& key)
{
    if (auto r = LoginDatabase.Query(("SELECT value_ FROM auth.portal_config WHERE key_='" + SqlEsc(key) + "'").c_str()))
        return r->Fetch()[0].GetString();
    return "";
}

// Check if a bnet account has forum moderation privileges
static bool IsForumMod(uint32 bnetId) {
    if (!bnetId) return false;
    std::string modIds = PortalCfg("forum_mod_ids");
    if (modIds.empty()) return bnetId == 1;
    std::string wrapped = "," + modIds + ",";
    std::string needle  = "," + std::to_string(bnetId) + ",";
    return wrapped.find(needle) != std::string::npos;
}

// Get display name for a forum author (email prefix before @)
static std::string ForumAuthorName(uint32 bnetId) {
    std::string name;
    if (auto r = LoginDatabase.Query(("SELECT email FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
        name = r->Fetch()[0].GetString();
    auto at = name.find('@');
    if (at != std::string::npos) name = name.substr(0, at);
    if (name.size() > 30) name = name.substr(0, 30);
    if (name.empty()) name = "Usuario" + std::to_string(bnetId);
    return name;
}

// Log a portal activity event into portal_activity_log
static void LogActivity(uint32 bnetId, const char* category, const char* type,
    int32 amount, std::string const& desc,
    std::string const& ip = "", std::string const& extra = "")
{
    LoginDatabase.DirectExecute(("INSERT INTO auth.portal_activity_log"
        " (bnet_id,category,type,amount,description,ip_address,extra)"
        " VALUES(" + std::to_string(bnetId) + ",'" + SqlEsc(std::string(category)) +
        "','" + SqlEsc(std::string(type)) + "'," + std::to_string(amount) +
        ",'" + SqlEsc(desc) + "','" + SqlEsc(ip) + "','" + SqlEsc(extra) + "')").c_str());
}

} // anon namespace

// ============================================================================
// AdminService implementation
// ============================================================================
namespace Battlenet
{
AdminService& AdminService::Instance()
{
    static AdminService inst;
    return inst;
}

std::shared_ptr<Trinity::Net::Http::SessionState>
    AdminService::CreateNewSessionState(boost::asio::ip::address const& address)
{
    auto state = std::make_shared<Trinity::Net::Http::SessionState>();
    InitAndStoreSessionState(state, address);
    return state;
}

bool AdminService::StartNetwork(Trinity::Asio::IoContext& ioContext,
                                std::string const& bindIp, uint16 port, int32 threadCount)
{
    if (!HttpService::StartNetwork(ioContext, bindIp, port, threadCount))
        return false;

    // Ensure snapshot table exists
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.admin_char_snapshots ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_account_id INT UNSIGNED NOT NULL DEFAULT 0,"
        "  game_account_id INT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_guid INT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_name VARCHAR(12) NOT NULL DEFAULT '',"
        "  snapshot_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  label VARCHAR(255) NOT NULL DEFAULT '',"
        "  snap_type TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  data_json LONGBLOB NOT NULL,"
        "  PRIMARY KEY (id),"
        "  INDEX idx_char (char_guid, snapshot_time),"
        "  INDEX idx_account (game_account_id),"
        "  INDEX idx_bnet (bnet_account_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Portal: news, sessions, web chat queue
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_news ("
        "  id INT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  title VARCHAR(255) NOT NULL DEFAULT '',"
        "  category VARCHAR(50) NOT NULL DEFAULT 'general',"
        "  summary TEXT NOT NULL,"
        "  content LONGTEXT NOT NULL,"
        "  image_url VARCHAR(500) NOT NULL DEFAULT '',"
        "  author VARCHAR(64) NOT NULL DEFAULT 'Staff',"
        "  is_published TINYINT UNSIGNED NOT NULL DEFAULT 1,"
        "  is_featured TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  views INT UNSIGNED NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (id),"
        "  INDEX idx_pub (is_published, created_at),"
        "  INDEX idx_feat (is_featured, created_at)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_sessions ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_account_id INT UNSIGNED NOT NULL,"
        "  session_token VARCHAR(64) NOT NULL,"
        "  ip_address VARCHAR(45) NOT NULL DEFAULT '',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  expires_at DATETIME NOT NULL,"
        "  PRIMARY KEY (id),"
        "  UNIQUE INDEX idx_token (session_token),"
        "  INDEX idx_bnet (bnet_account_id),"
        "  INDEX idx_expires (expires_at)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.web_chat_queue ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  game_account_id INT UNSIGNED NOT NULL,"
        "  char_guid INT UNSIGNED NOT NULL DEFAULT 0,"
        "  chat_type VARCHAR(20) NOT NULL DEFAULT 'say',"
        "  message VARCHAR(1024) NOT NULL DEFAULT '',"
        "  target VARCHAR(64) NOT NULL DEFAULT '',"
        "  channel_name VARCHAR(64) NOT NULL DEFAULT '',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  INDEX idx_account (game_account_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Portal config (rates, etc.)
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_config ("
        "  key_ VARCHAR(64) NOT NULL,"
        "  value_ VARCHAR(255) NOT NULL DEFAULT '',"
        "  PRIMARY KEY (key_)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    LoginDatabase.DirectExecute(
        "INSERT IGNORE INTO auth.portal_config (key_,value_) VALUES"
        " ('rate_xp','1'),('rate_drop','1'),('rate_gold','1'),('rate_rep','1'),('rate_honor','1'),"
        " ('trade_pd_buy_rate','50'),('trade_pd_sell_rate','40'),('transfer_pd_fee','10'),"
        " ('vote_cooldown_hours','12'),('server_name','Lineage Reborn'),('stripe_key',''),"
        " ('stripe_price_100','500'),('stripe_price_500','2000'),('stripe_price_1000','3500')");
    // Character service costs
    LoginDatabase.DirectExecute(
        "INSERT IGNORE INTO auth.portal_config (key_,value_) VALUES"
        " ('char_unstuck_cost','0'),('char_revive_cost','0'),"
        " ('char_rename_cost','100'),('char_customize_cost','150'),"
        " ('char_race_change_cost','500'),('char_faction_change_cost','800'),"
        " ('char_boost70_cost','2000'),('char_restore_deleted_cost','200'),"
        " ('char_transfer_cost','500'),('char_gold_rate','10')");

    // 2FA pending secrets table
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_2fa_pending ("
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  secret VARBINARY(20) NOT NULL,"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (bnet_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Promo codes tables
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.promo_codes ("
        "  code VARCHAR(32) NOT NULL,"
        "  pd_reward INT UNSIGNED NOT NULL DEFAULT 0,"
        "  pv_reward INT UNSIGNED NOT NULL DEFAULT 0,"
        "  max_uses INT UNSIGNED NOT NULL DEFAULT 1,"
        "  uses INT UNSIGNED NOT NULL DEFAULT 0,"
        "  is_active TINYINT UNSIGNED NOT NULL DEFAULT 1,"
        "  PRIMARY KEY (code)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.promo_code_uses ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  code VARCHAR(32) NOT NULL,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  used_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  UNIQUE KEY uk_bnet_code (bnet_id,code)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Vote log table
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_vote_log ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  site_key VARCHAR(32) NOT NULL,"
        "  voted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_bnet_site (bnet_id,site_key)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Vote points column on battlenet_accounts (MySQL-compatible existence check)
    if (!LoginDatabase.Query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='auth' AND TABLE_NAME='battlenet_accounts' AND COLUMN_NAME='voteCredits'"))
        LoginDatabase.DirectExecute("ALTER TABLE auth.battlenet_accounts ADD COLUMN voteCredits INT UNSIGNED NOT NULL DEFAULT 0");

    // Stripe payments table
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.stripe_payments ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  session_id VARCHAR(128) NOT NULL DEFAULT '',"
        "  pd_amount INT UNSIGNED NOT NULL DEFAULT 0,"
        "  amount_cents INT UNSIGNED NOT NULL DEFAULT 0,"
        "  status VARCHAR(20) NOT NULL DEFAULT 'pending',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_bnet (bnet_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Item shop catalog
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_shop_items ("
        "  id INT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  item_entry INT UNSIGNED NOT NULL DEFAULT 0,"
        "  name VARCHAR(128) NOT NULL DEFAULT '',"
        "  description VARCHAR(512) NOT NULL DEFAULT '',"
        "  price_pd INT UNSIGNED NOT NULL DEFAULT 0,"
        "  category VARCHAR(32) NOT NULL DEFAULT 'misc',"
        "  is_active TINYINT UNSIGNED NOT NULL DEFAULT 1,"
        "  PRIMARY KEY (id),"
        "  KEY idx_cat (category, is_active)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Item shop pending orders
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_shop_orders ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  account_id INT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_guid BIGINT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_name VARCHAR(32) NOT NULL DEFAULT '',"
        "  item_entry INT UNSIGNED NOT NULL DEFAULT 0,"
        "  item_name VARCHAR(128) NOT NULL DEFAULT '',"
        "  count INT UNSIGNED NOT NULL DEFAULT 1,"
        "  pd_spent INT UNSIGNED NOT NULL DEFAULT 0,"
        "  status VARCHAR(20) NOT NULL DEFAULT 'pending',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_bnet (bnet_id),"
        "  KEY idx_status (status)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Item recovery requests
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_item_recovery_requests ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  account_id INT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_guid BIGINT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_name VARCHAR(32) NOT NULL DEFAULT '',"
        "  description TEXT NOT NULL,"
        "  status VARCHAR(20) NOT NULL DEFAULT 'pending',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_bnet (bnet_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Forum tables
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.forum_categories ("
        "  id INT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  name VARCHAR(80) NOT NULL DEFAULT '',"
        "  description VARCHAR(255) NOT NULL DEFAULT '',"
        "  icon VARCHAR(16) NOT NULL DEFAULT '\xF0\x9F\x92\xAC',"
        "  sort_order INT NOT NULL DEFAULT 0,"
        "  is_active TINYINT UNSIGNED NOT NULL DEFAULT 1,"
        "  PRIMARY KEY (id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.forum_threads ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  category_id INT UNSIGNED NOT NULL,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  author_name VARCHAR(50) NOT NULL DEFAULT '',"
        "  title VARCHAR(120) NOT NULL DEFAULT '',"
        "  is_pinned TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  is_locked TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  is_hidden TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  views INT UNSIGNED NOT NULL DEFAULT 0,"
        "  reply_count INT UNSIGNED NOT NULL DEFAULT 0,"
        "  last_post_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_cat (category_id, is_hidden, is_pinned, last_post_at)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.forum_posts ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  thread_id BIGINT UNSIGNED NOT NULL,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  author_name VARCHAR(50) NOT NULL DEFAULT '',"
        "  content TEXT NOT NULL,"
        "  is_hidden TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_thread (thread_id, is_hidden, id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Default forum categories (INSERT IGNORE = won't duplicate on restart)
    LoginDatabase.DirectExecute(
        "INSERT IGNORE INTO auth.forum_categories (id,name,description,icon,sort_order) VALUES"
        " (1,'General','Discusion general sobre el servidor y la comunidad','\xF0\x9F\x92\xAC',1),"
        " (2,'Guias y Tutoriales','Guias, consejos y tutoriales para nuevos jugadores','\xF0\x9F\x93\x96',2),"
        " (3,'Soporte','Reportes de bugs, ayuda tecnica y problemas de cuenta','\xF0\x9F\x86\x98',3),"
        " (4,'PvP y Arena','Discusion, estrategias y logros en PvP','\xE2\x9A\x94',4),"
        " (5,'Comercio','Compra, venta e intercambio de objetos del juego','\xF0\x9F\x92\xB0',5)");
    // Forum moderator IDs (comma-separated list of bnet_ids)
    LoginDatabase.DirectExecute("INSERT IGNORE INTO auth.portal_config (key_,value_) VALUES ('forum_mod_ids','1')");

    // Activity log for Historiales (PD/PV, transactions, security)
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.portal_activity_log ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  bnet_id INT UNSIGNED NOT NULL,"
        "  category VARCHAR(20) NOT NULL DEFAULT 'general',"
        "  type VARCHAR(40) NOT NULL DEFAULT '',"
        "  amount INT NOT NULL DEFAULT 0,"
        "  description VARCHAR(255) NOT NULL DEFAULT '',"
        "  ip_address VARCHAR(64) NOT NULL DEFAULT '',"
        "  extra VARCHAR(255) NOT NULL DEFAULT '',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  KEY idx_bnet_cat (bnet_id, category, id),"
        "  KEY idx_bnet_id (bnet_id, id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Achievement points table (populated by worldserver at startup from DB2 store)
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.achievement_pts ("
        "  id INT UNSIGNED NOT NULL,"
        "  points TINYINT NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Prune expired portal sessions
    LoginDatabase.DirectExecute("DELETE FROM auth.portal_sessions WHERE expires_at < NOW()");

    // Ensure chat monitor log table exists
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.admin_chat_log ("
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  event_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  char_guid INT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_name VARCHAR(32) NOT NULL DEFAULT '',"
        "  char_level TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  char_zone VARCHAR(100) NOT NULL DEFAULT '',"
        "  chat_type VARCHAR(20) NOT NULL DEFAULT '',"
        "  message TEXT NOT NULL,"
        "  target_guid INT UNSIGNED NOT NULL DEFAULT 0,"
        "  target_name VARCHAR(32) NOT NULL DEFAULT '',"
        "  target_zone VARCHAR(100) NOT NULL DEFAULT '',"
        "  target_level TINYINT UNSIGNED NOT NULL DEFAULT 0,"
        "  guild_id INT UNSIGNED NOT NULL DEFAULT 0,"
        "  group_id INT UNSIGNED NOT NULL DEFAULT 0,"
        "  channel_name VARCHAR(64) NOT NULL DEFAULT '',"
        "  PRIMARY KEY (id),"
        "  INDEX idx_char_id (char_guid, id),"
        "  INDEX idx_guild (guild_id, id),"
        "  INDEX idx_group (group_id, id),"
        "  INDEX idx_time (event_time)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Migrate admin_chat_log: add columns missing from older schema (compatible with MySQL 5.7+)
    {
        auto addCol = [](const char* col, const char* def) {
            std::string chk = std::string("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS"
                " WHERE TABLE_SCHEMA='auth' AND TABLE_NAME='admin_chat_log' AND COLUMN_NAME='") + col + "'";
            if (auto r = LoginDatabase.Query(chk.c_str()))
                if (r->Fetch()[0].GetUInt32() == 0)
                    LoginDatabase.DirectExecute((std::string("ALTER TABLE auth.admin_chat_log ADD COLUMN ") + col + " " + def).c_str());
        };
        addCol("target_guid",  "INT UNSIGNED NOT NULL DEFAULT 0");
        addCol("target_name",  "VARCHAR(32) NOT NULL DEFAULT ''");
        addCol("target_zone",  "VARCHAR(100) NOT NULL DEFAULT ''");
        addCol("target_level", "TINYINT UNSIGNED NOT NULL DEFAULT 0");
        addCol("guild_id",     "INT UNSIGNED NOT NULL DEFAULT 0");
        addCol("group_id",     "INT UNSIGNED NOT NULL DEFAULT 0");
        addCol("channel_name", "VARCHAR(64) NOT NULL DEFAULT ''");
    }
    // Prune chat log entries older than 48 hours on startup
    LoginDatabase.DirectExecute(
        "DELETE FROM auth.admin_chat_log WHERE event_time < NOW() - INTERVAL 48 HOUR");

    // Ensure kick-queue table exists (worldserver polls this to kick sessions)
    LoginDatabase.DirectExecute(
        "CREATE TABLE IF NOT EXISTS auth.admin_pending_kicks ("
        "  id INT UNSIGNED NOT NULL AUTO_INCREMENT,"
        "  game_account_id INT UNSIGNED NOT NULL,"
        "  reason VARCHAR(255) NOT NULL DEFAULT 'Admin maintenance',"
        "  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "  PRIMARY KEY (id),"
        "  INDEX idx_account (game_account_id)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    namespace http = boost::beast::http;
    using Trinity::Net::Http::RequestContext;
    using Trinity::Net::Http::RequestHandlerResult;
    using Trinity::Net::Http::ToStdStringView;

    // ── GET /admin ────────────────────────────────────────────────────
    RegisterHandler(http::verb::get, "/admin",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        ctx.response.set(http::field::content_type, "text/html; charset=utf-8");
        ctx.response.body() = k_Html;
        return RequestHandlerResult::Handled;
    });

    // ── GET / (user portal) ───────────────────────────────────────────
    RegisterHandler(http::verb::get, "/",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        ctx.response.set(http::field::content_type, "text/html; charset=utf-8");
        ctx.response.body() = k_PortalHtml;
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/status ───────────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/status",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto& buf = sAdminBuf;
        std::ostringstream j;
        j << "{"
          << "\"running\":"  << (buf.Running.load() ? "true" : "false") << ","
          << "\"uptime\":"   << JsonStr(UptimeStr(buf.StartTime)) << ","
          << "\"startTime\":" << JsonStr(StartTimeStr(buf.StartTime)) << ","
          << "\"sessions\":" << buf.Sessions.load() << ","
          << "\"bnetPort\":" << buf.BnetPort << ","
          << "\"httpPort\":" << buf.HttpPort << ","
          << "\"tactPort\":" << buf.TactPort << ","
          << "\"version\":"  << JsonStr(buf.Version.empty() ? GitRevision::GetFullVersion() : buf.Version)
          << "}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/logs?since=N ─────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/logs",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint64_t since = 0;
        if (auto it = params.find("since"); it != params.end())
            try { since = std::stoull(it->second); } catch (...) {}

        auto entries = sAdminBuf.GetSince(since);
        std::ostringstream j;
        j << "{\"entries\":[";
        bool first = true;
        for (auto const& e : entries)
        {
            if (!first) j << ',';
            first = false;
            j << "{\"seq\":" << e.seq
              << ",\"level\":" << JsonStr(e.level)
              << ",\"text\":"  << JsonStr(e.text)
              << ",\"time\":"  << JsonStr(e.time)
              << "}";
        }
        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/realms ───────────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/realms",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto realms = sRealmList->GetAllRealms();
        std::ostringstream j;
        j << "{\"realms\":[";
        bool first = true;
        for (auto const& [handle, realm] : realms)
        {
            if (!first) j << ',';
            first = false;
            bool online = !(realm.Flags & REALM_FLAG_OFFLINE);
            std::string extAddr = realm.Addresses.empty() ? "" : realm.Addresses[0].to_string();
            std::string locAddr = realm.Addresses.size() > 1 ? realm.Addresses[1].to_string() : extAddr;
            j << "{\"id\":"            << handle.Realm
              << ",\"name\":"          << JsonStr(realm.Name)
              << ",\"address\":"       << JsonStr(extAddr)
              << ",\"localAddress\":"  << JsonStr(locAddr)
              << ",\"port\":"          << realm.Port
              << ",\"type\":"          << static_cast<int>(realm.Type)
              << ",\"flag\":"          << static_cast<int>(realm.Flags)
              << ",\"timezone\":"      << static_cast<int>(realm.Timezone)
              << ",\"secLevel\":"      << static_cast<int>(realm.AllowedSecurityLevel)
              << ",\"online\":"        << (online ? "true" : "false")
              << ",\"population\":"    << realm.PopulationLevel
              << "}";
        }
        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/realms/toggle ───────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/realms/toggle",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body = ctx.request.body();
        int64_t port    = JsonGetInt(body, "port");
        std::string ofl = JsonGet(body, "offline");
        bool offline    = (ofl == "true" || ofl == "1");

        if (port <= 0)
        {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"invalid port\"}";
            return RequestHandlerResult::Handled;
        }

        // Update realmlist flag in the database
        // offline: set bit 2 (REALM_FLAG_OFFLINE); online: clear bit 2 (253 = ~2 & 0xFF)
        char sql[128];
        if (offline)
            snprintf(sql, sizeof(sql), "UPDATE realmlist SET flag=(flag|2) WHERE port=%u", static_cast<uint32>(port));
        else
            snprintf(sql, sizeof(sql), "UPDATE realmlist SET flag=(flag&253) WHERE port=%u", static_cast<uint32>(port));
        LoginDatabase.DirectExecute(sql);

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/realms/update ───────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/realms/update",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body = ctx.request.body();
        int64_t id      = JsonGetInt(body, "id");
        int64_t port    = JsonGetInt(body, "port");
        int64_t type    = JsonGetInt(body, "type");
        int64_t sec     = JsonGetInt(body, "secLevel");
        std::string name  = JsonGet(body, "name");
        std::string addr  = JsonGet(body, "address");
        std::string laddr = JsonGet(body, "localAddress");

        if (id <= 0 || name.empty() || addr.empty() || port <= 0)
        {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Campos obligatorios faltantes\"}";
            return RequestHandlerResult::Handled;
        }

        auto sql = Trinity::StringFormat(
            "UPDATE realmlist SET name='{}', address='{}', localAddress='{}', port={}, icon={}, allowedSecurityLevel={}"
            " WHERE id={}",
            SqlEsc(name), SqlEsc(addr), SqlEsc(laddr), static_cast<uint32>(port),
            static_cast<uint32>(type), static_cast<uint32>(sec), static_cast<uint32>(id));
        LoginDatabase.DirectExecute(sql.c_str());

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/realms/add ──────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/realms/add",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body = ctx.request.body();
        int64_t port    = JsonGetInt(body, "port");
        int64_t type    = JsonGetInt(body, "type");
        int64_t sec     = JsonGetInt(body, "secLevel");
        std::string name  = JsonGet(body, "name");
        std::string addr  = JsonGet(body, "address");
        std::string laddr = JsonGet(body, "localAddress");

        if (name.empty() || addr.empty() || port <= 0)
        {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Campos obligatorios faltantes\"}";
            return RequestHandlerResult::Handled;
        }
        if (laddr.empty()) laddr = addr;

        // Inherit gamebuild from an existing realm so the client can connect
        uint32 gamebuild = 0;
        if (auto gbRes = LoginDatabase.Query("SELECT gamebuild FROM realmlist LIMIT 1"))
            gamebuild = gbRes->Fetch()[0].GetUInt32();

        auto sql = Trinity::StringFormat(
            "INSERT INTO realmlist (name, address, localAddress, localSubnetMask, port, icon, flag, timezone, allowedSecurityLevel, population, gamebuild)"
            " VALUES ('{}', '{}', '{}', '255.255.255.0', {}, {}, 2, 1, {}, 0.0, {})",
            SqlEsc(name), SqlEsc(addr), SqlEsc(laddr),
            static_cast<uint32>(port), static_cast<uint32>(type),
            static_cast<uint32>(sec), gamebuild);
        LoginDatabase.DirectExecute(sql.c_str());

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/players/offline?q=name&page=N ───────────────────────
    RegisterHandler(http::verb::get, "/api/players/offline",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        constexpr int PAGE_SIZE = 48;
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        std::string q;
        int page = 0;
        if (auto it = params.find("q");    it != params.end()) q    = it->second;
        if (auto it = params.find("page"); it != params.end())
            try { page = std::stoi(it->second); } catch (...) {}
        if (page < 0) page = 0;

        // Build name filter: lowercase q in C++, apply LOWER() on column for case-insensitive match
        std::string nameFilter;
        if (!q.empty())
        {
            std::string qLow = SqlEsc(q);
            for (char& c : qLow) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            nameFilter = " AND LOWER(c.name) LIKE '%" + qLow + "%'";
        }
        std::string baseWhere = "c.online=0" + nameFilter;

        // Count total matching rows — plain concatenation, no fmt
        uint64_t total = 0;
        {
            std::string countSql =
                "SELECT COUNT(*) FROM characters.characters c WHERE " + baseWhere;
            if (auto res = LoginDatabase.Query(countSql.c_str()))
                total = res->Fetch()[0].GetUInt64();
        }

        int pages = static_cast<int>((total + PAGE_SIZE - 1) / PAGE_SIZE);
        if (pages < 1) pages = 1;
        if (page >= pages) page = pages - 1;
        int offset = page * PAGE_SIZE;

        std::string sql =
            "SELECT c.guid, c.name, c.race, c.class, c.level, c.zone, c.logout_time,"
            " (SELECT AreaName FROM hotfixes.area_table WHERE ID=c.zone ORDER BY VerifiedBuild DESC LIMIT 1) as zone_name,"
            " g.name as guild_name"
            " FROM characters.characters c"
            " LEFT JOIN characters.guild_member gm ON c.guid=gm.guid"
            " LEFT JOIN characters.guild g ON gm.guildid=g.guildid"
            " WHERE " + baseWhere +
            " ORDER BY c.name LIMIT " + std::to_string(PAGE_SIZE) +
            " OFFSET " + std::to_string(offset);

        std::ostringstream j;
        j << "{\"total\":"  << total
          << ",\"page\":"   << page
          << ",\"pages\":"  << pages
          << ",\"players\":[";
        bool first = true;
        if (auto res = LoginDatabase.Query(sql.c_str()))
        {
            do {
                auto f = res->Fetch();
                if (!first) j << ','; first = false;
                std::string zoneName = f[7].IsNull() ? "" : f[7].GetString();
                std::string guild    = f[8].IsNull() ? "" : f[8].GetString();
                j << "{\"guid\":"        << f[0].GetUInt32()
                  << ",\"name\":"        << JsonStr(f[1].GetString())
                  << ",\"race\":"        << (int)f[2].GetUInt8()
                  << ",\"class\":"       << (int)f[3].GetUInt8()
                  << ",\"level\":"       << (int)f[4].GetUInt8()
                  << ",\"zone\":"        << f[5].GetUInt32()
                  << ",\"logout_time\":" << f[6].GetInt64()
                  << ",\"zone_name\":"   << JsonStr(zoneName)
                  << ",\"guild\":"       << JsonStr(guild)
                  << "}";
            } while (res->NextRow());
        }
        j << "]}";

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/accounts?page=N&q=search ────────────────────────────
    RegisterHandler(http::verb::get, "/api/accounts",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        int page = 0;
        std::string q;
        if (auto it = params.find("page"); it != params.end())
            try { page = std::stoi(it->second); } catch (...) {}
        if (auto it = params.find("q"); it != params.end())
            q = it->second;

        constexpr int PAGE_SIZE = 20;
        int offset = page * PAGE_SIZE;

        std::string where = q.empty()
            ? "1"
            : std::string("(a.username LIKE '%") + SqlEsc(q) + "%' OR a.email LIKE '%" + SqlEsc(q) + "%')";

        // Count
        uint64_t total = 0;
        {
            auto cntSql = std::string("SELECT COUNT(*) FROM account a WHERE ") + where;
            if (auto cntRes = LoginDatabase.Query(cntSql.c_str()))
                total = cntRes->Fetch()[0].GetUInt64();
        }

        int pages = static_cast<int>((total + PAGE_SIZE - 1) / PAGE_SIZE);

        std::ostringstream j;
        j << "{\"page\":" << page << ",\"pages\":" << pages << ",\"total\":" << total << ",\"accounts\":[";

        auto listSql = std::string(
            "SELECT a.id, a.username, a.email, a.last_ip,"
            " DATE_FORMAT(a.last_login,'%Y-%m-%d %T'), a.failed_logins,"
            " IFNULL((SELECT 1 FROM account_banned ab WHERE ab.id=a.id AND ab.active=1"
            " AND (ab.unbandate>UNIX_TIMESTAMP() OR ab.unbandate=ab.bandate) LIMIT 1),0) AS banned"
            " FROM account a WHERE ") + where + Trinity::StringFormat(" ORDER BY a.id LIMIT {} OFFSET {}", PAGE_SIZE, offset);
        auto res = LoginDatabase.Query(listSql.c_str());

        bool first = true;
        if (res)
        {
            do
            {
                auto fields = res->Fetch();
                if (!first) j << ',';
                first = false;
                j << "{\"id\":"         << fields[0].GetUInt32()
                  << ",\"username\":"   << JsonStr(fields[1].GetString())
                  << ",\"email\":"      << JsonStr(fields[2].GetString())
                  << ",\"lastIp\":"     << JsonStr(fields[3].GetString())
                  << ",\"lastLogin\":"  << JsonStr(fields[4].GetString())
                  << ",\"failed\":"     << fields[5].GetUInt32()
                  << ",\"banned\":"     << (fields[6].GetUInt8() ? "true" : "false")
                  << "}";
            } while (res->NextRow());
        }

        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/account/info?id=N ────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/account/info",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        // Always return HTTP 200 — errors go in the JSON body so apiFetch doesn't throw
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);

        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint32 id = 0;
        if (auto it = params.find("id"); it != params.end())
            try { id = static_cast<uint32>(std::stoul(it->second)); } catch (...) {}

        if (!id)
        {
            ctx.response.body() = "{\"error\":\"id invalido\"}";
            return RequestHandlerResult::Handled;
        }

        // Query 1: basic account fields + bnet email
        std::string email;
        uint32 expansion = 2;
        {
            auto sql = Trinity::StringFormat(
                "SELECT a.expansion, ba.email"
                " FROM account a"
                " LEFT JOIN battlenet_accounts ba ON a.battlenet_account=ba.id"
                " WHERE a.id={}", id);
            auto res = LoginDatabase.Query(sql.c_str());
            if (!res)
            {
                ctx.response.body() = "{\"error\":\"cuenta no encontrada\"}";
                return RequestHandlerResult::Handled;
            }
            auto f = res->Fetch();
            expansion = f[0].GetUInt32();
            email     = f[1].GetString(); // NULL-safe: returns "" when ba.email IS NULL
        }

        // Query 2: GM level (separate query avoids IFNULL/MAX type guessing)
        uint32 gmLevel = 0;
        {
            auto sql = Trinity::StringFormat(
                "SELECT SecurityLevel FROM account_access"
                " WHERE AccountID={} ORDER BY SecurityLevel DESC LIMIT 1", id);
            if (auto res = LoginDatabase.Query(sql.c_str()))
                gmLevel = res->Fetch()[0].GetUInt32();
        }

        // Query 3: current RBAC role grant (roles are permissions 196-199)
        uint32 rbacRole = 0;
        {
            auto sql = Trinity::StringFormat(
                "SELECT permissionId FROM rbac_account_permissions"
                " WHERE accountId={} AND permissionId BETWEEN 196 AND 199 AND granted=1"
                " ORDER BY permissionId ASC LIMIT 1", id);
            if (auto res = LoginDatabase.Query(sql.c_str()))
                rbacRole = res->Fetch()[0].GetUInt32();
        }

        std::ostringstream j;
        j << "{\"email\":"     << JsonStr(email)
          << ",\"expansion\":" << expansion
          << ",\"gmLevel\":"   << gmLevel
          << ",\"rbacRole\":"  << rbacRole
          << "}";
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/account/update ──────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/account/update",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        // Always HTTP 200 — errors go in JSON so apiFetch doesn't throw
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);

        std::string body  = ctx.request.body();
        uint32 id         = static_cast<uint32>(JsonGetInt(body, "id"));
        std::string email = JsonGet(body, "email");
        std::string pass  = JsonGet(body, "password");
        uint32 expansion  = static_cast<uint32>(JsonGetInt(body, "expansion"));
        uint32 gmLevel    = static_cast<uint32>(JsonGetInt(body, "gmLevel"));

        auto fail = [&](char const* msg)
        {
            ctx.response.body() = std::string("{\"ok\":false,\"error\":\"") + msg + "\"}";
        };

        if (!id)           { fail("id invalido");            return RequestHandlerResult::Handled; }
        if (email.empty()) { fail("email requerido");         return RequestHandlerResult::Handled; }
        if (email.size() > 320) { fail("email demasiado largo"); return RequestHandlerResult::Handled; }
        if (!pass.empty() && pass.size() > 128) { fail("password demasiado larga"); return RequestHandlerResult::Handled; }

        std::string emailUp = email;
        Utf8ToUpperOnlyLatin(emailUp);

        // Fetch current bnet account id and game account username
        uint32 bnetId = 0;
        std::string gameUsername;
        {
            auto sql = Trinity::StringFormat(
                "SELECT battlenet_account, username FROM account WHERE id={}", id);
            auto res = LoginDatabase.Query(sql.c_str());
            if (!res) { fail("cuenta no encontrada"); return RequestHandlerResult::Handled; }
            auto f   = res->Fetch();
            bnetId       = f[0].GetUInt32();
            gameUsername = f[1].GetString();
        }

        // ── Email ─────────────────────────────────────────────────────
        // Check email not already taken by another bnet account
        {
            auto sql = Trinity::StringFormat(
                "SELECT 1 FROM battlenet_accounts WHERE email='{}' AND id<>{}",
                SqlEsc(emailUp), bnetId);
            if (LoginDatabase.Query(sql.c_str()))
            { fail("ese email ya esta en uso"); return RequestHandlerResult::Handled; }
        }
        if (bnetId)
            LoginDatabase.DirectExecute(Trinity::StringFormat(
                "UPDATE battlenet_accounts SET email='{}' WHERE id={}",
                SqlEsc(emailUp), bnetId).c_str());
        LoginDatabase.DirectExecute(Trinity::StringFormat(
            "UPDATE account SET email='{}',reg_mail='{}' WHERE id={}",
            SqlEsc(emailUp), SqlEsc(emailUp), id).c_str());

        // ── Password ──────────────────────────────────────────────────
        if (!pass.empty())
        {
            // Bnet (BnetSRP6v2/SHA256) — raw SQL to avoid DirectExecute+ASYNC stmt issue
            if (bnetId)
            {
                std::string srpUser = ByteArrayToHexStr(Trinity::Crypto::SHA256::GetDigestOf(emailUp));
                auto [bS, bV] = Trinity::Crypto::SRP6::MakeRegistrationData<BnetSRP6>(srpUser, pass);
                LoginDatabase.DirectExecute(Trinity::StringFormat(
                    "UPDATE battlenet_accounts SET srp_version=2, salt=0x{}, verifier=0x{} WHERE id={}",
                    ByteArrayToHexStr(bS), ByteArrayToHexStr(bV), bnetId).c_str());
            }
            // Game (GruntSRP6) — raw SQL
            {
                std::string gUser = gameUsername;
                std::string gPass = pass.substr(0, 16);
                Utf8ToUpperOnlyLatin(gUser);
                Utf8ToUpperOnlyLatin(gPass);
                auto [gS, gV] = Trinity::Crypto::SRP6::MakeRegistrationData<GameSRP6>(gUser, gPass);
                LoginDatabase.DirectExecute(Trinity::StringFormat(
                    "UPDATE account SET salt=0x{}, verifier=0x{} WHERE id={}",
                    ByteArrayToHexStr(gS), ByteArrayToHexStr(gV), id).c_str());
            }
        }

        // ── Expansion ─────────────────────────────────────────────────
        LoginDatabase.DirectExecute(Trinity::StringFormat(
            "UPDATE account SET expansion={} WHERE id={}", expansion, id).c_str());

        // ── GM level ──────────────────────────────────────────────────
        LoginDatabase.DirectExecute(Trinity::StringFormat(
            "DELETE FROM account_access WHERE AccountID={}", id).c_str());
        if (gmLevel > 0)
            LoginDatabase.DirectExecute(Trinity::StringFormat(
                "INSERT INTO account_access (AccountID,SecurityLevel,RealmID) VALUES ({},{}, -1)",
                id, gmLevel).c_str());

        // ── RBAC Role (196=Admin 197=GM 198=Mod 199=Player) ───────────
        uint32 rbacRole = static_cast<uint32>(JsonGetInt(body, "rbacRole"));
        if (rbacRole != 0 && (rbacRole < 196 || rbacRole > 199))
            rbacRole = 0;
        LoginDatabase.DirectExecute(Trinity::StringFormat(
            "DELETE FROM rbac_account_permissions WHERE accountId={} AND permissionId BETWEEN 196 AND 199",
            id).c_str());
        if (rbacRole > 0)
            LoginDatabase.DirectExecute(Trinity::StringFormat(
                "INSERT INTO rbac_account_permissions (accountId,permissionId,granted,realmId)"
                " VALUES ({},{},1,-1) ON DUPLICATE KEY UPDATE granted=1",
                id, rbacRole).c_str());

        TC_LOG_INFO("server.bnetserver",
            "Admin panel: Updated account id={} email='{}' expansion={} gmLevel={} rbacRole={}{}",
            id, emailUp, expansion, gmLevel, rbacRole, pass.empty() ? "" : " [password changed]");

        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/rbac/reload ─────────────────────────────────────────
    // Signals the worldserver (via DB flag) to call World::ReloadRBAC()
    RegisterHandler(http::verb::post, "/api/rbac/reload",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);

        // Create the signal table if it doesn't exist yet
        LoginDatabase.DirectExecute(
            "CREATE TABLE IF NOT EXISTS admin_pending_reload"
            " (id INT NOT NULL DEFAULT 1 PRIMARY KEY,"
            "  rbac_reload TINYINT NOT NULL DEFAULT 0)");
        LoginDatabase.DirectExecute(
            "INSERT IGNORE INTO admin_pending_reload VALUES (1,0)");

        // Set the reload flag — worldserver polls this every 5 s
        LoginDatabase.DirectExecute(
            "UPDATE admin_pending_reload SET rbac_reload=1 WHERE id=1");

        TC_LOG_INFO("server.bnetserver", "Admin panel: RBAC reload requested");
        ctx.response.body() =
            "{\"ok\":true,\"message\":\"Recarga de RBAC programada. Surtira efecto en los proximos segundos.\"}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/account/create ──────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/account/create",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body  = ctx.request.body();
        std::string email = JsonGet(body, "email");
        std::string pass  = JsonGet(body, "password");

        auto jsonError = [&](char const* msg)
        {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = std::string("{\"ok\":false,\"error\":\"") + msg + "\"}";
        };

        if (email.empty())  { jsonError("email requerido");      return RequestHandlerResult::Handled; }
        if (pass.empty())   { jsonError("password requerida");   return RequestHandlerResult::Handled; }
        if (email.size() > 320) { jsonError("email demasiado largo"); return RequestHandlerResult::Handled; }
        if (pass.size() > 128)  { jsonError("password demasiado larga"); return RequestHandlerResult::Handled; }

        // Normalize
        std::string emailUp = email;
        Utf8ToUpperOnlyLatin(emailUp);

        // Check email not already taken
        {
            auto chkSql = Trinity::StringFormat(
                "SELECT id FROM battlenet_accounts WHERE email='{}'", SqlEsc(emailUp));
            if (LoginDatabase.Query(chkSql.c_str()))
            {
                jsonError("ese email ya existe");
                return RequestHandlerResult::Handled;
            }
        }

        // ── Create battlenet_accounts entry (BnetSRP6v2 / SHA256) ─────
        {
            std::string srpUsername = ByteArrayToHexStr(Trinity::Crypto::SHA256::GetDigestOf(emailUp));
            auto [salt, verifier] = Trinity::Crypto::SRP6::MakeRegistrationData<BnetSRP6>(srpUsername, pass);

            LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BNET_ACCOUNT);
            stmt->setString(0, emailUp);
            stmt->setInt8(1, 2); // SrpVersion::v2
            stmt->setBinary(2, salt);
            stmt->setBinary(3, verifier);
            LoginDatabase.DirectExecute(stmt);
        }

        // Fetch new bnet account id
        uint32 bnetId = 0;
        {
            auto idSql = Trinity::StringFormat(
                "SELECT id FROM battlenet_accounts WHERE email='{}'", SqlEsc(emailUp));
            if (auto res = LoginDatabase.Query(idSql.c_str()))
                bnetId = res->Fetch()[0].GetUInt32();
        }

        if (!bnetId)
        {
            ctx.response.result(http::status::internal_server_error);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"fallo al recuperar id bnet\"}";
            return RequestHandlerResult::Handled;
        }

        // ── Create account entry (GruntSRP6) ──────────────────────────
        {
            std::string gameUsername = Trinity::StringFormat("{}#1", bnetId);
            std::string gamePass = pass.substr(0, 16); // MAX_PASS_STR
            Utf8ToUpperOnlyLatin(gamePass);
            Utf8ToUpperOnlyLatin(gameUsername);

            auto [salt, verifier] = Trinity::Crypto::SRP6::MakeRegistrationData<GameSRP6>(gameUsername, gamePass);

            LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_ACCOUNT);
            stmt->setString(0, gameUsername);
            stmt->setBinary(1, salt);
            stmt->setBinary(2, verifier);
            stmt->setString(3, emailUp); // reg_mail
            stmt->setString(4, emailUp); // email
            stmt->setUInt32(5, bnetId);
            stmt->setUInt8(6, 1); // battlenet_index
            LoginDatabase.DirectExecute(stmt);
        }

        TC_LOG_INFO("server.bnetserver", "Admin panel: Created account email='{}' bnetId={}", emailUp, bnetId);

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = Trinity::StringFormat("{{\"ok\":true,\"bnetId\":{}}}", bnetId);
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/account/ban ─────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/account/ban",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body   = ctx.request.body();
        int64_t id         = JsonGetInt(body, "id");
        std::string reason = JsonGet(body, "reason");
        int64_t duration   = JsonGetInt(body, "duration"); // seconds; 0 = permanent

        if (id <= 0)
        {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"invalid id\"}";
            return RequestHandlerResult::Handled;
        }

        if (reason.empty()) reason = "Baneado por el administrador";

        // Deactivate existing bans
        {
            char deactSql[128];
            snprintf(deactSql, sizeof(deactSql),
                "UPDATE account_banned SET active=0 WHERE id=%u AND active=1",
                static_cast<uint32>(id));
            LoginDatabase.DirectExecute(deactSql);
        }

        // Insert new ban (permanent when duration=0: unbandate=bandate)
        std::string insertSql;
        if (duration > 0)
            insertSql = Trinity::StringFormat(
                "INSERT INTO account_banned (id,bandate,unbandate,bannedby,banreason,active)"
                " VALUES ({},UNIX_TIMESTAMP(),UNIX_TIMESTAMP()+{},'Admin Panel','{}',1)",
                static_cast<uint32>(id), duration, SqlEsc(reason));
        else
            insertSql = Trinity::StringFormat(
                "INSERT INTO account_banned (id,bandate,unbandate,bannedby,banreason,active)"
                " VALUES ({},UNIX_TIMESTAMP(),UNIX_TIMESTAMP(),'Admin Panel','{}',1)",
                static_cast<uint32>(id), SqlEsc(reason));

        LoginDatabase.DirectExecute(insertSql.c_str());

        TC_LOG_INFO("server.bnetserver", "Admin panel: Account {} banned. Reason: {}", id, reason);

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/account/unban ───────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/account/unban",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        int64_t id = JsonGetInt(ctx.request.body(), "id");
        if (id <= 0)
        {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"invalid id\"}";
            return RequestHandlerResult::Handled;
        }

        {
            char sql[128];
            snprintf(sql, sizeof(sql),
                "UPDATE account_banned SET active=0 WHERE id=%u AND active=1",
                static_cast<uint32>(id));
            LoginDatabase.DirectExecute(sql);
        }

        TC_LOG_INFO("server.bnetserver", "Admin panel: Account {} unbanned.", id);

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/bans?page=N&q=search ────────────────────────────────
    RegisterHandler(http::verb::get, "/api/bans",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        int page = 0;
        std::string q;
        if (auto it = params.find("page"); it != params.end())
            try { page = std::stoi(it->second); } catch (...) {}
        if (auto it = params.find("q"); it != params.end())
            q = it->second;

        constexpr int PAGE_SIZE = 20;
        int offset = page * PAGE_SIZE;

        std::string where = q.empty()
            ? "1"
            : std::string("a.username LIKE '%") + SqlEsc(q) + "%'";

        auto banSql = std::string(
            "SELECT a.id, a.username, ab.banreason, ab.bannedby, ab.bandate, ab.unbandate"
            " FROM account_banned ab JOIN account a ON a.id=ab.id"
            " WHERE ab.active=1 AND (ab.unbandate>UNIX_TIMESTAMP() OR ab.unbandate=ab.bandate)"
            " AND ") + where + Trinity::StringFormat(" ORDER BY ab.bandate DESC LIMIT {} OFFSET {}", PAGE_SIZE, offset);
        auto res = LoginDatabase.Query(banSql.c_str());

        std::ostringstream j;
        j << "{\"bans\":[";
        bool first = true;
        if (res)
        {
            do
            {
                auto fields = res->Fetch();
                if (!first) j << ',';
                first = false;
                uint32 bandate   = fields[4].GetUInt32();
                uint32 unbandate = fields[5].GetUInt32();
                bool permanent   = (unbandate == bandate);
                j << "{\"accountId\":"  << fields[0].GetUInt32()
                  << ",\"username\":"   << JsonStr(fields[1].GetString())
                  << ",\"reason\":"     << JsonStr(fields[2].GetString())
                  << ",\"bannedBy\":"   << JsonStr(fields[3].GetString())
                  << ",\"banDate\":"    << JsonStr(UnixTimeStr(bandate))
                  << ",\"unbanDate\":"  << JsonStr(permanent ? "Permanente" : UnixTimeStr(unbandate))
                  << ",\"permanent\":"  << (permanent ? "true" : "false")
                  << "}";
            } while (res->NextRow());
        }
        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/config ───────────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/config",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        struct CfgEntry { char const* key; char const* desc; };
        struct CfgSection { char const* name; std::vector<CfgEntry> entries; };

        std::vector<CfgSection> sections =
        {
            { "Red", {
                { "BattlenetPort",              "Puerto de autenticacion Battle.net" },
                { "LoginREST.Port",             "Puerto del servicio REST de login" },
                { "LoginREST.TactPort",         "Puerto del stub TACT CDN" },
                { "Admin.Port",                 "Puerto del panel de administracion" },
                { "BindIP",                     "IP de enlace del servidor" },
                { "LoginREST.ExternalAddress",  "Direccion externa del servidor" },
                { "LoginREST.LocalAddress",     "Direccion local del servidor" },
            }},
            { "General", {
                { "RealmsStateUpdateDelay",   "Intervalo de actualizacion de reinos (seg)" },
                { "MaxPingTime",              "Intervalo de ping MySQL (min)" },
                { "BanExpiryCheckInterval",   "Verificacion de bans expirados (seg)" },
                { "LoginREST.TicketDuration", "Duracion del ticket de login (seg)" },
            }},
            { "Seguridad", {
                { "LoginREST.TicketDuration",   "Validez del ticket de sesion (seg)" },
            }},
        };

        std::ostringstream j;
        j << "{\"sections\":[";
        bool fs = true;
        for (auto const& sec : sections)
        {
            if (!fs) j << ',';
            fs = false;
            j << "{\"name\":" << JsonStr(sec.name) << ",\"entries\":[";
            bool fe = true;
            for (auto const& e : sec.entries)
            {
                if (!fe) j << ',';
                fe = false;
                std::string val = sConfigMgr->GetStringDefault(e.key, "(sin valor)");
                j << "{\"key\":"   << JsonStr(e.key)
                  << ",\"value\":" << JsonStr(val)
                  << ",\"desc\":"  << JsonStr(e.desc)
                  << "}";
            }
            j << "]}";
        }
        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/maintenance ──────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/maintenance",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        bool active = sAdminBuf.MaintenanceMode.load();
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = std::string("{\"active\":") + (active ? "true" : "false") + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/maintenance ─────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/maintenance",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body = ctx.request.body();
        std::string activeStr = JsonGet(body, "active");
        bool activate = (activeStr == "true" || activeStr == "1");

        sAdminBuf.MaintenanceMode.store(activate);

        // Update realmlist.allowedSecurityLevel so worldserver picks it up
        // SEC_GAMEMASTER=1 blocks non-GMs; SEC_PLAYER=0 allows all
        uint8 secLevel = activate ? 1 : 0;
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE realmlist SET allowedSecurityLevel=%u", secLevel);
        LoginDatabase.DirectExecute(sql);

        if (activate)
            TC_LOG_INFO("server.bnetserver", "Admin panel: Maintenance mode ENABLED. Non-GM players will be kicked.");
        else
            TC_LOG_INFO("server.bnetserver", "Admin panel: Maintenance mode DISABLED. Server open to all players.");

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/players ──────────────────────────────────────────────
    // Returns online players list. DB: characters + hotfixes (cross-db query)
    RegisterHandler(http::verb::get, "/api/players",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);

        auto params  = ParseQuery(ToStdStringView(ctx.request.target()));
        std::string search;
        int faction  = 0;
        if (auto it = params.find("q");       it != params.end()) search  = it->second;
        if (auto it = params.find("faction"); it != params.end())
            try { faction = std::stoi(it->second); } catch (...) {}

        std::string factionWhere;
        if (faction == 1) factionWhere = " AND c.race IN (1,3,4,7,11)";
        else if (faction == 2) factionWhere = " AND c.race IN (2,5,6,8,9,10)";

        std::string searchWhere;
        if (!search.empty())
            searchWhere = " AND c.name LIKE '%" + SqlEsc(search) + "%'";

        auto sql = std::string(
            "SELECT c.guid, c.name, c.race, c.class, c.level, c.xp, c.zone,"
            " (SELECT AreaName FROM hotfixes.area_table WHERE ID=c.zone ORDER BY VerifiedBuild DESC LIMIT 1) as zone_name,"
            " g.name as guild_name,"
            " gr.rname as guild_rank_name"
            " FROM characters.characters c"
            " LEFT JOIN characters.guild_member gm ON c.guid=gm.guid"
            " LEFT JOIN characters.guild g ON gm.guildid=g.guildid"
            " LEFT JOIN characters.guild_rank gr ON gm.guildid=gr.guildid AND gm.rank=gr.rid"
            " WHERE c.online=1") + factionWhere + searchWhere + " ORDER BY c.name";

        auto res = LoginDatabase.Query(sql.c_str());
        std::ostringstream j;
        j << "{\"players\":[";
        bool first = true;
        if (res)
        {
            do {
                auto f = res->Fetch();
                if (!first) j << ',';
                first = false;
                uint32 zone = f[6].GetUInt32();
                j << "{\"guid\":"     << f[0].GetUInt64()
                  << ",\"name\":"     << JsonStr(f[1].GetString())
                  << ",\"race\":"     << (int)f[2].GetUInt8()
                  << ",\"class\":"    << (int)f[3].GetUInt8()
                  << ",\"level\":"    << (int)f[4].GetUInt8()
                  << ",\"xp\":"       << f[5].GetUInt32()
                  << ",\"zone\":"     << zone
                  << ",\"zone_name\":" << JsonStr(f[7].IsNull() ? Trinity::StringFormat("Zona#{}", zone) : f[7].GetString())
                  << ",\"guild\":"    << JsonStr(f[8].IsNull() ? "" : f[8].GetString())
                  << ",\"guild_rank\":" << JsonStr(f[9].IsNull() ? "" : f[9].GetString())
                  << "}";
            } while (res->NextRow());
        }
        j << "]}";
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/player/detail?guid=N ─────────────────────────────────
    RegisterHandler(http::verb::get, "/api/player/detail",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);

        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint64 guid = 0;
        if (auto it = params.find("guid"); it != params.end())
            try { guid = std::stoull(it->second); } catch (...) {}

        if (!guid)
        {
            ctx.response.body() = "{\"error\":\"guid invalido\"}";
            return RequestHandlerResult::Handled;
        }

        // ── Info ──────────────────────────────────────────────────────
        std::ostringstream j;
        j << "{";
        {
            auto sql = Trinity::StringFormat(
                "SELECT c.name,c.race,c.class,c.level,c.xp,c.money,c.zone,c.map,c.totaltime,"
                " (SELECT AreaName FROM hotfixes.area_table WHERE ID=c.zone ORDER BY VerifiedBuild DESC LIMIT 1) as zn"
                " FROM characters.characters c WHERE c.guid={}", guid);
            auto res = LoginDatabase.Query(sql.c_str());
            if (!res) { ctx.response.body() = "{\"error\":\"jugador no encontrado\"}"; return RequestHandlerResult::Handled; }
            auto f = res->Fetch();
            uint64 money = f[5].GetUInt64();
            uint32 zone  = f[6].GetUInt32();
            j << "\"info\":{"
              << "\"name\":"    << JsonStr(f[0].GetString())
              << ",\"race\":"   << (int)f[1].GetUInt8()
              << ",\"class\":"  << (int)f[2].GetUInt8()
              << ",\"level\":"  << (int)f[3].GetUInt8()
              << ",\"xp\":"     << f[4].GetUInt32()
              << ",\"gold\":"   << (money / 10000)
              << ",\"silver\":" << ((money / 100) % 100)
              << ",\"copper\":" << (money % 100)
              << ",\"zone\":"   << zone
              << ",\"zone_name\":" << JsonStr(f[9].IsNull() ? Trinity::StringFormat("Zona#{}", zone) : f[9].GetString())
              << ",\"map\":"    << f[7].GetUInt16()
              << ",\"totaltime\":" << f[8].GetUInt32()
              << "}";
        }

        // ── Achievements ──────────────────────────────────────────────
        j << ",\"achievements\":[";
        {
            // Points are stored only in the server's in-memory DB2 data, not in MySQL.
            // We return the achievement ID, optional title from hotfixes (sparse), and date.
            auto sql = Trinity::StringFormat(
                "SELECT ca.achievement,"
                " (SELECT Title FROM hotfixes.achievement WHERE ID=ca.achievement LIMIT 1) as title,"
                " ca.date"
                " FROM characters.character_achievement ca"
                " WHERE ca.guid={} ORDER BY ca.date DESC LIMIT 500", guid);
            bool first = true;
            if (auto res = LoginDatabase.Query(sql.c_str()))
            {
                do {
                    auto f = res->Fetch();
                    if (!first) j << ','; first = false;
                    j << "{\"id\":" << f[0].GetUInt32()
                      << ",\"title\":" << JsonStr(f[1].IsNull() ? Trinity::StringFormat("#{}", f[0].GetUInt32()) : f[1].GetString())
                      << ",\"date\":"  << f[2].GetInt64()
                      << "}";
                } while (res->NextRow());
            }
        }
        j << "]";

        // ── Professions ───────────────────────────────────────────────
        j << ",\"professions\":[";
        {
            auto sql = Trinity::StringFormat(
                "SELECT skill,value,max,professionSlot"
                " FROM characters.character_skills"
                " WHERE guid={} AND skill IN (129,164,165,171,182,185,186,197,202,333,356,393,755,773)"
                " ORDER BY professionSlot,skill", guid);
            bool first = true;
            if (auto res = LoginDatabase.Query(sql.c_str()))
            {
                do {
                    auto f = res->Fetch();
                    if (!first) j << ','; first = false;
                    j << "{\"skill\":" << f[0].GetUInt16()
                      << ",\"value\":" << f[1].GetUInt16()
                      << ",\"max\":"   << f[2].GetUInt16()
                      << ",\"slot\":"  << (int)f[3].GetInt8()
                      << "}";
                } while (res->NextRow());
            }
        }
        j << "]";

        // ── Inventory (equipment + bags + bank) ───────────────────────
        j << ",\"inventory\":[";
        {
            // Use ANY_VALUE to avoid ONLY_FULL_GROUP_BY issues
            auto sql = Trinity::StringFormat(
                "SELECT ci.bag, ci.slot, ii.itemEntry, ii.count,"
                " ANY_VALUE(isp.Display) as name,"
                " ANY_VALUE(isp.OverallQualityID) as quality"
                " FROM characters.character_inventory ci"
                " JOIN characters.item_instance ii ON ci.item=ii.guid"
                " LEFT JOIN hotfixes.item_sparse isp ON ii.itemEntry=isp.ID"
                " WHERE ci.guid={}"
                " GROUP BY ci.bag,ci.slot,ii.itemEntry,ii.count"
                " ORDER BY ci.bag,ci.slot LIMIT 400", guid);
            bool first = true;
            if (auto res = LoginDatabase.Query(sql.c_str()))
            {
                do {
                    auto f = res->Fetch();
                    if (!first) j << ','; first = false;
                    j << "{\"bag\":"    << f[0].GetUInt64()
                      << ",\"slot\":"   << (int)f[1].GetUInt8()
                      << ",\"entry\":"  << f[2].GetUInt32()
                      << ",\"count\":"  << f[3].GetUInt32()
                      << ",\"name\":"   << JsonStr(f[4].IsNull() ? "" : f[4].GetString())
                      << ",\"quality\":" << (f[5].IsNull() ? 1 : f[5].GetInt8())
                      << "}";
                } while (res->NextRow());
            }
        }
        j << "]";

        // ── Mail ──────────────────────────────────────────────────────
        j << ",\"mail\":[";
        {
            auto mailSql = Trinity::StringFormat(
                "SELECT m.id,m.messageType,m.subject,m.body,m.has_items,m.money,m.expire_time,"
                " CASE WHEN m.messageType=0 THEN (SELECT name FROM characters.characters WHERE guid=m.sender LIMIT 1) ELSE 'Sistema' END as sender_name"
                " FROM characters.mail m"
                " WHERE m.receiver={} ORDER BY m.expire_time DESC LIMIT 30", guid);
            bool firstMail = true;
            if (auto mailRes = LoginDatabase.Query(mailSql.c_str()))
            {
                do {
                    auto f = mailRes->Fetch();
                    uint64 mailId = f[0].GetUInt64();
                    if (!firstMail) j << ','; firstMail = false;
                    j << "{\"id\":"       << mailId
                      << ",\"type\":"     << (int)f[1].GetUInt8()
                      << ",\"subject\":"  << JsonStr(f[2].IsNull() ? "" : f[2].GetString())
                      << ",\"body\":"     << JsonStr(f[3].IsNull() ? "" : f[3].GetString())
                      << ",\"has_items\":" << (f[4].GetUInt8() ? "true" : "false")
                      << ",\"money\":"    << f[5].GetUInt64()
                      << ",\"expire\":"   << f[6].GetInt64()
                      << ",\"sender\":"   << JsonStr(f[7].IsNull() ? "Sistema" : f[7].GetString())
                      << ",\"items\":[";
                    // Mail items
                    auto itemSql = Trinity::StringFormat(
                        "SELECT ii.itemEntry,ii.count,"
                        " ANY_VALUE(isp.Display) as name,"
                        " ANY_VALUE(isp.OverallQualityID) as quality"
                        " FROM characters.mail_items mi"
                        " JOIN characters.item_instance ii ON mi.item_guid=ii.guid"
                        " LEFT JOIN hotfixes.item_sparse isp ON ii.itemEntry=isp.ID"
                        " WHERE mi.mail_id={} GROUP BY ii.itemEntry,ii.count", mailId);
                    bool firstItem = true;
                    if (auto itemRes = LoginDatabase.Query(itemSql.c_str()))
                    {
                        do {
                            auto fi = itemRes->Fetch();
                            if (!firstItem) j << ','; firstItem = false;
                            j << "{\"entry\":" << fi[0].GetUInt32()
                              << ",\"count\":" << fi[1].GetUInt32()
                              << ",\"name\":"  << JsonStr(fi[2].IsNull() ? "" : fi[2].GetString())
                              << ",\"quality\":" << (fi[3].IsNull() ? 1 : fi[3].GetInt8())
                              << "}";
                        } while (itemRes->NextRow());
                    }
                    j << "]}";
                } while (mailRes->NextRow());
            }
        }
        j << "]";

        // ── Guild ─────────────────────────────────────────────────────
        j << ",\"guild\":null";
        {
            auto sql = Trinity::StringFormat(
                "SELECT g.guildid,g.name,g.motd,g.BankMoney,gr.rname,gm.rank"
                " FROM characters.guild_member gm"
                " JOIN characters.guild g ON gm.guildid=g.guildid"
                " JOIN characters.guild_rank gr ON gm.guildid=gr.guildid AND gm.rank=gr.rid"
                " WHERE gm.guid={}", guid);
            if (auto res = LoginDatabase.Query(sql.c_str()))
            {
                auto f = res->Fetch();
                uint64 guildId = f[0].GetUInt64();
                std::ostringstream gj;
                gj << "{\"id\":"        << guildId
                   << ",\"name\":"      << JsonStr(f[1].GetString())
                   << ",\"motd\":"      << JsonStr(f[2].IsNull() ? "" : f[2].GetString())
                   << ",\"bank_money\":" << f[3].GetUInt64()
                   << ",\"rank\":"      << JsonStr(f[4].GetString())
                   << ",\"rank_order\":" << (int)f[5].GetUInt8()
                   << ",\"bank_tabs\":[";
                // Guild bank: group by tab
                auto bankSql = Trinity::StringFormat(
                    "SELECT gbi.TabId,COALESCE(gbt.TabName,'Tab') as tname,gbi.SlotId,ii.itemEntry,ii.count,"
                    " ANY_VALUE(isp.Display) as iname, ANY_VALUE(isp.OverallQualityID) as iquality"
                    " FROM characters.guild_bank_item gbi"
                    " JOIN characters.item_instance ii ON gbi.item_guid=ii.guid"
                    " LEFT JOIN characters.guild_bank_tab gbt ON gbi.guildid=gbt.guildid AND gbi.TabId=gbt.TabId"
                    " LEFT JOIN hotfixes.item_sparse isp ON ii.itemEntry=isp.ID"
                    " WHERE gbi.guildid={}"
                    " GROUP BY gbi.TabId,gbi.SlotId,ii.itemEntry,ii.count,gbt.TabName"
                    " ORDER BY gbi.TabId,gbi.SlotId LIMIT 500", guildId);
                // Build tabs map
                struct TabData { std::string name; std::ostringstream items; bool first{true}; };
                std::map<uint8, TabData> tabs;
                if (auto br = LoginDatabase.Query(bankSql.c_str()))
                {
                    do {
                        auto fb = br->Fetch();
                        uint8 tid = fb[0].GetUInt8();
                        if (tabs.find(tid) == tabs.end())
                            tabs[tid].name = fb[1].GetString();
                        auto& td = tabs[tid];
                        if (!td.first) td.items << ','; td.first = false;
                        td.items << "{\"slot\":"   << (int)fb[2].GetUInt8()
                                 << ",\"entry\":"  << fb[3].GetUInt32()
                                 << ",\"count\":"  << fb[4].GetUInt32()
                                 << ",\"name\":"   << JsonStr(fb[5].IsNull() ? "" : fb[5].GetString())
                                 << ",\"quality\":" << (fb[6].IsNull() ? 1 : fb[6].GetInt8())
                                 << "}";
                    } while (br->NextRow());
                }
                bool firstTab = true;
                for (auto& [tid, td] : tabs)
                {
                    if (!firstTab) gj << ','; firstTab = false;
                    gj << "{\"id\":" << (int)tid
                       << ",\"name\":" << JsonStr(td.name)
                       << ",\"items\":[" << td.items.str() << "]}";
                }
                gj << "]}";
                // Replace null guild in output
                std::string js = j.str();
                auto pos = js.rfind(",\"guild\":null");
                if (pos != std::string::npos)
                    js.replace(pos, 13, ",\"guild\":" + gj.str());
                j.str(""); j.clear(); j << js;
            }
        }

        j << "}";
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/snapshots/search ─────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/snapshots/search",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        std::string type = "char", q;
        if (auto it = params.find("type"); it != params.end()) type = it->second;
        if (auto it = params.find("q");    it != params.end()) q    = it->second;

        std::ostringstream j;
        j << "{\"chars\":[";
        bool first = true;

        if (type == "char" && !q.empty())
        {
            std::string qLow = SqlEsc(q);
            for (char& c : qLow) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            std::string sql =
                "SELECT c.guid, c.name, c.level, c.class, c.race,"
                " c.account as acc_id,"
                " COALESCE(b.id, 0) as bnet_id,"
                " COALESCE(a.username, '') as acc_name,"
                " (SELECT COUNT(*) FROM auth.admin_char_snapshots s WHERE s.char_guid=c.guid) as snap_count"
                " FROM characters.characters c"
                " LEFT JOIN auth.account a ON c.account=a.id"
                " LEFT JOIN auth.battlenet_accounts b ON a.battlenet_account=b.id"
                " WHERE LOWER(c.name) LIKE '%" + qLow + "%'"
                " LIMIT 50";
            auto res = LoginDatabase.Query(sql.c_str());
            if (res) do {
                auto f = res->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"guid\":"         << f[0].GetUInt32()
                  << ",\"name\":"          << JsonStr(f[1].GetString())
                  << ",\"level\":"         << (int)f[2].GetUInt8()
                  << ",\"class\":"         << (int)f[3].GetUInt8()
                  << ",\"race\":"          << (int)f[4].GetUInt8()
                  << ",\"account_id\":"    << f[5].GetUInt32()
                  << ",\"bnet_id\":"       << f[6].GetUInt32()
                  << ",\"account_name\":"  << JsonStr(f[7].GetString())
                  << ",\"snap_count\":"    << f[8].GetUInt64()
                  << "}";
            } while (res->NextRow());
        }
        else if (type == "account" && !q.empty())
        {
            std::string qLow = SqlEsc(q);
            for (char& c : qLow) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            std::string sql =
                "SELECT c.guid, c.name, c.level, c.class, c.race,"
                " c.account as acc_id,"
                " COALESCE(b.id, 0) as bnet_id,"
                " COALESCE(a.username, '') as acc_name,"
                " (SELECT COUNT(*) FROM auth.admin_char_snapshots s WHERE s.char_guid=c.guid) as snap_count"
                " FROM characters.characters c"
                " INNER JOIN auth.account a ON c.account=a.id"
                " LEFT JOIN auth.battlenet_accounts b ON a.battlenet_account=b.id"
                " WHERE LOWER(a.username) LIKE '%" + qLow + "%' OR LOWER(a.email) LIKE '%" + qLow + "%'"
                " LIMIT 100";
            auto res = LoginDatabase.Query(sql.c_str());
            if (res) do {
                auto f = res->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"guid\":"         << f[0].GetUInt32()
                  << ",\"name\":"          << JsonStr(f[1].GetString())
                  << ",\"level\":"         << (int)f[2].GetUInt8()
                  << ",\"class\":"         << (int)f[3].GetUInt8()
                  << ",\"race\":"          << (int)f[4].GetUInt8()
                  << ",\"account_id\":"    << f[5].GetUInt32()
                  << ",\"bnet_id\":"       << f[6].GetUInt32()
                  << ",\"account_name\":"  << JsonStr(f[7].GetString())
                  << ",\"snap_count\":"    << f[8].GetUInt64()
                  << "}";
            } while (res->NextRow());
        }
        else if (type == "ip" && !q.empty())
        {
            std::string safeIp = SqlEsc(q);
            std::string sql =
                "SELECT c.guid, c.name, c.level, c.class, c.race,"
                " c.account as acc_id,"
                " COALESCE(b.id, 0) as bnet_id,"
                " COALESCE(a.username, '') as acc_name,"
                " (SELECT COUNT(*) FROM auth.admin_char_snapshots s WHERE s.char_guid=c.guid) as snap_count"
                " FROM characters.characters c"
                " INNER JOIN auth.account a ON c.account=a.id"
                " LEFT JOIN auth.battlenet_accounts b ON a.battlenet_account=b.id"
                " WHERE a.last_ip='" + safeIp + "'"
                " LIMIT 100";
            auto res = LoginDatabase.Query(sql.c_str());
            if (res) do {
                auto f = res->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"guid\":"         << f[0].GetUInt32()
                  << ",\"name\":"          << JsonStr(f[1].GetString())
                  << ",\"level\":"         << (int)f[2].GetUInt8()
                  << ",\"class\":"         << (int)f[3].GetUInt8()
                  << ",\"race\":"          << (int)f[4].GetUInt8()
                  << ",\"account_id\":"    << f[5].GetUInt32()
                  << ",\"bnet_id\":"       << f[6].GetUInt32()
                  << ",\"account_name\":"  << JsonStr(f[7].GetString())
                  << ",\"snap_count\":"    << f[8].GetUInt64()
                  << "}";
            } while (res->NextRow());
        }

        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/snapshots/list ───────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/snapshots/list",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        constexpr int PAGE_SIZE = 20;
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint32 charGuid = 0;
        int page = 0;
        if (auto it = params.find("char_guid"); it != params.end())
            try { charGuid = static_cast<uint32>(std::stoul(it->second)); } catch (...) {}
        if (auto it = params.find("page"); it != params.end())
            try { page = std::stoi(it->second); } catch (...) {}
        if (page < 0) page = 0;

        if (charGuid == 0) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"error\":\"char_guid requerido\"}";
            return RequestHandlerResult::Handled;
        }

        uint64 total = 0;
        {
            auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.admin_char_snapshots WHERE char_guid=" + std::to_string(charGuid)).c_str());
            if (r) total = r->Fetch()[0].GetUInt64();
        }
        int pages = static_cast<int>((total + PAGE_SIZE - 1) / PAGE_SIZE);
        if (pages < 1) pages = 1;
        if (page >= pages) page = pages - 1;

        std::string sql =
            "SELECT id, UNIX_TIMESTAMP(snapshot_time), snap_type, label, LENGTH(data_json)"
            " FROM auth.admin_char_snapshots WHERE char_guid=" + std::to_string(charGuid) +
            " ORDER BY snapshot_time DESC LIMIT " + std::to_string(PAGE_SIZE) +
            " OFFSET " + std::to_string(page * PAGE_SIZE);

        std::ostringstream j;
        j << "{\"total\":" << total << ",\"page\":" << page << ",\"pages\":" << pages << ",\"snapshots\":[";
        bool first = true;
        auto res = LoginDatabase.Query(sql.c_str());
        if (res) do {
            auto f = res->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"         << f[0].GetUInt64()
              << ",\"ts\":"          << f[1].GetInt64()
              << ",\"snap_type\":"   << (int)f[2].GetUInt8()
              << ",\"label\":"       << JsonStr(f[3].GetString())
              << ",\"size_bytes\":"  << f[4].GetUInt64()
              << "}";
        } while (res->NextRow());
        j << "]}";

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/snapshots/create ────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/snapshots/create",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto body = ctx.request.body();
        uint32 charGuid  = static_cast<uint32>(JsonGetInt(body, "char_guid"));
        uint32 accountId = static_cast<uint32>(JsonGetInt(body, "account_id"));
        uint32 bnetId    = static_cast<uint32>(JsonGetInt(body, "bnet_id"));
        std::string label = JsonGet(body, "label");
        int snapType = static_cast<int>(JsonGetInt(body, "snap_type"));

        if (charGuid == 0) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"char_guid requerido\"}";
            return RequestHandlerResult::Handled;
        }

        uint64 newId = TakeCharSnapshot(charGuid, accountId, bnetId, label, snapType);
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = newId > 0
            ? "{\"ok\":true,\"snapshot_id\":" + std::to_string(newId) + "}"
            : "{\"ok\":false,\"error\":\"Error al crear snapshot\"}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/snapshots/create-bulk ──────────────────────────────
    RegisterHandler(http::verb::post, "/api/snapshots/create-bulk",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto body = ctx.request.body();
        uint32 accountId = static_cast<uint32>(JsonGetInt(body, "account_id"));
        uint32 bnetId    = static_cast<uint32>(JsonGetInt(body, "bnet_id"));
        std::string label = JsonGet(body, "label");
        int snapType = static_cast<int>(JsonGetInt(body, "snap_type"));

        // Parse char_guids array from JSON manually
        auto pos = body.find("\"char_guids\"");
        if (pos == std::string::npos) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"char_guids requerido\"}";
            return RequestHandlerResult::Handled;
        }
        auto arrStart = body.find('[', pos);
        auto arrEnd   = body.find(']', arrStart);
        int count = 0;
        if (arrStart != std::string::npos && arrEnd != std::string::npos)
        {
            std::string arr = body.substr(arrStart + 1, arrEnd - arrStart - 1);
            std::istringstream ss(arr);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                tok.erase(tok.begin(), std::find_if(tok.begin(), tok.end(), [](unsigned char c){ return !std::isspace(c); }));
                tok.erase(std::find_if(tok.rbegin(), tok.rend(), [](unsigned char c){ return !std::isspace(c); }).base(), tok.end());
                try {
                    uint32 guid = static_cast<uint32>(std::stoul(tok));
                    if (guid > 0) { TakeCharSnapshot(guid, accountId, bnetId, label, snapType); count++; }
                } catch (...) {}
            }
        }
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"count\":" + std::to_string(count) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/snapshots/restore ───────────────────────────────────
    RegisterHandler(http::verb::post, "/api/snapshots/restore",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto body = ctx.request.body();
        uint64 snapId   = static_cast<uint64>(JsonGetInt(body, "snapshot_id"));
        bool autoBackup = JsonGet(body, "auto_backup") != "false";

        if (snapId == 0) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"snapshot_id requerido\"}";
            return RequestHandlerResult::Handled;
        }

        std::string err = RestoreCharSnapshot(snapId, autoBackup);
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = err.empty()
            ? "{\"ok\":true}"
            : "{\"ok\":false,\"error\":" + JsonStr(err) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/snapshots/delete ────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/snapshots/delete",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto body = ctx.request.body();
        uint64 snapId = static_cast<uint64>(JsonGetInt(body, "snapshot_id"));

        if (snapId == 0) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"snapshot_id requerido\"}";
            return RequestHandlerResult::Handled;
        }

        LoginDatabase.DirectExecute(("DELETE FROM auth.admin_char_snapshots WHERE id=" + std::to_string(snapId)).c_str());
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ─────────────────────────────────────────────────────────────────
    // PORTAL PUBLIC API
    // ─────────────────────────────────────────────────────────────────

    // Helper lambda (captured by value in each handler — stateless)
    auto portalAuth = [](RequestContext& ctx) -> uint32 {
        // Extract X-Portal-Token header, validate against portal_sessions
        std::string token;
        for (auto& f : ctx.request)
            if (f.name_string() == "x-portal-token") { token = std::string(f.value()); break; }
        if (token.empty()) return 0;
        auto r = LoginDatabase.Query(("SELECT bnet_account_id FROM auth.portal_sessions"
            " WHERE session_token='" + SqlEsc(token) + "' AND expires_at > NOW() LIMIT 1").c_str());
        return r ? r->Fetch()[0].GetUInt32() : 0;
    };

    // ── GET /api/portal/status ────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/status",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto& buf = sAdminBuf;
        uint32 online = 0, chars = 0, guilds = 0;
        if (auto r = LoginDatabase.Query("SELECT COUNT(*) FROM characters.characters WHERE online=1"))
            online = r->Fetch()[0].GetUInt32();
        if (auto r = LoginDatabase.Query("SELECT COUNT(*) FROM characters.characters"))
            chars = r->Fetch()[0].GetUInt32();
        if (auto r = LoginDatabase.Query("SELECT COUNT(*) FROM characters.guild"))
            guilds = r->Fetch()[0].GetUInt32();

        auto realms = sRealmList->GetAllRealms();
        std::ostringstream j;
        j << "{\"online\":" << online
          << ",\"chars\":"  << chars
          << ",\"guilds\":" << guilds
          << ",\"uptime\":" << JsonStr(UptimeStr(buf.StartTime))
          << ",\"realms\":[";
        bool first = true;
        for (auto const& [h, realm] : realms) {
            if (!first) j << ','; first = false;
            j << "{\"name\":" << JsonStr(realm.Name)
              << ",\"online\":" << ((realm.Flags & REALM_FLAG_OFFLINE) ? "false" : "true")
              << ",\"pop\":" << realm.PopulationLevel << "}";
        }
        j << "],\"rates\":{";
        bool firstRate = true;
        if (auto r = LoginDatabase.Query("SELECT key_, value_ FROM auth.portal_config WHERE key_ LIKE 'rate_%'")) do {
            auto f = r->Fetch();
            std::string key = f[0].GetString();
            if (key.size() > 5) key = key.substr(5); // strip "rate_"
            if (!firstRate) j << ','; firstRate = false;
            j << JsonStr(key) << ':' << JsonStr(f[1].GetString());
        } while (r->NextRow());
        j << "}}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/news?page=N&cat= ─────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/news",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        int page = 0; std::string cat;
        if (auto it = params.find("page"); it != params.end())
            try { page = std::max(0, std::stoi(it->second)); } catch(...) {}
        if (auto it = params.find("cat");  it != params.end()) cat = it->second;
        int perPage = 9;

        std::string where = "WHERE is_published=1";
        if (!cat.empty() && cat != "all") where += " AND category='" + SqlEsc(cat) + "'";

        uint32 total = 0;
        if (auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.portal_news " + where).c_str()))
            total = r->Fetch()[0].GetUInt32();

        std::string sql = "SELECT id,title,category,summary,image_url,author,DATE_FORMAT(created_at,'%d-%m-%Y'),views,is_featured"
            " FROM auth.portal_news " + where + " ORDER BY is_featured DESC, created_at DESC"
            " LIMIT " + std::to_string(perPage) + " OFFSET " + std::to_string(page * perPage);

        std::ostringstream j;
        j << "{\"total\":" << total << ",\"page\":" << page
          << ",\"pages\":" << ((total + perPage - 1) / perPage) << ",\"news\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(sql.c_str())) do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"       << f[0].GetUInt32()
              << ",\"title\":"    << JsonStr(f[1].GetString())
              << ",\"category\":" << JsonStr(f[2].GetString())
              << ",\"summary\":"  << JsonStr(f[3].GetString())
              << ",\"image\":"    << JsonStr(f[4].GetString())
              << ",\"author\":"   << JsonStr(f[5].GetString())
              << ",\"date\":"     << JsonStr(f[6].GetString())
              << ",\"views\":"    << f[7].GetUInt32()
              << ",\"featured\":" << (f[8].GetUInt8() ? "true" : "false")
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/news/article?id=N ────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/news/article",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint32 id = 0;
        if (auto it = params.find("id"); it != params.end())
            try { id = static_cast<uint32>(std::stoul(it->second)); } catch (...) {}
        if (!id) { ctx.response.result(http::status::bad_request); ctx.response.body() = "{}"; return RequestHandlerResult::Handled; }
        LoginDatabase.DirectExecute(("UPDATE auth.portal_news SET views=views+1 WHERE id=" + std::to_string(id)).c_str());
        if (auto r = LoginDatabase.Query(("SELECT id,title,category,content,image_url,author,DATE_FORMAT(created_at,'%d-%m-%Y'),views"
            " FROM auth.portal_news WHERE id=" + std::to_string(id)).c_str()))
        {
            auto f = r->Fetch();
            std::ostringstream j;
            j << "{\"id\":" << f[0].GetUInt32() << ",\"title\":" << JsonStr(f[1].GetString())
              << ",\"category\":" << JsonStr(f[2].GetString()) << ",\"content\":" << JsonStr(f[3].GetString())
              << ",\"image\":" << JsonStr(f[4].GetString()) << ",\"author\":" << JsonStr(f[5].GetString())
              << ",\"date\":" << JsonStr(f[6].GetString()) << ",\"views\":" << f[7].GetUInt32() << "}";
            ctx.response.result(http::status::ok);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = j.str();
        } else {
            ctx.response.result(http::status::not_found);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"error\":\"not found\"}";
        }
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/rankings?type= ───────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/rankings",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        std::string type = "honor";
        if (auto it = params.find("type"); it != params.end()) type = it->second;

        std::ostringstream j;

        // ── honor ─────────────────────────────────────────────────────
        if (type == "honor") {
            j << "{\"type\":\"honor\",\"rows\":[";
            bool first = true;
            if (auto r = LoginDatabase.Query(
                "SELECT name, race, class, totalKills, todayKills"
                " FROM characters.characters WHERE totalKills > 0"
                " ORDER BY totalKills DESC LIMIT 10"))
            do {
                auto f = r->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"name\":"  << JsonStr(f[0].GetString())
                  << ",\"race\":"  << (uint32_t)f[1].GetUInt8()
                  << ",\"class\":" << (uint32_t)f[2].GetUInt8()
                  << ",\"value\":" << f[3].GetUInt32()
                  << ",\"today\":" << f[4].GetUInt32() << "}";
            } while (r->NextRow());
            j << "]}";

        // ── level ─────────────────────────────────────────────────────
        } else if (type == "level") {
            j << "{\"type\":\"level\",\"rows\":[";
            bool first = true;
            if (auto r = LoginDatabase.Query(
                "SELECT name, level, race, class, totaltime FROM characters.characters"
                " ORDER BY level DESC, totaltime DESC LIMIT 10"))
            do {
                auto f = r->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"name\":"  << JsonStr(f[0].GetString())
                  << ",\"level\":" << (uint32_t)f[1].GetUInt8()
                  << ",\"race\":"  << (uint32_t)f[2].GetUInt8()
                  << ",\"class\":" << (uint32_t)f[3].GetUInt8()
                  << ",\"value\":" << f[4].GetUInt32() << "}";
            } while (r->NextRow());
            j << "]}";

        // ── guilds ────────────────────────────────────────────────────
        } else if (type == "guilds") {
            j << "{\"type\":\"guilds\",\"rows\":[";
            bool first = true;
            if (auto r = LoginDatabase.Query(
                "SELECT g.name, COUNT(gm.guid) AS members, g.createdate"
                " FROM characters.guild g"
                " LEFT JOIN characters.guild_member gm ON g.guildid=gm.guildid"
                " GROUP BY g.guildid ORDER BY members DESC LIMIT 20"))
            do {
                auto f = r->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"name\":"  << JsonStr(f[0].GetString())
                  << ",\"value\":" << f[1].GetUInt32()
                  << ",\"since\":" << f[2].GetUInt32() << "}";
            } while (r->NextRow());
            j << "]}";

        // ── classes ───────────────────────────────────────────────────
        } else if (type == "classes") {
            // Alliance races: 1,3,4,7,11  Horde: 2,5,6,8,10
            static const uint8_t allianceRaces[] = {1,3,4,7,11};
            std::map<uint8_t, uint32_t> classTot, classA, classH;
            if (auto r = LoginDatabase.Query(
                "SELECT class, race, COUNT(*) FROM characters.characters GROUP BY class, race")) do {
                auto f = r->Fetch();
                uint8_t cls = f[0].GetUInt8(), race = f[1].GetUInt8();
                uint32_t cnt = f[2].GetUInt32();
                classTot[cls] += cnt;
                bool isA = false;
                for (uint8_t ar : allianceRaces) if (race == ar) { isA = true; break; }
                if (isA) classA[cls] += cnt; else classH[cls] += cnt;
            } while (r->NextRow());
            // Realm name
            auto realms = sRealmList->GetAllRealms();
            std::string realmName = realms.empty() ? "Servidor" : realms.begin()->second.Name;
            j << "{\"type\":\"classes\",\"realm\":" << JsonStr(realmName) << ",\"classes\":[";
            bool first = true;
            for (auto& [cls, tot] : classTot) {
                if (!first) j << ','; first = false;
                j << "{\"id\":" << (uint32_t)cls
                  << ",\"total\":" << tot
                  << ",\"alliance\":" << classA[cls]
                  << ",\"horde\":" << classH[cls] << "}";
            }
            j << "]}";

        // ── races ─────────────────────────────────────────────────────
        } else if (type == "races") {
            static const uint8_t allianceRaces[] = {1,3,4,7,11};
            std::map<uint8_t, uint32_t> raceTot, raceA, raceH;
            if (auto r = LoginDatabase.Query(
                "SELECT race, COUNT(*) FROM characters.characters GROUP BY race")) do {
                auto f = r->Fetch();
                uint8_t race = f[0].GetUInt8();
                uint32_t cnt = f[1].GetUInt32();
                raceTot[race] += cnt;
                bool isA = false;
                for (uint8_t ar : allianceRaces) if (race == ar) { isA = true; break; }
                if (isA) raceA[race] += cnt; else raceH[race] += cnt;
            } while (r->NextRow());
            auto realms = sRealmList->GetAllRealms();
            std::string realmName = realms.empty() ? "Servidor" : realms.begin()->second.Name;
            j << "{\"type\":\"races\",\"realm\":" << JsonStr(realmName) << ",\"races\":[";
            bool first = true;
            for (auto& [race, tot] : raceTot) {
                if (!first) j << ','; first = false;
                j << "{\"id\":" << (uint32_t)race
                  << ",\"total\":" << tot
                  << ",\"alliance\":" << raceA[race]
                  << ",\"horde\":" << raceH[race] << "}";
            }
            j << "]}";

        // ── achievements ──────────────────────────────────────────────
        } else if (type == "achievements") {
            // Top 10 by total achievement POINTS (from auth.achievement_pts, synced from DB2 at worldserver startup)
            j << "{\"type\":\"achievements\",\"top\":[";
            bool first = true;
            if (auto r = LoginDatabase.Query(
                "SELECT c.name, c.race, c.class, COALESCE(SUM(ap.points),0) AS pts"
                " FROM characters.character_achievement ca"
                " JOIN characters.characters c ON ca.guid=c.guid"
                " LEFT JOIN auth.achievement_pts ap ON ap.id=ca.achievement"
                " GROUP BY ca.guid, c.name, c.race, c.class"
                " ORDER BY pts DESC LIMIT 10")) do {
                auto f = r->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"name\":"  << JsonStr(f[0].GetString())
                  << ",\"race\":"  << (uint32_t)f[1].GetUInt8()
                  << ",\"class\":" << (uint32_t)f[2].GetUInt8()
                  << ",\"pts\":"   << f[3].GetUInt32() << "}";
            } while (r->NextRow());

            // First to level 80 per class+race (achievement 13 = Level 80)
            // Also capture the absolute first character ever to reach 80
            j << "],\"first80\":[";
            std::map<uint32_t, std::tuple<std::string,uint8_t,uint8_t,int64_t>> first80;
            std::string absFirst80Name; uint8_t absFirst80Race = 0, absFirst80Class = 0; int64_t absFirst80Date = 0;
            if (auto r = LoginDatabase.Query(
                "SELECT c.name, c.race, c.class, ca.date"
                " FROM characters.character_achievement ca"
                " JOIN characters.characters c ON ca.guid=c.guid"
                " WHERE ca.achievement=13 ORDER BY ca.date ASC")) do {
                auto f = r->Fetch();
                uint8_t race = f[1].GetUInt8(), cls = f[2].GetUInt8();
                int64_t date = f[3].GetInt64();
                uint32_t key = (uint32_t)cls * 100 + race;
                if (!first80.count(key))
                    first80[key] = {f[0].GetString(), race, cls, date};
                // The very first row (lowest date) is the absolute first
                if (absFirst80Name.empty()) {
                    absFirst80Name  = f[0].GetString();
                    absFirst80Race  = race;
                    absFirst80Class = cls;
                    absFirst80Date  = date;
                }
            } while (r->NextRow());
            first = true;
            for (auto& [key, val] : first80) {
                if (!first) j << ','; first = false;
                auto& [name, race, cls, date] = val;
                j << "{\"name\":"  << JsonStr(name)
                  << ",\"race\":"  << (uint32_t)race
                  << ",\"class\":" << (uint32_t)cls
                  << ",\"date\":"  << date << "}";
            }
            // Absolute first to 80 on the server
            j << "],\"absoluteFirst\":";
            if (!absFirst80Name.empty())
                j << "{\"name\":"  << JsonStr(absFirst80Name)
                  << ",\"race\":"  << (uint32_t)absFirst80Race
                  << ",\"class\":" << (uint32_t)absFirst80Class
                  << ",\"date\":"  << absFirst80Date << "}";
            else
                j << "null";
            j << "}";

        } else {
            j << "{\"type\":" << JsonStr(type) << ",\"rows\":[]}";
        }

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/register ─────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/register",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body  = ctx.request.body();
        std::string email = JsonGet(body, "email");
        std::string pass  = JsonGet(body, "password");
        auto fail = [&](char const* msg) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = std::string("{\"ok\":false,\"error\":\"") + msg + "\"}";
        };
        if (email.size() < 5 || email.size() > 320) { fail("Email invalido"); return RequestHandlerResult::Handled; }
        if (pass.size() < 6 || pass.size() > 64)    { fail("Password debe tener entre 6 y 64 caracteres"); return RequestHandlerResult::Handled; }

        std::string emailUp = email;
        Utf8ToUpperOnlyLatin(emailUp);

        if (LoginDatabase.Query(("SELECT id FROM battlenet_accounts WHERE email='" + SqlEsc(emailUp) + "'").c_str())) {
            fail("Este email ya esta registrado"); return RequestHandlerResult::Handled;
        }

        // Create BNet account
        {
            std::string srpUser = ByteArrayToHexStr(Trinity::Crypto::SHA256::GetDigestOf(emailUp));
            auto [salt, verifier] = Trinity::Crypto::SRP6::MakeRegistrationData<BnetSRP6>(srpUser, pass);
            LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_BNET_ACCOUNT);
            stmt->setString(0, emailUp);
            stmt->setInt8(1, 2);
            stmt->setBinary(2, salt);
            stmt->setBinary(3, verifier);
            LoginDatabase.DirectExecute(stmt);
        }
        uint32 bnetId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM battlenet_accounts WHERE email='" + SqlEsc(emailUp) + "'").c_str()))
            bnetId = r->Fetch()[0].GetUInt32();
        if (!bnetId) { fail("Error interno al crear cuenta"); return RequestHandlerResult::Handled; }

        // Create game account
        {
            std::string gUser = Trinity::StringFormat("{}#1", bnetId);
            std::string gPass = pass.substr(0, 16);
            Utf8ToUpperOnlyLatin(gPass); Utf8ToUpperOnlyLatin(gUser);
            auto [salt, verifier] = Trinity::Crypto::SRP6::MakeRegistrationData<GameSRP6>(gUser, gPass);
            LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_ACCOUNT);
            stmt->setString(0, gUser); stmt->setBinary(1, salt); stmt->setBinary(2, verifier);
            stmt->setString(3, emailUp); stmt->setString(4, emailUp);
            stmt->setUInt32(5, bnetId); stmt->setUInt8(6, 1);
            LoginDatabase.DirectExecute(stmt);
        }
        TC_LOG_INFO("server.bnetserver", "Portal: New account email='{}' bnetId={}", emailUp, bnetId);
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/login ────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/login",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body  = ctx.request.body();
        std::string email = JsonGet(body, "email");
        std::string pass  = JsonGet(body, "password");
        auto fail = [&](char const* msg) {
            ctx.response.result(http::status::unauthorized);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = std::string("{\"ok\":false,\"error\":\"") + msg + "\"}";
        };
        if (email.empty() || pass.empty()) { fail("Credenciales requeridas"); return RequestHandlerResult::Handled; }
        std::string emailUp = email; Utf8ToUpperOnlyLatin(emailUp);

        // Fetch BNet account (battlenet_accounts has no 'locked' column; bans live in battlenet_account_bans)
        auto r = LoginDatabase.Query(("SELECT id, salt, verifier FROM battlenet_accounts WHERE email='" + SqlEsc(emailUp) + "'").c_str());
        if (!r) { fail("Email o contrasena incorrectos"); return RequestHandlerResult::Handled; }
        auto fv = r->Fetch();
        uint32 bnetId = fv[0].GetUInt32();

        // Verify password via SRP6 (v2: no uppercase, case-sensitive PBKDF2)
        Trinity::Crypto::SRP::Salt     salt     = fv[1].GetBinary<Trinity::Crypto::SRP::SALT_LENGTH>();
        Trinity::Crypto::SRP::Verifier verifier = fv[2].GetBinary();
        std::string srpUser = ByteArrayToHexStr(Trinity::Crypto::SHA256::GetDigestOf(emailUp));
        Trinity::Crypto::SRP::BnetSRP6v2<Trinity::Crypto::SHA256> srpChk(srpUser, salt, verifier);
        if (!srpChk.CheckCredentials(srpUser, pass)) { fail("Email o contrasena incorrectos"); return RequestHandlerResult::Handled; }

        // Create session token
        std::string token;
        {
            std::array<uint8, 32> rand;
            Trinity::Crypto::GetRandomBytes(rand);
            token = ByteArrayToHexStr(rand);
        }
        std::string ip;
        // Get client IP from X-Forwarded-For or direct
        for (auto& hf : ctx.request)
            if (hf.name_string() == "x-forwarded-for") { ip = std::string(hf.value()); break; }

        LoginDatabase.DirectExecute(
            ("INSERT INTO auth.portal_sessions (bnet_account_id,session_token,ip_address,expires_at)"
             " VALUES (" + std::to_string(bnetId) + ",'" + SqlEsc(token) + "','" + SqlEsc(ip) + "'"
             ",DATE_ADD(NOW(),INTERVAL 7 DAY))").c_str());
        LogActivity(bnetId, "security", "login", 0, "Inicio de sesion", ip);

        std::ostringstream j;
        j << "{\"ok\":true,\"token\":" << JsonStr(token)
          << ",\"bnetId\":" << bnetId << ",\"email\":" << JsonStr(emailUp) << "}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/logout ───────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/logout",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string token;
        for (auto& hf : ctx.request)
            if (hf.name_string() == "x-portal-token") { token = std::string(hf.value()); break; }
        if (!token.empty())
            LoginDatabase.DirectExecute(("DELETE FROM auth.portal_sessions WHERE session_token='" + SqlEsc(token) + "'").c_str());
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/account ───────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/account",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}";
            return RequestHandlerResult::Handled;
        }

        // Helper: lowercase + mask email (show up to 6 chars, then ***)
        auto lowerStr = [](std::string s) -> std::string {
            for (auto& c : s) c = (char)std::tolower((unsigned char)c);
            return s;
        };
        auto maskEmail = [&lowerStr](std::string raw) -> std::string {
            std::string e = lowerStr(raw);
            auto at = e.find('@');
            if (at == std::string::npos || at == 0) return "***";
            size_t show = std::min(at, (size_t)6);
            return e.substr(0, show) + "***" + e.substr(at);
        };

        // BNet account data
        // Use DATE_FORMAT to convert timestamp to string — Date type has no converter (nullptr crash)
        std::string bnetEmail, joindate, lastWebIp;
        uint32 donatePts = 0;
        if (auto r = LoginDatabase.Query(("SELECT email, DATE_FORMAT(joindate,'%H:%i:%s %d-%m-%Y'), last_ip, battlePayCredits, voteCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str())) {
            auto f = r->Fetch();
            bnetEmail  = f[0].GetString();
            joindate   = f[1].GetString();
            lastWebIp  = f[2].GetString();
            donatePts  = f[3].GetUInt32();
            // voteCredits (f[4]) fetched below
        }
        uint32 votePts = 0;
        if (auto r = LoginDatabase.Query(("SELECT voteCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            votePts = r->Fetch()[0].GetUInt32();

        // Game account data — pick first sub-account linked to this bnet id
        uint32 accId = 0;
        std::string accEmail, regMail, srvIp;
        bool has2FA = false;
        uint32 recruiter = 0;
        if (auto r = LoginDatabase.Query(("SELECT id, email, reg_mail, last_ip, totp_secret, recruiter FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str())) {
            auto f = r->Fetch();
            accId     = f[0].GetUInt32();
            accEmail  = f[1].GetString();
            regMail   = f[2].GetString();
            srvIp     = f[3].GetString();
            has2FA    = !f[4].IsNull();   // totp_secret NOT NULL → 2FA activo
            recruiter = f[5].GetUInt32();
        }

        // Last web IP from most recent portal session
        if (auto r = LoginDatabase.Query(("SELECT ip_address FROM portal_sessions WHERE bnet_account_id=" + std::to_string(bnetId) + " ORDER BY expires_at DESC LIMIT 1").c_str()))
            lastWebIp = r->Fetch()[0].GetString();

        // Is account banned
        bool isBanned = false;
        if (auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM battlenet_account_bans WHERE id=" + std::to_string(bnetId) + " AND unbandate>=UNIX_TIMESTAMP()").c_str()))
            isBanned = r->Fetch()[0].GetUInt32() > 0;

        // Recruited friends count (accounts whose recruiter = any account.id linked to this bnet)
        uint32 friendsRecruited = 0;
        if (accId) {
            if (auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM account WHERE recruiter IN (SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + ")").c_str()))
                friendsRecruited = r->Fetch()[0].GetUInt32();
        }

        // Account name: battletag if set, else email prefix (lowercase)
        std::string bnetEmailLow = lowerStr(bnetEmail);
        std::string accName;
        auto atPos = bnetEmailLow.find('@');
        accName = (atPos != std::string::npos) ? bnetEmailLow.substr(0, atPos) : bnetEmailLow;

        std::ostringstream j;
        j << "{\"ok\":true"
          << ",\"bnetId\":"          << bnetId
          << ",\"accountId\":"       << accId
          << ",\"accName\":"         << JsonStr(accName)
          << ",\"regMail\":"         << JsonStr(maskEmail(regMail.empty() ? bnetEmail : regMail))
          << ",\"curMail\":"         << JsonStr(maskEmail(accEmail.empty() ? bnetEmail : accEmail))
          << ",\"joindate\":"        << JsonStr(joindate)
          << ",\"lastWebIp\":"       << JsonStr(lastWebIp)
          << ",\"lastSrvIp\":"       << JsonStr(srvIp)
          << ",\"donatePts\":"       << donatePts
          << ",\"votePts\":"         << votePts
          << ",\"has2FA\":"          << (has2FA ? "true" : "false")
          << ",\"isBanned\":"        << (isBanned ? "true" : "false")
          << ",\"isRecruited\":"     << (recruiter > 0 ? "true" : "false")
          << ",\"friendsRecruited\":" << friendsRecruited
          << ",\"chars\":[";

        // Characters
        bool first = true;
        if (accId) {
            if (auto r = LoginDatabase.Query(
                ("SELECT guid, name, level, race, class, gender, online"
                 " FROM characters.characters WHERE account=" + std::to_string(accId)).c_str()))
            do {
                auto f = r->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"guid\":"   << f[0].GetUInt64()
                  << ",\"name\":"   << JsonStr(f[1].GetString())
                  << ",\"level\":"  << (uint32_t)f[2].GetUInt8()
                  << ",\"race\":"   << (uint32_t)f[3].GetUInt8()
                  << ",\"class\":"  << (uint32_t)f[4].GetUInt8()
                  << ",\"gender\":" << (uint32_t)f[5].GetUInt8()
                  << ",\"online\":" << (f[6].GetUInt8() ? "true" : "false")
                  << "}";
            } while (r->NextRow());
        }
        j << "]}";
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/account/password ────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/account/password",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}";
            return RequestHandlerResult::Handled;
        }
        std::string pwdIp; for (auto& hf : ctx.request) if (hf.name_string() == "x-forwarded-for") { pwdIp = std::string(hf.value()); break; }
        std::string body  = ctx.request.body();
        std::string newp  = JsonGet(body, "new_password");
        if (newp.size() < 6 || newp.size() > 64) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Nueva password debe tener 6-64 caracteres\"}";
            return RequestHandlerResult::Handled;
        }
        // Fetch email for SRP username derivation
        auto vr = LoginDatabase.Query(("SELECT email FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str());
        if (!vr) { ctx.response.result(http::status::internal_server_error); ctx.response.body() = "{}"; return RequestHandlerResult::Handled; }
        std::string emailUp = vr->Fetch()[0].GetString();
        Utf8ToUpperOnlyLatin(emailUp);
        std::string srpUser = ByteArrayToHexStr(Trinity::Crypto::SHA256::GetDigestOf(emailUp));
        // Update BNet password (session token already proves identity)
        {
            auto [ns, nv] = Trinity::Crypto::SRP6::MakeRegistrationData<BnetSRP6>(srpUser, newp);
            LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET salt='" + ByteArrayToHexStr(ns) +
                "',verifier='" + ByteArrayToHexStr(nv) + "' WHERE id=" + std::to_string(bnetId)).c_str());
        }
        // Update game account password
        {
            std::string gUser = Trinity::StringFormat("{}#1", bnetId);
            std::string gPass = newp.substr(0, 16);
            Utf8ToUpperOnlyLatin(gPass); Utf8ToUpperOnlyLatin(gUser);
            auto [ns, nv] = Trinity::Crypto::SRP6::MakeRegistrationData<GameSRP6>(gUser, gPass);
            LoginDatabase.DirectExecute(("UPDATE account SET salt='" + ByteArrayToHexStr(ns) +
                "',verifier='" + ByteArrayToHexStr(nv) + "' WHERE battlenet_account=" + std::to_string(bnetId)).c_str());
        }
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        LogActivity(bnetId, "security", "password_change", 0, "Contrasena actualizada", pwdIp);
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/account/2fa/setup ────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/account/2fa/setup",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        // Generate 20-byte random TOTP secret
        Trinity::Crypto::TOTP::Secret secret(Trinity::Crypto::TOTP::RECOMMENDED_SECRET_LENGTH);
        Trinity::Crypto::GetRandomBytes(secret.data(), secret.size());
        std::string b32 = Base32Encode(secret);
        // Store pending secret (expires old one if exists)
        std::string hexSecret;
        for (uint8 b : secret) { char buf[3]; snprintf(buf, sizeof(buf), "%02X", b); hexSecret += buf; }
        LoginDatabase.DirectExecute(("REPLACE INTO auth.portal_2fa_pending (bnet_id,secret) VALUES(" +
            std::to_string(bnetId) + ",UNHEX('" + hexSecret + "'))").c_str());
        // Get server name for OTP label
        std::string srvName = PortalCfg("server_name");
        if (srvName.empty()) srvName = "Servidor";
        // Get account email
        std::string email;
        if (auto r = LoginDatabase.Query(("SELECT email FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            email = r->Fetch()[0].GetString();
        // Build otpauth URI
        std::string otpUri = "otpauth://totp/" + SqlEsc(srvName) + ":" + SqlEsc(email) +
            "?secret=" + b32 + "&issuer=" + SqlEsc(srvName) + "&algorithm=SHA1&digits=6&period=30";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"secret\":" + JsonStr(b32) + ",\"otpUri\":" + JsonStr(otpUri) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/account/2fa/enable ──────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/account/2fa/enable",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string fa2Ip; for (auto& hf : ctx.request) if (hf.name_string() == "x-forwarded-for") { fa2Ip = std::string(hf.value()); break; }
        std::string body = ctx.request.body();
        std::string code = JsonGet(body, "code");
        if (code.size() != 6) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo de 6 digitos requerido\"}"; return RequestHandlerResult::Handled; }
        uint32 token = 0;
        try { token = static_cast<uint32>(std::stoul(code)); } catch (...) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo invalido\"}"; return RequestHandlerResult::Handled; }
        // Load pending secret
        auto r = LoginDatabase.Query(("SELECT HEX(secret) FROM auth.portal_2fa_pending WHERE bnet_id=" + std::to_string(bnetId) +
            " AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)").c_str());
        if (!r) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Sesion expirada, genera nuevo codigo QR\"}"; return RequestHandlerResult::Handled; }
        std::string hexSec = r->Fetch()[0].GetString();
        Trinity::Crypto::TOTP::Secret secret;
        for (size_t i = 0; i + 1 < hexSec.size(); i += 2) {
            uint8 b = (uint8)std::stoul(hexSec.substr(i, 2), nullptr, 16);
            secret.push_back(b);
        }
        if (!Trinity::Crypto::TOTP::ValidateToken(secret, token)) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo incorrecto, verifica tu app\"}";
            return RequestHandlerResult::Handled;
        }
        // Save secret to all game accounts linked to this bnet account
        LoginDatabase.DirectExecute(("UPDATE account SET totp_secret=UNHEX('" + hexSec + "') WHERE battlenet_account=" + std::to_string(bnetId)).c_str());
        LoginDatabase.DirectExecute(("DELETE FROM auth.portal_2fa_pending WHERE bnet_id=" + std::to_string(bnetId)).c_str());
        LogActivity(bnetId, "security", "2fa_enable", 0, "2FA activado", fa2Ip);
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/account/2fa/disable ─────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/account/2fa/disable",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string dis2Ip; for (auto& hf : ctx.request) if (hf.name_string() == "x-forwarded-for") { dis2Ip = std::string(hf.value()); break; }
        std::string body = ctx.request.body();
        std::string code = JsonGet(body, "code");
        uint32 token = 0;
        try { token = static_cast<uint32>(std::stoul(code)); } catch (...) {}
        // Verify current TOTP before disabling
        auto r = LoginDatabase.Query(("SELECT HEX(totp_secret) FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " AND totp_secret IS NOT NULL LIMIT 1").c_str());
        if (!r) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"2FA no esta activado\"}"; return RequestHandlerResult::Handled; }
        std::string hexSec = r->Fetch()[0].GetString();
        Trinity::Crypto::TOTP::Secret secret;
        for (size_t i = 0; i + 1 < hexSec.size(); i += 2)
            secret.push_back((uint8)std::stoul(hexSec.substr(i, 2), nullptr, 16));
        if (!Trinity::Crypto::TOTP::ValidateToken(secret, token)) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo TOTP incorrecto\"}";
            return RequestHandlerResult::Handled;
        }
        LoginDatabase.DirectExecute(("UPDATE account SET totp_secret=NULL WHERE battlenet_account=" + std::to_string(bnetId)).c_str());
        LogActivity(bnetId, "security", "2fa_disable", 0, "2FA desactivado", dis2Ip);
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/transfer ─────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/transfer",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string body = ctx.request.body();
        std::string toEmail = JsonGet(body, "to_email");
        uint32 amount = 0;
        try { amount = static_cast<uint32>(std::stoul(JsonGet(body, "amount"))); } catch (...) {}
        if (amount < 1 || toEmail.empty()) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Datos invalidos\"}"; return RequestHandlerResult::Handled; }
        Utf8ToUpperOnlyLatin(toEmail);
        // Get sender's PD balance
        auto sr = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str());
        if (!sr) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Error de cuenta\"}"; return RequestHandlerResult::Handled; }
        uint32 balance = sr->Fetch()[0].GetUInt32();
        // Compute fee
        uint32 feePercent = 10;
        try { feePercent = static_cast<uint32>(std::stoul(PortalCfg("transfer_pd_fee"))); } catch (...) {}
        uint32 fee = (amount * feePercent + 99) / 100;
        uint32 total = amount + fee;
        if (total > balance) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes (incluye " + std::to_string(fee) + " PD de comision)\"}"; return RequestHandlerResult::Handled; }
        // Find recipient
        auto tr = LoginDatabase.Query(("SELECT id FROM battlenet_accounts WHERE email='" + SqlEsc(toEmail) + "'").c_str());
        if (!tr) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Cuenta de destino no encontrada\"}"; return RequestHandlerResult::Handled; }
        uint32 toId = tr->Fetch()[0].GetUInt32();
        if (toId == bnetId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"No puedes transferir a tu propia cuenta\"}"; return RequestHandlerResult::Handled; }
        LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" + std::to_string(total) + " WHERE id=" + std::to_string(bnetId) + " AND battlePayCredits>=" + std::to_string(total)).c_str());
        LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits+" + std::to_string(amount) + " WHERE id=" + std::to_string(toId)).c_str());
        LogActivity(bnetId, "pd", "transfer_out", -(int32)total, "Enviaste " + std::to_string(amount) + " PD (comision: " + std::to_string(fee) + " PD) a " + toEmail, "", toEmail);
        LogActivity(bnetId, "transaction", "pd_transfer_out", -(int32)total, "Transferencia PD a " + toEmail, "", std::to_string(amount) + " PD + " + std::to_string(fee) + " fee");
        LogActivity(toId, "pd", "transfer_in", (int32)amount, "Recibiste " + std::to_string(amount) + " PD", "", "");
        LogActivity(toId, "transaction", "pd_transfer_in", (int32)amount, "Transferencia PD recibida", "", std::to_string(amount) + " PD");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"fee\":" + std::to_string(fee) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/trade/info ────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/trade/info",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint32 pdBal = 0;
        if (auto r = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            pdBal = r->Fetch()[0].GetUInt32();
        std::string buyRate = PortalCfg("trade_pd_buy_rate");   // gold per PD (to buy PD)
        std::string sellRate = PortalCfg("trade_pd_sell_rate");  // gold per PD (when selling)
        if (buyRate.empty())  buyRate  = "50";
        if (sellRate.empty()) sellRate = "40";
        // Get characters for this account
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        std::ostringstream j;
        j << "{\"ok\":true,\"pd\":" << pdBal << ",\"buyRate\":" << buyRate << ",\"sellRate\":" << sellRate << ",\"chars\":[";
        bool first = true;
        if (accId) {
            if (auto r = LoginDatabase.Query(("SELECT guid,name,level,money FROM characters.characters WHERE account=" + std::to_string(accId)).c_str())) do {
                auto f = r->Fetch();
                if (!first) j << ','; first = false;
                j << "{\"guid\":" << f[0].GetUInt64()
                  << ",\"name\":" << JsonStr(f[1].GetString())
                  << ",\"level\":" << (uint32_t)f[2].GetUInt8()
                  << ",\"money\":" << f[3].GetInt64() << "}";
            } while (r->NextRow());
        }
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/trade/buy ────────────────────────────────────
    // Buy PD with in-game gold (deducts gold from character, adds PD to bnet account)
    RegisterHandler(http::verb::post, "/api/portal/trade/buy",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string body = ctx.request.body();
        uint64 charGuid = 0; uint32 pdAmount = 0;
        try { charGuid = static_cast<uint64>(std::stoull(JsonGet(body, "char_guid"))); } catch (...) {}
        try { pdAmount = static_cast<uint32>(std::stoul(JsonGet(body, "pd_amount"))); } catch (...) {}
        if (!charGuid || !pdAmount) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Datos invalidos\"}"; return RequestHandlerResult::Handled; }
        uint32 buyRate = 50;
        try { buyRate = static_cast<uint32>(std::stoul(PortalCfg("trade_pd_buy_rate"))); } catch (...) {}
        int64 goldCost = (int64)pdAmount * buyRate * 10000LL; // rate is in gold, convert to copper
        // Verify character belongs to this account
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Cuenta no encontrada\"}"; return RequestHandlerResult::Handled; }
        auto cr = LoginDatabase.Query(("SELECT money FROM characters.characters WHERE guid=" + std::to_string(charGuid) + " AND account=" + std::to_string(accId)).c_str());
        if (!cr) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled; }
        int64 money = cr->Fetch()[0].GetInt64();
        if (money < goldCost) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Oro insuficiente (necesitas " + std::to_string(goldCost/10000) + " oro)\"}"; return RequestHandlerResult::Handled; }
        LoginDatabase.DirectExecute(("UPDATE characters.characters SET money=money-" + std::to_string(goldCost) + " WHERE guid=" + std::to_string(charGuid) + " AND account=" + std::to_string(accId)).c_str());
        LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits+" + std::to_string(pdAmount) + " WHERE id=" + std::to_string(bnetId)).c_str());
        LogActivity(bnetId, "pd", "trade_buy", (int32)pdAmount, "Compraste " + std::to_string(pdAmount) + " PD por " + std::to_string(goldCost/10000) + " oro", "", std::to_string(goldCost/10000) + " oro");
        LogActivity(bnetId, "transaction", "gold_to_pd", (int32)pdAmount, "Comercio: " + std::to_string(goldCost/10000) + " oro -> " + std::to_string(pdAmount) + " PD");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"goldCost\":" + std::to_string(goldCost/10000) + ",\"pdGained\":" + std::to_string(pdAmount) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/trade/sell ───────────────────────────────────
    // Sell PD for in-game gold (deducts PD from bnet account, adds gold to character)
    RegisterHandler(http::verb::post, "/api/portal/trade/sell",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string body = ctx.request.body();
        uint64 charGuid = 0; uint32 pdAmount = 0;
        try { charGuid = static_cast<uint64>(std::stoull(JsonGet(body, "char_guid"))); } catch (...) {}
        try { pdAmount = static_cast<uint32>(std::stoul(JsonGet(body, "pd_amount"))); } catch (...) {}
        if (!charGuid || !pdAmount) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Datos invalidos\"}"; return RequestHandlerResult::Handled; }
        uint32 sellRate = 40;
        try { sellRate = static_cast<uint32>(std::stoul(PortalCfg("trade_pd_sell_rate"))); } catch (...) {}
        int64 goldGain = (int64)pdAmount * sellRate * 10000LL;
        // Verify PD balance
        auto pr = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str());
        if (!pr || pr->Fetch()[0].GetUInt32() < pdAmount) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes\"}"; return RequestHandlerResult::Handled; }
        // Verify character belongs to this account
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        auto cr = LoginDatabase.Query(("SELECT guid FROM characters.characters WHERE guid=" + std::to_string(charGuid) + " AND account=" + std::to_string(accId)).c_str());
        if (!cr) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled; }
        // Check gold cap (max 2^31-1 copper)
        LoginDatabase.DirectExecute(("UPDATE characters.characters SET money=LEAST(money+" + std::to_string(goldGain) + ",2147483647) WHERE guid=" + std::to_string(charGuid)).c_str());
        LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" + std::to_string(pdAmount) + " WHERE id=" + std::to_string(bnetId) + " AND battlePayCredits>=" + std::to_string(pdAmount)).c_str());
        LogActivity(bnetId, "pd", "trade_sell", -(int32)pdAmount, "Vendiste " + std::to_string(pdAmount) + " PD por " + std::to_string(goldGain/10000) + " oro", "", std::to_string(goldGain/10000) + " oro");
        LogActivity(bnetId, "transaction", "pd_to_gold", -(int32)pdAmount, "Comercio: " + std::to_string(pdAmount) + " PD -> " + std::to_string(goldGain/10000) + " oro");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"goldGain\":" + std::to_string(goldGain/10000) + ",\"pdSold\":" + std::to_string(pdAmount) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/promo ────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/promo",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string code = JsonGet(ctx.request.body(), "code");
        if (code.empty() || code.size() > 32) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo invalido\"}"; return RequestHandlerResult::Handled; }
        // Sanitize: keep only alphanumeric and dash/underscore
        std::string safeCode;
        for (char c : code) if (isalnum((unsigned char)c) || c=='-' || c=='_') safeCode += c;
        auto cr = LoginDatabase.Query(("SELECT pd_reward,pv_reward,max_uses,uses,is_active FROM auth.promo_codes WHERE code='" + SqlEsc(safeCode) + "'").c_str());
        if (!cr) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo no existe\"}"; return RequestHandlerResult::Handled; }
        auto cf = cr->Fetch();
        uint32 pdR = cf[0].GetUInt32(), pvR = cf[1].GetUInt32(), maxU = cf[2].GetUInt32(), uses = cf[3].GetUInt32();
        bool active = cf[4].GetUInt8() != 0;
        if (!active || uses >= maxU) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Codigo expirado o agotado\"}"; return RequestHandlerResult::Handled; }
        // Check if already used
        auto ur = LoginDatabase.Query(("SELECT id FROM auth.promo_code_uses WHERE bnet_id=" + std::to_string(bnetId) + " AND code='" + SqlEsc(safeCode) + "'").c_str());
        if (ur) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Ya usaste este codigo\"}"; return RequestHandlerResult::Handled; }
        LoginDatabase.DirectExecute(("INSERT INTO auth.promo_code_uses (code,bnet_id) VALUES('" + SqlEsc(safeCode) + "'," + std::to_string(bnetId) + ")").c_str());
        LoginDatabase.DirectExecute(("UPDATE auth.promo_codes SET uses=uses+1 WHERE code='" + SqlEsc(safeCode) + "'").c_str());
        if (pdR > 0) LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits+" + std::to_string(pdR) + " WHERE id=" + std::to_string(bnetId)).c_str());
        if (pvR > 0) LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET voteCredits=voteCredits+" + std::to_string(pvR) + " WHERE id=" + std::to_string(bnetId)).c_str());
        if (pdR > 0) LogActivity(bnetId, "pd", "earn_promo", (int32)pdR, "Codigo promo: +" + std::to_string(pdR) + " PD", "", safeCode);
        if (pvR > 0) LogActivity(bnetId, "pv", "earn_promo", (int32)pvR, "Codigo promo: +" + std::to_string(pvR) + " PV", "", safeCode);
        LogActivity(bnetId, "transaction", "promo_redeem", (int32)(pdR + pvR), "Codigo promo canjeado: " + safeCode, "", "PD+" + std::to_string(pdR) + " PV+" + std::to_string(pvR));
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"pd\":" + std::to_string(pdR) + ",\"pv\":" + std::to_string(pvR) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/vote ──────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/vote",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint32 cooldownH = 12;
        try { cooldownH = static_cast<uint32>(std::stoul(PortalCfg("vote_cooldown_hours"))); } catch (...) {}
        // Static vote sites (can be extended via portal_config)
        struct VoteSite { const char* key; const char* name; const char* url; uint32 pvReward; };
        static const VoteSite sites[] = {
            {"gtop100",  "Gtop100",      "https://gtop100.com/topsites/WoW/",    10},
            {"topg",     "Top-Games",    "https://topg.org/wow-private-servers/", 10},
            {"wowpvp",   "WoW-PvP",      "https://www.wow-pvp.com/",              5},
        };
        std::ostringstream j;
        j << "{\"ok\":true,\"sites\":[";
        bool first = true;
        for (auto& s : sites) {
            // Check cooldown
            bool canVote = true;
            if (auto r = LoginDatabase.Query(("SELECT voted_at FROM auth.portal_vote_log WHERE bnet_id=" + std::to_string(bnetId) +
                " AND site_key='" + std::string(s.key) + "' ORDER BY voted_at DESC LIMIT 1").c_str())) {
                // voted_at is DATETIME — we can't call GetString() safely, so use UNIX_TIMESTAMP comparison
                canVote = false; // has a recent vote row — check via separate query
                auto cr2 = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.portal_vote_log WHERE bnet_id=" + std::to_string(bnetId) +
                    " AND site_key='" + std::string(s.key) + "' AND voted_at > DATE_SUB(NOW(), INTERVAL " + std::to_string(cooldownH) + " HOUR)").c_str());
                if (cr2) canVote = (cr2->Fetch()[0].GetUInt32() == 0);
            }
            if (!first) j << ','; first = false;
            j << "{\"key\":" << JsonStr(s.key)
              << ",\"name\":" << JsonStr(s.name)
              << ",\"url\":" << JsonStr(s.url)
              << ",\"pv\":" << s.pvReward
              << ",\"canVote\":" << (canVote ? "true" : "false") << "}";
        }
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/vote/claim ───────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/vote/claim",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string siteKey = JsonGet(ctx.request.body(), "site_key");
        // Validate site key
        static const char* validKeys[] = {"gtop100","topg","wowpvp"};
        static const uint32 pvRewards[] = {10, 10, 5};
        int siteIdx = -1;
        for (int i = 0; i < 3; ++i) if (siteKey == validKeys[i]) { siteIdx = i; break; }
        if (siteIdx < 0) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Sitio invalido\"}"; return RequestHandlerResult::Handled; }
        uint32 cooldownH = 12;
        try { cooldownH = static_cast<uint32>(std::stoul(PortalCfg("vote_cooldown_hours"))); } catch (...) {}
        // Check cooldown
        auto cr = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.portal_vote_log WHERE bnet_id=" + std::to_string(bnetId) +
            " AND site_key='" + SqlEsc(siteKey) + "' AND voted_at > DATE_SUB(NOW(), INTERVAL " + std::to_string(cooldownH) + " HOUR)").c_str());
        if (cr && cr->Fetch()[0].GetUInt32() > 0) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Debes esperar " + std::to_string(cooldownH) + " horas entre votos\"}";
            return RequestHandlerResult::Handled;
        }
        uint32 pvReward = pvRewards[siteIdx];
        LoginDatabase.DirectExecute(("INSERT INTO auth.portal_vote_log (bnet_id,site_key) VALUES(" + std::to_string(bnetId) + ",'" + SqlEsc(siteKey) + "')").c_str());
        LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET voteCredits=voteCredits+" + std::to_string(pvReward) + " WHERE id=" + std::to_string(bnetId)).c_str());
        LogActivity(bnetId, "pv", "earn_vote", (int32)pvReward, "Voto en " + siteKey + ": +" + std::to_string(pvReward) + " PV", "", siteKey);
        LogActivity(bnetId, "transaction", "vote_claim", (int32)pvReward, "PV reclamados por voto en " + siteKey, "", std::to_string(pvReward) + " PV");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"pv\":" + std::to_string(pvReward) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/stripe/packages ──────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/stripe/packages",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        // Prices in cents from portal_config
        std::string p100  = PortalCfg("stripe_price_100");
        std::string p500  = PortalCfg("stripe_price_500");
        std::string p1000 = PortalCfg("stripe_price_1000");
        if (p100.empty())  p100  = "500";
        if (p500.empty())  p500  = "2000";
        if (p1000.empty()) p1000 = "3500";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "[{\"id\":\"pd100\",\"pd\":100,\"cents\":" + p100 +
            "},{\"id\":\"pd500\",\"pd\":500,\"cents\":" + p500 +
            "},{\"id\":\"pd1000\",\"pd\":1000,\"cents\":" + p1000 + "}]";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/stripe/checkout ─────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/stripe/checkout",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        std::string stripeKey = PortalCfg("stripe_key");
        if (stripeKey.empty()) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Pagos no configurados. Contacta al administrador.\"}";
            return RequestHandlerResult::Handled;
        }
        std::string pkg = JsonGet(ctx.request.body(), "package");
        uint32 pd = 0, cents = 0;
        if      (pkg == "pd100")  { pd = 100;  try { cents = static_cast<uint32>(std::stoul(PortalCfg("stripe_price_100")));  } catch (...) { cents = 500;  } }
        else if (pkg == "pd500")  { pd = 500;  try { cents = static_cast<uint32>(std::stoul(PortalCfg("stripe_price_500")));  } catch (...) { cents = 2000; } }
        else if (pkg == "pd1000") { pd = 1000; try { cents = static_cast<uint32>(std::stoul(PortalCfg("stripe_price_1000"))); } catch (...) { cents = 3500; } }
        else { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Paquete invalido\"}"; return RequestHandlerResult::Handled; }
        // Record pending payment
        LoginDatabase.DirectExecute(("INSERT INTO auth.stripe_payments (bnet_id,pd_amount,amount_cents,status) VALUES(" +
            std::to_string(bnetId) + "," + std::to_string(pd) + "," + std::to_string(cents) + ",'pending')").c_str());
        // Stub: return info for client-side Stripe.js integration
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"stub\":true,\"message\":\"Integra Stripe.js con la clave: configure stripe_key en portal_config\",\"pd\":" + std::to_string(pd) + ",\"cents\":" + std::to_string(cents) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/char/quests?guid=N ────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/char/quests",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Sin cuenta de juego\"}"; return RequestHandlerResult::Handled;
        }
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint64 charGuid = 0;
        if (auto it = params.find("guid"); it != params.end())
            try { charGuid = std::stoull(it->second); } catch (...) {}
        if (!charGuid) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"guid requerido\"}"; return RequestHandlerResult::Handled;
        }
        if (!LoginDatabase.Query(("SELECT 1 FROM characters.characters WHERE guid=" + std::to_string(charGuid) +
            " AND account=" + std::to_string(accId) + " AND deleteDate=0").c_str())) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        std::ostringstream j;
        j << "{\"ok\":true,\"quests\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(
            ("SELECT cq.quest, cq.status, IFNULL(q.LogTitle,'Desconocida') AS title,"
             " IFNULL(q.QuestLevel,0) AS qlvl"
             " FROM characters.character_queststatus cq"
             " LEFT JOIN world.quest_template q ON q.ID=cq.quest"
             " WHERE cq.guid=" + std::to_string(charGuid) + " AND cq.status BETWEEN 1 AND 3"
             " ORDER BY cq.status ASC, qlvl DESC LIMIT 50").c_str()))
        do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            uint32 status = (uint32_t)f[1].GetUInt8();
            const char* slabel = status==1?"En progreso":status==2?"Lista para entregar":"Fallida";
            j << "{\"id\":"     << f[0].GetUInt32()
              << ",\"status\":" << status
              << ",\"sl\":"     << JsonStr(slabel)
              << ",\"title\":"  << JsonStr(f[2].GetString())
              << ",\"level\":"  << JsonStr(f[3].GetString())
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/char/action ──────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/char/action",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Sin cuenta de juego\"}"; return RequestHandlerResult::Handled;
        }
        std::string body = ctx.request.body();
        uint64 charGuid = static_cast<uint64>(JsonGetInt(body, "guid"));
        std::string action = JsonGet(body, "action");
        int64_t amount = JsonGetInt(body, "amount");
        if (!charGuid || action.empty()) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Parametros invalidos\"}"; return RequestHandlerResult::Handled;
        }
        auto charRes = LoginDatabase.Query(("SELECT name, race, level, online FROM characters.characters WHERE guid=" +
            std::to_string(charGuid) + " AND account=" + std::to_string(accId) + " AND deleteDate=0").c_str());
        if (!charRes) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        auto cf = charRes->Fetch();
        std::string charName = cf[0].GetString();
        uint32 race    = (uint32_t)cf[1].GetUInt8();
        uint32 charLvl = (uint32_t)cf[2].GetUInt8();
        bool   isOnline = cf[3].GetUInt8() != 0;

        uint32 cost = 0, atLoginFlag = 0;
        bool requireOffline = false;

        if      (action == "revive")         { try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_revive_cost")));        } catch (...) {} atLoginFlag = 0x100; }
        else if (action == "rename")         { try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_rename_cost")));         } catch (...) { cost = 100;  } atLoginFlag = 0x001; }
        else if (action == "customize")      { try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_customize_cost")));      } catch (...) { cost = 150;  } atLoginFlag = 0x008; }
        else if (action == "race_change")    { try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_race_change_cost")));    } catch (...) { cost = 500;  } atLoginFlag = 0x080; }
        else if (action == "faction_change") { try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_faction_change_cost"))); } catch (...) { cost = 800;  } atLoginFlag = 0x040; }
        else if (action == "unstuck") {
            try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_unstuck_cost"))); } catch (...) {}
            requireOffline = true;
        } else if (action == "boost70") {
            try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_boost70_cost"))); } catch (...) { cost = 2000; }
            requireOffline = true;
            if (charLvl >= 70) {
                ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
                ctx.response.body() = "{\"ok\":false,\"error\":\"El personaje ya es nivel 70 o superior\"}"; return RequestHandlerResult::Handled;
            }
        } else if (action == "gold") {
            requireOffline = true;
            if (amount < 1 || amount > 100000) {
                ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
                ctx.response.body() = "{\"ok\":false,\"error\":\"Cantidad invalida (1-100000 oro)\"}"; return RequestHandlerResult::Handled;
            }
            uint32 goldRate = 10;
            try { goldRate = std::max(1u, static_cast<uint32>(std::stoul(PortalCfg("char_gold_rate")))); } catch (...) {}
            cost = static_cast<uint32>((amount + goldRate - 1) / goldRate);
        } else {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Accion desconocida\"}"; return RequestHandlerResult::Handled;
        }
        if (requireOffline && isOnline) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"El personaje debe estar desconectado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 userPD = 0;
        if (auto r = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            userPD = r->Fetch()[0].GetUInt32();
        if (cost > userPD) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes (necesitas " + std::to_string(cost) + " PD)\"}"; return RequestHandlerResult::Handled;
        }
        if (cost > 0)
            LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" +
                std::to_string(cost) + " WHERE id=" + std::to_string(bnetId) +
                " AND battlePayCredits>=" + std::to_string(cost)).c_str());

        if (atLoginFlag) {
            LoginDatabase.DirectExecute(("UPDATE characters.characters SET at_login=(at_login|" +
                std::to_string(atLoginFlag) + ") WHERE guid=" + std::to_string(charGuid)).c_str());
        } else if (action == "unstuck") {
            bool isAlliance = (race==1||race==3||race==4||race==7||race==11);
            uint32 safeMap = isAlliance ? 0u : 1u;
            float sx = isAlliance ? -8833.37f : -2917.58f;
            float sy = isAlliance ?   628.62f :  -257.98f;
            float sz = isAlliance ?    94.00f :    52.99f;
            char sql[384];
            snprintf(sql, sizeof(sql),
                "UPDATE characters.characters SET map=%u,position_x=%f,position_y=%f,"
                "position_z=%f,orientation=0,instance_id=0 WHERE guid=%llu",
                safeMap, sx, sy, sz, (unsigned long long)charGuid);
            LoginDatabase.DirectExecute(sql);
        } else if (action == "boost70") {
            LoginDatabase.DirectExecute(("UPDATE characters.characters SET level=70,xp=0 WHERE guid=" +
                std::to_string(charGuid)).c_str());
        } else if (action == "gold") {
            int64_t copper = amount * 10000LL;
            LoginDatabase.DirectExecute(("UPDATE characters.characters SET money=LEAST(money+" +
                std::to_string(copper) + ",2147483647) WHERE guid=" + std::to_string(charGuid)).c_str());
        }
        if (cost > 0) LogActivity(bnetId, "pd", "spend_service", -(int32)cost, action + " para " + charName + ": -" + std::to_string(cost) + " PD", "", charName);
        LogActivity(bnetId, "transaction", "char_service", -(int32)cost, "Servicio de personaje: " + action + " (" + charName + ")", "", std::to_string(cost) + " PD");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"cost\":" + std::to_string(cost) + "}"; return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/char/transfer ────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/char/transfer",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 srcAccId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            srcAccId = r->Fetch()[0].GetUInt32();
        if (!srcAccId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Sin cuenta de juego\"}"; return RequestHandlerResult::Handled;
        }
        std::string body = ctx.request.body();
        uint64 charGuid = static_cast<uint64>(JsonGetInt(body, "guid"));
        std::string targetEmail = JsonGet(body, "target_email");
        if (!charGuid || targetEmail.empty()) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Parametros invalidos\"}"; return RequestHandlerResult::Handled;
        }
        auto charRes = LoginDatabase.Query(("SELECT name, online FROM characters.characters WHERE guid=" +
            std::to_string(charGuid) + " AND account=" + std::to_string(srcAccId) + " AND deleteDate=0").c_str());
        if (!charRes) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        auto cf = charRes->Fetch();
        if (cf[1].GetUInt8()) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"El personaje debe estar desconectado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 tgtBnetId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM battlenet_accounts WHERE LOWER(email)=LOWER('" + SqlEsc(targetEmail) + "')").c_str()))
            tgtBnetId = r->Fetch()[0].GetUInt32();
        if (!tgtBnetId || tgtBnetId == bnetId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Cuenta de destino no encontrada\"}"; return RequestHandlerResult::Handled;
        }
        uint32 tgtAccId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(tgtBnetId) + " LIMIT 1").c_str()))
            tgtAccId = r->Fetch()[0].GetUInt32();
        if (!tgtAccId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"La cuenta destino no esta registrada en el juego\"}"; return RequestHandlerResult::Handled;
        }
        uint32 cost = 500;
        try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_transfer_cost"))); } catch (...) {}
        uint32 userPD = 0;
        if (auto r = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            userPD = r->Fetch()[0].GetUInt32();
        if (cost > userPD) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes (necesitas " + std::to_string(cost) + " PD)\"}"; return RequestHandlerResult::Handled;
        }
        if (cost > 0)
            LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" +
                std::to_string(cost) + " WHERE id=" + std::to_string(bnetId) +
                " AND battlePayCredits>=" + std::to_string(cost)).c_str());
        LoginDatabase.DirectExecute(("UPDATE characters.characters SET account=" + std::to_string(tgtAccId) +
            " WHERE guid=" + std::to_string(charGuid)).c_str());
        if (cost > 0) LogActivity(bnetId, "pd", "spend_service", -(int32)cost, "Transferencia de personaje: -" + std::to_string(cost) + " PD", "", targetEmail);
        LogActivity(bnetId, "transaction", "char_transfer", -(int32)cost, "Transferiste personaje a " + targetEmail, "", std::to_string(cost) + " PD");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"cost\":" + std::to_string(cost) + "}"; return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/char/deleted ──────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/char/deleted",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":true,\"chars\":[]}"; return RequestHandlerResult::Handled;
        }
        std::ostringstream j;
        j << "{\"ok\":true,\"chars\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(
            ("SELECT guid, deleteInfos_Name, level, race, class"
             " FROM characters.characters WHERE deleteInfos_Account=" + std::to_string(accId) +
             " AND deleteDate>0 ORDER BY deleteDate DESC LIMIT 20").c_str()))
        do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"guid\":"  << f[0].GetUInt64()
              << ",\"name\":"  << JsonStr(f[1].GetString())
              << ",\"level\":" << (uint32_t)f[2].GetUInt8()
              << ",\"race\":"  << (uint32_t)f[3].GetUInt8()
              << ",\"class\":" << (uint32_t)f[4].GetUInt8()
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/char/restore ─────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/char/restore",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Sin cuenta de juego\"}"; return RequestHandlerResult::Handled;
        }
        std::string body = ctx.request.body();
        uint64 charGuid = static_cast<uint64>(JsonGetInt(body, "guid"));
        if (!charGuid) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"guid requerido\"}"; return RequestHandlerResult::Handled;
        }
        auto charRes = LoginDatabase.Query(("SELECT name FROM characters.characters WHERE guid=" +
            std::to_string(charGuid) + " AND deleteInfos_Account=" + std::to_string(accId) +
            " AND deleteDate>0").c_str());
        if (!charRes) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        std::string charName = charRes->Fetch()[0].GetString();
        if (LoginDatabase.Query(("SELECT 1 FROM characters.characters WHERE name='" + SqlEsc(charName) +
            "' AND deleteDate=0").c_str())) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"El nombre '" + charName + "' ya esta en uso. Renombra el personaje activo primero.\"}";
            return RequestHandlerResult::Handled;
        }
        uint32 cost = 200;
        try { cost = static_cast<uint32>(std::stoul(PortalCfg("char_restore_deleted_cost"))); } catch (...) {}
        uint32 userPD = 0;
        if (auto r = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            userPD = r->Fetch()[0].GetUInt32();
        if (cost > userPD) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes (necesitas " + std::to_string(cost) + " PD)\"}"; return RequestHandlerResult::Handled;
        }
        if (cost > 0)
            LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" +
                std::to_string(cost) + " WHERE id=" + std::to_string(bnetId) +
                " AND battlePayCredits>=" + std::to_string(cost)).c_str());
        LoginDatabase.DirectExecute(("UPDATE characters.characters SET deleteDate=0,deleteInfos_Account=0,deleteInfos_Name='' WHERE guid=" +
            std::to_string(charGuid)).c_str());
        if (cost > 0) LogActivity(bnetId, "pd", "spend_service", -(int32)cost, "Restauracion de personaje '" + charName + "': -" + std::to_string(cost) + " PD", "", charName);
        LogActivity(bnetId, "transaction", "char_restore", -(int32)cost, "Personaje restaurado: " + charName, "", std::to_string(cost) + " PD");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"cost\":" + std::to_string(cost) + ",\"name\":" + JsonStr(charName) + "}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/char/recovery-request ────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/char/recovery-request",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        std::string body = ctx.request.body();
        uint64 charGuid = static_cast<uint64>(JsonGetInt(body, "guid"));
        std::string desc = JsonGet(body, "description");
        if (!charGuid || desc.empty() || desc.size() > 2000) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Completa la descripcion (max 2000 caracteres)\"}"; return RequestHandlerResult::Handled;
        }
        std::string charName;
        if (accId)
            if (auto r = LoginDatabase.Query(("SELECT name FROM characters.characters WHERE guid=" +
                std::to_string(charGuid) + " AND account=" + std::to_string(accId) + " AND deleteDate=0").c_str()))
                charName = r->Fetch()[0].GetString();
        if (charName.empty()) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        LoginDatabase.DirectExecute(("INSERT INTO auth.portal_item_recovery_requests"
            " (bnet_id,account_id,char_guid,char_name,description)"
            " VALUES(" + std::to_string(bnetId) + "," + std::to_string(accId) + "," +
            std::to_string(charGuid) + ",'" + SqlEsc(charName) + "','" + SqlEsc(desc) + "')").c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}"; return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/shop/items ────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/shop/items",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::ostringstream j;
        j << "{\"ok\":true,\"items\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(
            "SELECT id,item_entry,name,description,price_pd,category"
            " FROM auth.portal_shop_items WHERE is_active=1 ORDER BY category,price_pd ASC"))
        do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"    << f[0].GetUInt32()
              << ",\"entry\":" << f[1].GetUInt32()
              << ",\"name\":"  << JsonStr(f[2].GetString())
              << ",\"desc\":"  << JsonStr(f[3].GetString())
              << ",\"price\":" << f[4].GetUInt32()
              << ",\"cat\":"   << JsonStr(f[5].GetString())
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/shop/buy ─────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/shop/buy",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Sin cuenta de juego\"}"; return RequestHandlerResult::Handled;
        }
        std::string body = ctx.request.body();
        int64_t  itemId   = JsonGetInt(body, "item_id");
        uint64   charGuid = static_cast<uint64>(JsonGetInt(body, "guid"));
        int64_t  count    = JsonGetInt(body, "count");
        if (itemId < 1 || !charGuid || count < 1 || count > 99) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Parametros invalidos\"}"; return RequestHandlerResult::Handled;
        }
        auto itemRes = LoginDatabase.Query(("SELECT item_entry,name,price_pd FROM auth.portal_shop_items"
            " WHERE id=" + std::to_string(itemId) + " AND is_active=1").c_str());
        if (!itemRes) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Objeto no disponible\"}"; return RequestHandlerResult::Handled;
        }
        auto sf = itemRes->Fetch();
        uint32 itemEntry  = sf[0].GetUInt32();
        std::string itemName = sf[1].GetString();
        uint32 priceUnit  = sf[2].GetUInt32();
        uint32 totalCost  = priceUnit * static_cast<uint32>(count);
        if (!LoginDatabase.Query(("SELECT 1 FROM characters.characters WHERE guid=" + std::to_string(charGuid) +
            " AND account=" + std::to_string(accId) + " AND deleteDate=0").c_str())) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        std::string cname;
        if (auto r = LoginDatabase.Query(("SELECT name FROM characters.characters WHERE guid=" + std::to_string(charGuid)).c_str()))
            cname = r->Fetch()[0].GetString();
        uint32 userPD = 0;
        if (auto r = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            userPD = r->Fetch()[0].GetUInt32();
        if (totalCost > userPD) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes (necesitas " + std::to_string(totalCost) + " PD)\"}"; return RequestHandlerResult::Handled;
        }
        LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" +
            std::to_string(totalCost) + " WHERE id=" + std::to_string(bnetId) +
            " AND battlePayCredits>=" + std::to_string(totalCost)).c_str());
        LoginDatabase.DirectExecute(("INSERT INTO auth.portal_shop_orders"
            " (bnet_id,account_id,char_guid,char_name,item_entry,item_name,count,pd_spent)"
            " VALUES(" + std::to_string(bnetId) + "," + std::to_string(accId) + "," +
            std::to_string(charGuid) + ",'" + SqlEsc(cname) + "'," +
            std::to_string(itemEntry) + ",'" + SqlEsc(itemName) + "'," +
            std::to_string(count) + "," + std::to_string(totalCost) + ")").c_str());
        LogActivity(bnetId, "pd", "spend_shop", -(int32)totalCost, "Tienda: " + itemName + " x" + std::to_string(count) + " (-" + std::to_string(totalCost) + " PD)", "", itemName + " x" + std::to_string(count));
        LogActivity(bnetId, "transaction", "shop_purchase", -(int32)totalCost, "Compra en tienda: " + itemName + " x" + std::to_string(count) + " para " + cname, "", std::to_string(totalCost) + " PD");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"cost\":" + std::to_string(totalCost) +
            ",\"msg\":\"Pedido registrado. El objeto sera entregado pronto por el equipo del servidor.\"}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/char/gift ─────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/char/gift",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled;
        }
        std::string body = ctx.request.body();
        std::string toCharName = JsonGet(body, "to_char");
        int64_t goldAmt = JsonGetInt(body, "gold");
        if (toCharName.empty() || goldAmt < 1 || goldAmt > 100000) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Parametros invalidos (1-100000 oro)\"}"; return RequestHandlerResult::Handled;
        }
        auto tgtRes = LoginDatabase.Query(("SELECT guid, online FROM characters.characters"
            " WHERE name='" + SqlEsc(toCharName) + "' AND deleteDate=0 LIMIT 1").c_str());
        if (!tgtRes) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Personaje destino no encontrado\"}"; return RequestHandlerResult::Handled;
        }
        auto tf = tgtRes->Fetch();
        uint64 tgtGuid  = tf[0].GetUInt64();
        if (tf[1].GetUInt8()) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"El personaje destino debe estar desconectado\"}"; return RequestHandlerResult::Handled;
        }
        uint32 goldRate = 10;
        try { goldRate = std::max(1u, static_cast<uint32>(std::stoul(PortalCfg("char_gold_rate")))); } catch (...) {}
        uint32 cost = static_cast<uint32>((goldAmt + goldRate - 1) / goldRate);
        uint32 userPD = 0;
        if (auto r = LoginDatabase.Query(("SELECT battlePayCredits FROM battlenet_accounts WHERE id=" + std::to_string(bnetId)).c_str()))
            userPD = r->Fetch()[0].GetUInt32();
        if (cost > userPD) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"PD insuficientes (necesitas " + std::to_string(cost) + " PD)\"}"; return RequestHandlerResult::Handled;
        }
        if (cost > 0)
            LoginDatabase.DirectExecute(("UPDATE battlenet_accounts SET battlePayCredits=battlePayCredits-" +
                std::to_string(cost) + " WHERE id=" + std::to_string(bnetId) +
                " AND battlePayCredits>=" + std::to_string(cost)).c_str());
        int64_t copper = goldAmt * 10000LL;
        LoginDatabase.DirectExecute(("UPDATE characters.characters SET money=LEAST(money+" +
            std::to_string(copper) + ",2147483647) WHERE guid=" + std::to_string(tgtGuid)).c_str());
        if (cost > 0) LogActivity(bnetId, "pd", "spend_gift", -(int32)cost, "Regalo a " + toCharName + ": " + std::to_string(goldAmt) + " oro (-" + std::to_string(cost) + " PD)", "", toCharName);
        LogActivity(bnetId, "transaction", "gold_gift", -(int32)cost, "Enviaste " + std::to_string(goldAmt) + " oro a " + toCharName, "", std::to_string(goldAmt) + " oro");
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true,\"cost\":" + std::to_string(cost) + "}"; return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/history ───────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/history",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        std::string cat = "pdpv";
        int page = 0;
        if (auto it = params.find("category"); it != params.end()) cat = it->second;
        if (auto it = params.find("page"); it != params.end()) try { page = std::max(0, std::stoi(it->second)); } catch (...) {}
        int per = 25;
        std::string catWhere;
        if      (cat == "pdpv")        catWhere = "category IN ('pd','pv')";
        else if (cat == "pd")          catWhere = "category='pd'";
        else if (cat == "pv")          catWhere = "category='pv'";
        else if (cat == "transaction") catWhere = "category='transaction'";
        else if (cat == "security")    catWhere = "category='security'";
        else                           catWhere = "category IN ('pd','pv')";
        uint32 total = 0;
        if (auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.portal_activity_log WHERE bnet_id=" +
            std::to_string(bnetId) + " AND " + catWhere).c_str()))
            total = r->Fetch()[0].GetUInt32();
        int pages = (int)((total + per - 1) / per);
        if (page >= pages && pages > 0) page = pages - 1;
        std::ostringstream j;
        j << "{\"ok\":true,\"total\":" << total << ",\"pages\":" << std::max(1, pages) << ",\"items\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(("SELECT id,type,amount,description,ip_address,extra,"
            "DATE_FORMAT(created_at,'%d-%m-%Y %H:%i')"
            " FROM auth.portal_activity_log"
            " WHERE bnet_id=" + std::to_string(bnetId) + " AND " + catWhere +
            " ORDER BY id DESC LIMIT " + std::to_string(per) +
            " OFFSET " + std::to_string(page * per)).c_str())) do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"     << f[0].GetUInt64()
              << ",\"type\":"   << JsonStr(f[1].GetString())
              << ",\"amount\":" << (int)f[2].GetInt32()
              << ",\"desc\":"   << JsonStr(f[3].GetString())
              << ",\"ip\":"     << JsonStr(f[4].GetString())
              << ",\"extra\":"  << JsonStr(f[5].GetString())
              << ",\"ts\":"     << JsonStr(f[6].GetString())
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── GET /api/chat/channels ────────────────────────────────────────
    // Returns builtin WotLK channels (id, display name, lookup value for GetChannelForPlayerByNamePart)
    // plus any custom channels observed in admin_chat_log
    RegisterHandler(http::verb::get, "/api/chat/channels",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        // Builtin WotLK Classic channels: id stored in admin_chat_log, name for display, value for channel lookup
        struct ChanDef { const char* id; const char* disp; const char* lookup; };
        static const ChanDef builtin[] = {
            {"1",  "General (1)",    "General"},
            {"2",  "Trade (2)",      "Trade"},
            {"22", "Def. Local (22)","Local Defense"},
            {"25", "LFG (25)",       "LookingForGroup"},
            {"26", "Rec. Guild (26)","Guild Recruitment"},
        };
        std::ostringstream j;
        j << "[";
        for (size_t i = 0; i < sizeof(builtin)/sizeof(builtin[0]); ++i) {
            if (i) j << ',';
            j << "{\"id\":" << JsonStr(builtin[i].id)
              << ",\"name\":" << JsonStr(builtin[i].disp)
              << ",\"value\":" << JsonStr(builtin[i].lookup) << "}";
        }
        // Add custom (non-numeric) channel names seen in logs
        if (auto cr = LoginDatabase.Query(
            "SELECT DISTINCT channel_name FROM auth.admin_chat_log"
            " WHERE chat_type='channel' AND channel_name != ''"
            "  AND channel_name NOT IN ('1','2','22','25','26')"
            "  AND channel_name NOT REGEXP '^[0-9]+$'"
            " ORDER BY channel_name ASC LIMIT 20"))
        {
            do {
                std::string cn = cr->Fetch()[0].GetString();
                j << ",{\"id\":" << JsonStr(cn) << ",\"name\":" << JsonStr(cn) << ",\"value\":" << JsonStr(cn) << "}";
            } while (cr->NextRow());
        }
        j << "]";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── POST /api/portal/chat/send ────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/portal/chat/send",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) {
            ctx.response.result(http::status::unauthorized);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}";
            return RequestHandlerResult::Handled;
        }
        uint32 accId = 0;
        if (auto r = LoginDatabase.Query(("SELECT id FROM account WHERE battlenet_account=" + std::to_string(bnetId) + " LIMIT 1").c_str()))
            accId = r->Fetch()[0].GetUInt32();
        if (!accId) { ctx.response.result(http::status::bad_request); ctx.response.body() = "{}"; return RequestHandlerResult::Handled; }

        std::string body = ctx.request.body();
        uint32 cguid     = static_cast<uint32>(JsonGetInt(body, "char_guid"));
        std::string ctype  = JsonGet(body, "chat_type");
        std::string cmsg   = JsonGet(body, "message");
        std::string ctarget = JsonGet(body, "target");
        std::string cchan  = JsonGet(body, "channel");
        if (cmsg.empty() || ctype.empty() || cmsg.size() > 255) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Mensaje invalido\"}";
            return RequestHandlerResult::Handled;
        }
        LoginDatabase.DirectExecute(
            ("INSERT INTO auth.web_chat_queue (game_account_id,char_guid,chat_type,message,target,channel_name)"
             " VALUES (" + std::to_string(accId) + "," + std::to_string(cguid) + ",'" +
             SqlEsc(ctype) + "','" + SqlEsc(cmsg) + "','" + SqlEsc(ctarget) + "','" + SqlEsc(cchan) + "')").c_str());
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/chat/chars ────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/portal/chat/chars",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "[]"; return RequestHandlerResult::Handled; }
        std::ostringstream j;
        j << "[";
        bool first = true;
        if (auto cr = LoginDatabase.Query(
            ("SELECT c.guid, c.name, c.level, c.online"
             " FROM characters.characters c"
             " JOIN account a ON a.id = c.account"
             " WHERE a.battlenet_account=" + std::to_string(bnetId) +
             " ORDER BY c.online DESC, c.level DESC, c.name ASC").c_str())) do {
            auto f = cr->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"guid\":"   << f[0].GetUInt32()
              << ",\"name\":"   << JsonStr(f[1].GetString())
              << ",\"level\":"  << (int)f[2].GetUInt8()
              << ",\"online\":" << (f[3].GetUInt8() ? "true" : "false")
              << "}";
        } while (cr->NextRow());
        j << "]";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ─────────────────────────────────────────────────────────────────
    // FORUM
    // ─────────────────────────────────────────────────────────────────

    // ── GET /api/forum/categories ─────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/forum/categories",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::ostringstream j;
        j << "[";
        bool first = true;
        if (auto r = LoginDatabase.Query(
            "SELECT id,name,description,icon,"
            "(SELECT COUNT(*) FROM auth.forum_threads ft WHERE ft.category_id=fc.id AND ft.is_hidden=0) AS tc,"
            "(SELECT COUNT(*) FROM auth.forum_posts fp"
            " JOIN auth.forum_threads ft2 ON ft2.id=fp.thread_id"
            " WHERE ft2.category_id=fc.id AND fp.is_hidden=0 AND ft2.is_hidden=0) AS pc"
            " FROM auth.forum_categories fc WHERE fc.is_active=1 ORDER BY fc.sort_order")) do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"     << f[0].GetUInt32()
              << ",\"name\":"   << JsonStr(f[1].GetString())
              << ",\"desc\":"   << JsonStr(f[2].GetString())
              << ",\"icon\":"   << JsonStr(f[3].GetString())
              << ",\"threads\":" << f[4].GetUInt32()
              << ",\"posts\":"  << f[5].GetUInt32()
              << "}";
        } while (r->NextRow());
        j << "]";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── GET /api/forum/threads?cat=N&page=N ──────────────────────────
    RegisterHandler(http::verb::get, "/api/forum/threads",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint32 catId = 0; int page = 0;
        if (auto it = params.find("cat");  it != params.end()) try { catId = (uint32)std::stoul(it->second); } catch (...) {}
        if (auto it = params.find("page"); it != params.end()) try { page = std::max(0, std::stoi(it->second)); } catch (...) {}
        if (!catId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"threads\":[],\"pages\":1}"; return RequestHandlerResult::Handled; }
        int per = 20;
        uint32 total = 0;
        if (auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.forum_threads WHERE category_id=" + std::to_string(catId) + " AND is_hidden=0").c_str()))
            total = r->Fetch()[0].GetUInt32();
        int pages = (int)((total + per - 1) / per);
        std::ostringstream j;
        j << "{\"total\":" << total << ",\"pages\":" << std::max(1,pages) << ",\"threads\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(("SELECT id,author_name,title,is_pinned,is_locked,views,reply_count,"
            "DATE_FORMAT(last_post_at,'%d-%m-%Y %H:%i')"
            " FROM auth.forum_threads WHERE category_id=" + std::to_string(catId) + " AND is_hidden=0"
            " ORDER BY is_pinned DESC, last_post_at DESC LIMIT " + std::to_string(per) +
            " OFFSET " + std::to_string(page * per)).c_str())) do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"      << f[0].GetUInt64()
              << ",\"author\":"  << JsonStr(f[1].GetString())
              << ",\"title\":"   << JsonStr(f[2].GetString())
              << ",\"pinned\":"  << (f[3].GetUInt8() ? "true" : "false")
              << ",\"locked\":"  << (f[4].GetUInt8() ? "true" : "false")
              << ",\"views\":"   << f[5].GetUInt32()
              << ",\"replies\":" << f[6].GetUInt32()
              << ",\"ts\":"      << JsonStr(f[7].GetString())
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── GET /api/forum/thread?id=N&page=N ────────────────────────────
    RegisterHandler(http::verb::get, "/api/forum/thread",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint64 thrId = 0; int page = 0;
        if (auto it = params.find("id");   it != params.end()) try { thrId = std::stoull(it->second); } catch (...) {}
        if (auto it = params.find("page"); it != params.end()) try { page = std::max(0, std::stoi(it->second)); } catch (...) {}
        if (!thrId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"posts\":[],\"pages\":1}"; return RequestHandlerResult::Handled; }
        uint32 bnetId = portalAuth(ctx);
        bool isMod = IsForumMod(bnetId);
        // Get thread meta + increment views
        uint8 isLocked = 0, isPinned = 0;
        if (auto r = LoginDatabase.Query(("SELECT is_locked, is_pinned FROM auth.forum_threads WHERE id=" + std::to_string(thrId) + " AND is_hidden=0").c_str())) {
            auto f = r->Fetch(); isLocked = f[0].GetUInt8(); isPinned = f[1].GetUInt8();
            LoginDatabase.DirectExecute(("UPDATE auth.forum_threads SET views=views+1 WHERE id=" + std::to_string(thrId)).c_str());
        }
        int per = 15;
        uint32 total = 0;
        if (auto r = LoginDatabase.Query(("SELECT COUNT(*) FROM auth.forum_posts WHERE thread_id=" + std::to_string(thrId) + " AND is_hidden=0").c_str()))
            total = r->Fetch()[0].GetUInt32();
        int pages = (int)((total + per - 1) / per);
        std::ostringstream j;
        j << "{\"locked\":" << (isLocked ? "true" : "false")
          << ",\"pinned\":" << (isPinned ? "true" : "false")
          << ",\"is_mod\":"  << (isMod ? "true" : "false")
          << ",\"total\":"   << total
          << ",\"pages\":"   << std::max(1, pages)
          << ",\"posts\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(("SELECT id,author_name,content,"
            "DATE_FORMAT(created_at,'%d-%m-%Y %H:%i')"
            " FROM auth.forum_posts WHERE thread_id=" + std::to_string(thrId) + " AND is_hidden=0"
            " ORDER BY id ASC LIMIT " + std::to_string(per) +
            " OFFSET " + std::to_string(page * per)).c_str())) do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":"      << f[0].GetUInt64()
              << ",\"author\":"  << JsonStr(f[1].GetString())
              << ",\"content\":" << JsonStr(f[2].GetString())
              << ",\"ts\":"      << JsonStr(f[3].GetString())
              << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str(); return RequestHandlerResult::Handled;
    });

    // ── POST /api/forum/thread/new ────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/forum/thread/new",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled; }
        std::string body = ctx.request.body();
        uint32 catId = (uint32)JsonGetInt(body, "cat_id");
        std::string title   = JsonGet(body, "title");
        std::string content = JsonGet(body, "content");
        if (!catId || title.size() < 3 || title.size() > 120 || content.size() < 10 || content.size() > 20000) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Titulo (3-120 chars) y contenido (10-20000 chars) requeridos\"}"; return RequestHandlerResult::Handled;
        }
        if (!LoginDatabase.Query(("SELECT 1 FROM auth.forum_categories WHERE id=" + std::to_string(catId) + " AND is_active=1").c_str())) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Categoria no encontrada\"}"; return RequestHandlerResult::Handled;
        }
        std::string author = ForumAuthorName(bnetId);
        LoginDatabase.DirectExecute(("INSERT INTO auth.forum_threads (category_id,bnet_id,author_name,title)"
            " VALUES(" + std::to_string(catId) + "," + std::to_string(bnetId) +
            ",'" + SqlEsc(author) + "','" + SqlEsc(title) + "')").c_str());
        if (auto r = LoginDatabase.Query("SELECT LAST_INSERT_ID()")) {
            uint64 thrId = r->Fetch()[0].GetUInt64();
            LoginDatabase.DirectExecute(("INSERT INTO auth.forum_posts (thread_id,bnet_id,author_name,content)"
                " VALUES(" + std::to_string(thrId) + "," + std::to_string(bnetId) +
                ",'" + SqlEsc(author) + "','" + SqlEsc(content) + "')").c_str());
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":true,\"id\":" + std::to_string(thrId) + "}"; return RequestHandlerResult::Handled;
        }
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}"; return RequestHandlerResult::Handled;
    });

    // ── POST /api/forum/post/new ──────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/forum/post/new",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"No autenticado\"}"; return RequestHandlerResult::Handled; }
        std::string body = ctx.request.body();
        uint64 thrId  = (uint64)JsonGetInt(body, "thread_id");
        std::string content = JsonGet(body, "content");
        if (!thrId || content.size() < 2 || content.size() > 10000) {
            ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"Contenido invalido\"}"; return RequestHandlerResult::Handled;
        }
        auto tr = LoginDatabase.Query(("SELECT is_locked FROM auth.forum_threads WHERE id=" + std::to_string(thrId) + " AND is_hidden=0").c_str());
        if (!tr) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Tema no encontrado\"}"; return RequestHandlerResult::Handled; }
        if (tr->Fetch()[0].GetUInt8()) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false,\"error\":\"Este tema esta cerrado\"}"; return RequestHandlerResult::Handled; }
        std::string author = ForumAuthorName(bnetId);
        LoginDatabase.DirectExecute(("INSERT INTO auth.forum_posts (thread_id,bnet_id,author_name,content)"
            " VALUES(" + std::to_string(thrId) + "," + std::to_string(bnetId) +
            ",'" + SqlEsc(author) + "','" + SqlEsc(content) + "')").c_str());
        LoginDatabase.DirectExecute(("UPDATE auth.forum_threads SET reply_count=reply_count+1, last_post_at=NOW() WHERE id=" + std::to_string(thrId)).c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}"; return RequestHandlerResult::Handled;
    });

    // ── POST /api/forum/thread/pin ────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/forum/thread/pin",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId || !IsForumMod(bnetId)) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint64 thrId = (uint64)JsonGetInt(ctx.request.body(), "id");
        if (!thrId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint8 cur = 0;
        if (auto r = LoginDatabase.Query(("SELECT is_pinned FROM auth.forum_threads WHERE id=" + std::to_string(thrId)).c_str()))
            cur = r->Fetch()[0].GetUInt8();
        LoginDatabase.DirectExecute(("UPDATE auth.forum_threads SET is_pinned=" + std::to_string(cur?0:1) + " WHERE id=" + std::to_string(thrId)).c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = std::string("{\"ok\":true,\"pinned\":") + (cur?"false":"true") + "}"; return RequestHandlerResult::Handled;
    });

    // ── POST /api/forum/thread/lock ───────────────────────────────────
    RegisterHandler(http::verb::post, "/api/forum/thread/lock",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId || !IsForumMod(bnetId)) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint64 thrId = (uint64)JsonGetInt(ctx.request.body(), "id");
        if (!thrId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint8 cur = 0;
        if (auto r = LoginDatabase.Query(("SELECT is_locked FROM auth.forum_threads WHERE id=" + std::to_string(thrId)).c_str()))
            cur = r->Fetch()[0].GetUInt8();
        LoginDatabase.DirectExecute(("UPDATE auth.forum_threads SET is_locked=" + std::to_string(cur?0:1) + " WHERE id=" + std::to_string(thrId)).c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = std::string("{\"ok\":true,\"locked\":") + (cur?"false":"true") + "}"; return RequestHandlerResult::Handled;
    });

    // ── POST /api/forum/thread/delete ─────────────────────────────────
    RegisterHandler(http::verb::post, "/api/forum/thread/delete",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId || !IsForumMod(bnetId)) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint64 thrId = (uint64)JsonGetInt(ctx.request.body(), "id");
        if (!thrId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        LoginDatabase.DirectExecute(("UPDATE auth.forum_threads SET is_hidden=1 WHERE id=" + std::to_string(thrId)).c_str());
        LoginDatabase.DirectExecute(("UPDATE auth.forum_posts SET is_hidden=1 WHERE thread_id=" + std::to_string(thrId)).c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}"; return RequestHandlerResult::Handled;
    });

    // ── POST /api/forum/post/delete ───────────────────────────────────
    RegisterHandler(http::verb::post, "/api/forum/post/delete",
        [portalAuth](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        uint32 bnetId = portalAuth(ctx);
        if (!bnetId || !IsForumMod(bnetId)) { ctx.response.result(http::status::unauthorized); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint64 postId = (uint64)JsonGetInt(ctx.request.body(), "id");
        if (!postId) { ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":false}"; return RequestHandlerResult::Handled; }
        uint64 thrId = 0;
        if (auto r = LoginDatabase.Query(("SELECT thread_id FROM auth.forum_posts WHERE id=" + std::to_string(postId)).c_str()))
            thrId = r->Fetch()[0].GetUInt64();
        LoginDatabase.DirectExecute(("UPDATE auth.forum_posts SET is_hidden=1 WHERE id=" + std::to_string(postId)).c_str());
        if (thrId) LoginDatabase.DirectExecute(("UPDATE auth.forum_threads SET reply_count=GREATEST(CAST(reply_count AS SIGNED)-1,0) WHERE id=" + std::to_string(thrId)).c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}"; return RequestHandlerResult::Handled;
    });

    // ─────────────────────────────────────────────────────────────────
    // ADMIN PANEL: NEWS MANAGEMENT
    // ─────────────────────────────────────────────────────────────────

    // ── GET /api/news?page=N ──────────────────────────────────────────
    RegisterHandler(http::verb::get, "/api/news",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        int page = 0;
        if (auto it = params.find("page"); it != params.end()) try { page = std::max(0, std::stoi(it->second)); } catch (...) {}
        int per = 10;
        uint32 total = 0;
        if (auto r = LoginDatabase.Query("SELECT COUNT(*) FROM auth.portal_news")) total = r->Fetch()[0].GetUInt32();
        std::ostringstream j;
        j << "{\"total\":" << total << ",\"pages\":" << ((total + per - 1) / per) << ",\"news\":[";
        bool first = true;
        if (auto r = LoginDatabase.Query(("SELECT id,title,category,author,is_published,is_featured,DATE_FORMAT(created_at,'%d-%m-%Y'),summary,image_url"
            " FROM auth.portal_news ORDER BY created_at DESC LIMIT " + std::to_string(per) +
            " OFFSET " + std::to_string(page * per)).c_str())) do {
            auto f = r->Fetch();
            if (!first) j << ','; first = false;
            j << "{\"id\":" << f[0].GetUInt32() << ",\"title\":" << JsonStr(f[1].GetString())
              << ",\"category\":" << JsonStr(f[2].GetString()) << ",\"author\":" << JsonStr(f[3].GetString())
              << ",\"published\":" << f[4].GetUInt8() << ",\"featured\":" << f[5].GetUInt8()
              << ",\"date\":" << JsonStr(f[6].GetString())
              << ",\"summary\":" << JsonStr(f[7].GetString())
              << ",\"image_url\":" << JsonStr(f[8].GetString()) << "}";
        } while (r->NextRow());
        j << "]}";
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/news/save ───────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/news/save",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        std::string body = ctx.request.body();
        int64_t id       = JsonGetInt(body, "id");
        std::string title    = JsonGet(body, "title");
        std::string category = JsonGet(body, "category");
        std::string summary  = JsonGet(body, "summary");
        std::string content  = JsonGet(body, "content");
        std::string image    = JsonGet(body, "image_url");
        std::string author   = JsonGet(body, "author");
        int published        = (int)JsonGetInt(body, "is_published");
        int featured         = (int)JsonGetInt(body, "is_featured");
        if (title.empty()) {
            ctx.response.result(http::status::bad_request); SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"ok\":false,\"error\":\"titulo requerido\"}"; return RequestHandlerResult::Handled;
        }
        if (id > 0) {
            LoginDatabase.DirectExecute(("UPDATE auth.portal_news SET title='" + SqlEsc(title) + "'"
                ",category='" + SqlEsc(category) + "',summary='" + SqlEsc(summary) +
                "',content='" + SqlEsc(content) + "',image_url='" + SqlEsc(image) +
                "',author='" + SqlEsc(author) + "',is_published=" + std::to_string(published) +
                ",is_featured=" + std::to_string(featured) + " WHERE id=" + std::to_string(id)).c_str());
        } else {
            LoginDatabase.DirectExecute(("INSERT INTO auth.portal_news (title,category,summary,content,image_url,author,is_published,is_featured)"
                " VALUES ('" + SqlEsc(title) + "','" + SqlEsc(category) + "','" + SqlEsc(summary) +
                "','" + SqlEsc(content) + "','" + SqlEsc(image) + "','" + SqlEsc(author) + "'," +
                std::to_string(published) + "," + std::to_string(featured) + ")").c_str());
        }
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/news/delete ─────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/news/delete",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        int64_t id = JsonGetInt(ctx.request.body(), "id");
        if (id > 0) LoginDatabase.DirectExecute(("DELETE FROM auth.portal_news WHERE id=" + std::to_string(id)).c_str());
        ctx.response.result(http::status::ok); SetJsonHeaders(ctx.response); ctx.response.body() = "{\"ok\":true}";
        return RequestHandlerResult::Handled;
    });

    // ── GET /api/portal/chat/events?char_guid=N&after_id=N ──────────
    RegisterHandler(http::verb::get, "/api/chat/events",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        auto params = ParseQuery(ToStdStringView(ctx.request.target()));
        uint32 charGuid = 0;
        uint64 afterId  = 0;
        if (auto it = params.find("char_guid"); it != params.end())
            try { charGuid = static_cast<uint32>(std::stoul(it->second)); } catch (...) {}
        if (auto it = params.find("after_id");  it != params.end())
            try { afterId  = std::stoull(it->second); } catch (...) {}

        if (charGuid == 0) {
            ctx.response.result(http::status::bad_request);
            SetJsonHeaders(ctx.response);
            ctx.response.body() = "{\"error\":\"char_guid requerido\"}";
            return RequestHandlerResult::Handled;
        }

        // Get character info + guild (guildid lives in guild_member, not characters)
        std::string charName; uint8 charLevel = 0; bool online = false;
        uint32 guildId = 0; std::string guildName; std::string liveZone;
        if (auto ci = LoginDatabase.Query(
            ("SELECT c.name, c.level, COALESCE(gm.guildid,0), c.online"
             " FROM characters.characters c"
             " LEFT JOIN characters.guild_member gm ON gm.guid=c.guid"
             " WHERE c.guid=" + std::to_string(charGuid)).c_str()))
        {
            auto f = ci->Fetch();
            charName  = f[0].GetString();
            charLevel = f[1].GetUInt8();
            guildId   = static_cast<uint32>(f[2].GetUInt64());
            online    = f[3].GetUInt8() != 0;
        }
        if (guildId) {
            if (auto gr = LoginDatabase.Query(
                ("SELECT name FROM characters.guild WHERE guildid=" + std::to_string(guildId)).c_str()))
                guildName = gr->Fetch()[0].GetString();
        }
        // Latest known zone from chat log
        if (auto zr = LoginDatabase.Query(
            ("SELECT char_zone FROM auth.admin_chat_log WHERE char_guid=" + std::to_string(charGuid) +
             " ORDER BY id DESC LIMIT 1").c_str()))
            liveZone = zr->Fetch()[0].GetString();

        // Get group_id the character belongs to
        uint32 groupDbId = 0;
        if (auto gr = LoginDatabase.Query(
            ("SELECT guid FROM characters.group_member WHERE memberGuid=" + std::to_string(charGuid) + " LIMIT 1").c_str()))
            groupDbId = gr->Fetch()[0].GetUInt32();

        // Fetch events
        std::string evSql =
            "SELECT id, DATE_FORMAT(event_time,'%Y-%m-%d %H:%i:%s') AS ts,"
            " char_guid, char_name, char_level, char_zone, chat_type, message,"
            " target_guid, target_name, target_zone, target_level,"
            " guild_id, group_id, channel_name"
            " FROM auth.admin_chat_log"
            " WHERE id > " + std::to_string(afterId) +
            " AND (char_guid=" + std::to_string(charGuid);
        if (guildId)
            evSql += " OR (chat_type IN ('guild','officer') AND guild_id=" + std::to_string(guildId) + ")";
        if (groupDbId)
            evSql += " OR (chat_type IN ('party','raid','raid_warning','instance') AND group_id=" + std::to_string(groupDbId) + ")";
        evSql += " OR chat_type='channel') ORDER BY id ASC LIMIT 200";

        std::ostringstream j;
        j << "{";
        // char_info
        j << "\"char_info\":{"
          << "\"name\":"       << JsonStr(charName)
          << ",\"level\":"     << static_cast<int>(charLevel)
          << ",\"zone\":"      << JsonStr(liveZone)
          << ",\"online\":"    << (online ? "true" : "false")
          << ",\"guild_name\":" << JsonStr(guildName)
          << "},";
        // events
        j << "\"events\":[";
        uint64 lastId = afterId;
        bool first = true;
        if (auto res = LoginDatabase.Query(evSql.c_str())) {
            do {
                auto f = res->Fetch();
                uint64 eid = f[0].GetUInt64();
                if (eid > lastId) lastId = eid;
                if (!first) j << ','; first = false;
                j << "{"
                  << "\"id\":"           << eid
                  << ",\"ts\":"          << JsonStr(f[1].GetString())
                  << ",\"char_guid\":"   << f[2].GetUInt32()
                  << ",\"char_name\":"   << JsonStr(f[3].GetString())
                  << ",\"char_level\":"  << static_cast<int>(f[4].GetUInt8())
                  << ",\"char_zone\":"   << JsonStr(f[5].GetString())
                  << ",\"chat_type\":"   << JsonStr(f[6].GetString())
                  << ",\"message\":"     << JsonStr(f[7].GetString())
                  << ",\"target_guid\":" << f[8].GetUInt32()
                  << ",\"target_name\":" << JsonStr(f[9].GetString())
                  << ",\"target_zone\":" << JsonStr(f[10].GetString())
                  << ",\"target_level\":" << static_cast<int>(f[11].GetUInt8())
                  << ",\"guild_id\":"    << f[12].GetUInt32()
                  << ",\"group_id\":"    << f[13].GetUInt32()
                  << ",\"channel_name\":" << JsonStr(f[14].GetString())
                  << "}";
            } while (res->NextRow());
        }
        j << "],\"last_id\":" << lastId << "}";

        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = j.str();
        return RequestHandlerResult::Handled;
    });

    // ── POST /api/stop ────────────────────────────────────────────────
    RegisterHandler(http::verb::post, "/api/stop",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        SetJsonHeaders(ctx.response);
        ctx.response.body() = "{\"ok\":true}";
        sAdminBuf.Running = false;
        if (sAdminBuf.ShutdownCallback)
            sAdminBuf.ShutdownCallback();
        return RequestHandlerResult::Handled;
    });

    _acceptor->AsyncAcceptWithCallback<&AdminService::OnSocketAccept>();
    TC_LOG_INFO("server.http", "Admin panel available at http://{}:{}/", bindIp, port);
    return true;
}

void AdminService::OnSocketAccept(boost::asio::ip::tcp::socket&& sock, uint32 threadIndex)
{
    sAdminService.OnSocketOpen(std::forward<boost::asio::ip::tcp::socket>(sock), threadIndex);
}

void AdminService::NotifyShutdown()
{
    sAdminBuf.Running = false;
}
} // namespace Battlenet
