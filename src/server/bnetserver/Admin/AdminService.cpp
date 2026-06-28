#include "AdminService.h"
#include "AdminLogBuffer.h"
#include "Config.h"
#include "DatabaseEnv.h"
#include "GitRevision.h"
#include "HttpCommon.h"
#include "Log.h"
#include "Realm.h"
#include "RealmList.h"
#include "StringFormat.h"
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/verb.hpp>
#include <ctime>
#include <map>
#include <sstream>
#include <string>

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
    <div class="nav-link" data-page="realms"><span class="ic">&#x1F30D;</span>Reinos</div>
    <div class="nav-link" data-page="logs"><span class="ic">&#x1F4CB;</span>Logs <span class="badge-live">EN VIVO</span></div>
  </div>
  <div class="nav-sec">
    <div class="nav-lbl">Sistema</div>
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
        <button class="btn btn-primary" onclick="loadAccounts(0,'')">&#x21BB; Actualizar</button>
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
        <button class="btn btn-primary" onclick="loadRealmsPage()">&#x21BB; Actualizar</button>
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
  realms:{title:'Gestion de Reinos',sub:'Estado y control de reinos'},
  logs:{title:'Logs del Servidor',sub:'Registro de actividad en tiempo real'},
  config:{title:'Configuracion',sub:'Parametros de configuracion actuales'},
  security:{title:'Seguridad',sub:'Cuentas baneadas y seguridad'}
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
  if(page==='realms')      loadRealmsPage();
  if(page==='logs')        startLogs();
  if(page==='config')      loadConfig();
  if(page==='security')    loadBanned(0,'');
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
      var btn=a.banned
        ?'<button class="btn btn-sm btn-success" onclick="unbanAcc('+a.id+',\''+esc(a.username)+'\')">Desbanear</button>'
        :'<button class="btn btn-sm btn-danger" onclick="openBanModal('+a.id+',\''+esc(a.username)+'\')">Banear</button>';
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
        +'</div>'
        +'<div class="rc-foot">'
        +(online
          ?'<button class="btn btn-danger btn-sm" onclick="toggleRealm('+r.port+',true)">Poner Offline</button>'
          :'<button class="btn btn-success btn-sm" onclick="toggleRealm('+r.port+',false)">Poner Online</button>')
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

// ── Server control ────────────────────────────────────────
function stopServer(){
  if(!confirm('Seguro que deseas detener el servidor BNetServer?\nEsto desconectara a todos los jugadores.'))return;
  apiFetch('/api/stop',{method:'POST'}).then(function(){toast('Servidor deteniendo...','warn');}).catch(function(){});
}

// ── Utils ─────────────────────────────────────────────────
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

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

    namespace http = boost::beast::http;
    using Trinity::Net::Http::RequestContext;
    using Trinity::Net::Http::RequestHandlerResult;
    using Trinity::Net::Http::ToStdStringView;

    // ── GET / ─────────────────────────────────────────────────────────
    RegisterHandler(http::verb::get, "/",
        [](std::shared_ptr<AdminHttpSession>, RequestContext& ctx) -> RequestHandlerResult
    {
        ctx.response.result(http::status::ok);
        ctx.response.set(http::field::content_type, "text/html; charset=utf-8");
        ctx.response.body() = k_Html;
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
            j << "{\"name\":"       << JsonStr(realm.Name)
              << ",\"port\":"       << realm.Port
              << ",\"type\":"       << static_cast<int>(realm.Type)
              << ",\"online\":"     << (online ? "true" : "false")
              << ",\"population\":" << realm.PopulationLevel
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
