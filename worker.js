const KV = {
  CONFIG: 'config',
  INSTALL_LOCK: 'install_lock',
  SESS_PREFIX: 'sess:',
  INVITES: 'invites', // JSON array
  COMPAT_CARDS: 'cards', // backward compatibility
};

const DEFAULT_CONFIG = {
  adminPath: '/admin',
  adminUsername: 'admin',
  adminPasswordHash: '',
  turnstile: { siteKey: '', secretKey: '' },
  globals: [], // [{id,label,tenantId,clientId,clientSecret,defaultDomain,skuMap (object)}]
  // 额外保护账户：仅按用户名（@ 前缀 / local-part）匹配。
  // - 用途：1) 禁止前台注册这些敏感用户名；2) 若这些账号已存在，禁止通过面板/API 删除。
  // - 默认内置常见高危用户名，避免首次部署未设置防护导致全局被盗。
  // 兼容字段 protectedUsers（旧版按完整邮箱保护）仍保留读取，但不再在 UI 中展示/保存。
  protectedUsers: [], // legacy: full UPN list (deprecated)
  protectedPrefixes: ['admin', 'superadmin', 'root', 'administrator', 'sysadmin', 'owner', 'support', 'helpdesk'],
  invite: { enabled: false },
};

const GITHUB_LINK = 'https://github.com/azincc/CF-M365-Admin';

/* -------------------- Utility -------------------- */
const enc = new TextEncoder();

async function sha256(txt) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(txt));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function jsonResponse(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function redirect(location, status = 302) {
  return new Response(null, { status, headers: { Location: location } });
}

function parseCookies(req) {
  const raw = req.headers.get('Cookie') || '';
  return Object.fromEntries(
    raw.split(';').map((c) => {
      const [k, ...v] = c.trim().split('=');
      return [k, v.join('=')];
    }),
  );
}

function mergeConfig(raw) {
  const base = structuredClone(DEFAULT_CONFIG);
  if (!raw || typeof raw !== 'object') return base;

  const cfg = { ...base, ...raw };

  cfg.turnstile = { ...base.turnstile, ...(raw.turnstile || {}) };
  cfg.invite = { ...base.invite, ...(raw.invite || {}) };

  cfg.globals = Array.isArray(raw.globals) ? raw.globals : base.globals;
  cfg.protectedUsers = Array.isArray(raw.protectedUsers) ? raw.protectedUsers : base.protectedUsers;
  cfg.protectedPrefixes = Array.isArray(raw.protectedPrefixes) ? raw.protectedPrefixes : base.protectedPrefixes;

  cfg.adminUsername = (raw.adminUsername || base.adminUsername || 'admin').toString().trim() || 'admin';
  cfg.adminPath = (raw.adminPath || base.adminPath || '/admin').toString().trim() || '/admin';
  cfg.adminPasswordHash = (raw.adminPasswordHash || base.adminPasswordHash || '').toString();

  return cfg;
}

async function getConfig(env) {
  const cfg = await env.CONFIG_KV.get(KV.CONFIG, 'json');
  return mergeConfig(cfg);
}
async function setConfig(env, cfg) {
  await env.CONFIG_KV.put(KV.CONFIG, JSON.stringify(cfg));
}

async function ensureInvites(env) {
  let data = await env.CONFIG_KV.get(KV.INVITES, 'json');
  if (!data) {
    const compat = await env.CONFIG_KV.get(KV.COMPAT_CARDS, 'json');
    if (compat) {
      await env.CONFIG_KV.put(KV.INVITES, JSON.stringify(compat));
      data = compat;
    } else {
      await env.CONFIG_KV.put(KV.INVITES, JSON.stringify([]));
      data = [];
    }
  }
  return data;
}
async function getInvites(env) {
  const data = await env.CONFIG_KV.get(KV.INVITES, 'json');
  if (data) return data;
  return await ensureInvites(env);
}
async function saveInvites(env, list) {
  await env.CONFIG_KV.put(KV.INVITES, JSON.stringify(list));
}

async function createSession(env) {
  const token = crypto.randomUUID();
  await env.CONFIG_KV.put(KV.SESS_PREFIX + token, Date.now().toString(), { expirationTtl: 60 * 60 * 6 });
  return token;
}
async function verifySession(env, req) {
  const cookies = parseCookies(req);
  const token = cookies.ADMIN_SESSION;
  if (!token) return false;
  const val = await env.CONFIG_KV.get(KV.SESS_PREFIX + token);
  return !!val;
}

function htmlResponse(html, status = 200) {
  return new Response(html, { status, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

function sanitizeSkuMap(str) {
  try {
    const obj = typeof str === 'string' ? JSON.parse(str || '{}') : {};
    if (typeof obj !== 'object' || Array.isArray(obj)) return {};
    return obj;
  } catch {
    return {};
  }
}

function disableSelectIfSingle(arr) {
  return arr.length <= 1;
}

function escapeHtml(value) {
  return (value ?? '')
    .toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function checkPasswordComplexity(pwd){
  if(!pwd || pwd.length<8) return false;
  let s=0;
  if(/[a-z]/.test(pwd)) s++;
  if(/[A-Z]/.test(pwd)) s++;
  if(/\d/.test(pwd)) s++;
  if(/[^a-zA-Z0-9]/.test(pwd)) s++;
  return s>=3;
}

/* -------------------- HTML Templates -------------------- */
const baseStyles = `
    :root {
        --primary: #0f766e;
        --primary-hover: #115e59;
        --primary-soft: rgba(15, 118, 110, 0.12);
        --secondary: #172033;
        --accent: #f59e0b;
        --danger: #dc2626;
        --danger-hover: #b91c1c;
        --surface: rgba(255, 255, 255, 0.86);
        --surface-solid: #ffffff;
        --surface-muted: #f6f8fc;
        --border: rgba(148, 163, 184, 0.22);
        --border-strong: rgba(15, 23, 42, 0.1);
        --text-main: #172033;
        --text-sub: #667085;
        --shadow-lg: 0 24px 64px rgba(15, 23, 42, 0.12);
        --shadow-md: 0 14px 34px rgba(15, 23, 42, 0.08);
        --shadow-sm: 0 6px 16px rgba(15, 23, 42, 0.06);
        --radius-lg: 28px;
        --radius-md: 20px;
        --radius-sm: 16px;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
        margin: 0;
        min-height: 100vh;
        color: var(--text-main);
        font-family: "Segoe UI Variable Display", "Segoe UI Variable Text", "PingFang SC", "Microsoft YaHei", sans-serif;
        background:
          radial-gradient(circle at 14% 18%, rgba(15, 118, 110, 0.18), transparent 28%),
          radial-gradient(circle at 86% 2%, rgba(245, 158, 11, 0.16), transparent 24%),
          radial-gradient(circle at 100% 100%, rgba(37, 99, 235, 0.14), transparent 32%),
          linear-gradient(135deg, #fff7ed 0%, #f5f9ff 44%, #effbf6 100%);
    }
    @keyframes fadeInUp {
      from { opacity: 0; transform: translateY(18px); }
      to { opacity: 1; transform: translateY(0); }
    }
    a {
      color: var(--primary);
      text-decoration: none;
      transition: color .18s ease;
    }
    a:hover { color: var(--primary-hover); }
    code {
      font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
      font-size: .92em;
      background: rgba(15, 23, 42, 0.06);
      padding: 2px 6px;
      border-radius: 8px;
    }
    .card {
      background: var(--surface);
      backdrop-filter: blur(22px);
      -webkit-backdrop-filter: blur(22px);
      padding: 32px;
      border-radius: var(--radius-lg);
      border: 1px solid rgba(255, 255, 255, 0.68);
      box-shadow: var(--shadow-lg);
      animation: fadeInUp .45s ease both;
    }
    button {
      appearance: none;
      min-height: 46px;
      padding: 12px 18px;
      background: linear-gradient(135deg, #0f766e 0%, #2563eb 100%);
      color: #fff;
      border: none;
      border-radius: 16px;
      font-weight: 700;
      letter-spacing: .01em;
      cursor: pointer;
      touch-action: manipulation;
      transition: transform .18s ease, box-shadow .18s ease, opacity .18s ease, filter .18s ease;
      box-shadow: 0 12px 26px rgba(37, 99, 235, 0.18);
    }
    button:hover {
      transform: translateY(-1px);
      filter: saturate(1.05);
      box-shadow: 0 16px 30px rgba(37, 99, 235, 0.22);
    }
    button:disabled {
      background: #94a3b8;
      cursor: not-allowed;
      box-shadow: none;
      transform: none;
      filter: none;
    }
    input, select, textarea {
      width: 100%;
      min-height: 48px;
      padding: 12px 14px;
      border: 1px solid rgba(148, 163, 184, 0.24);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.82);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.9), 0 1px 2px rgba(15, 23, 42, 0.02);
      font-size: 14px;
      color: var(--text-main);
      transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
    }
    input::placeholder, textarea::placeholder { color: #94a3b8; }
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: rgba(15, 118, 110, 0.56);
      box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12), 0 10px 22px rgba(15, 23, 42, 0.06);
      background: #fff;
    }
    .label {
      display: block;
      margin-bottom: 8px;
      font-size: 12px;
      font-weight: 800;
      color: #475569;
      letter-spacing: .04em;
      text-transform: uppercase;
    }
    .row { margin-bottom: 16px; }
    .message {
      margin-top: 14px;
      padding: 14px 16px;
      border-radius: 16px;
      font-size: 13px;
      line-height: 1.6;
      display: none;
      border: 1px solid transparent;
    }
    .message.error {
      background: #fff1f2;
      color: #b42318;
      border-color: #fecdd3;
    }
    .message.success {
      background: #ecfdf3;
      color: #027a48;
      border-color: #abefc6;
    }
    .tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      margin: 2px 4px 2px 0;
      border-radius: 999px;
      background: rgba(37, 99, 235, 0.1);
      color: #1d4ed8;
      font-size: 12px;
      font-weight: 700;
    }
    .table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0 10px;
    }
    .table th {
      padding: 0 14px 6px;
      text-align: left;
      color: #64748b;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .08em;
      cursor: pointer;
      user-select: none;
    }
    .table th .arrow { margin-left: 6px; color: #94a3b8; }
    .table th.active .arrow { color: var(--primary); }
    .table td {
      background: rgba(255, 255, 255, 0.96);
      padding: 15px 14px;
      border-radius: 16px;
      box-shadow: var(--shadow-sm);
      vertical-align: top;
    }
    .toolbar {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 16px;
    }
    .pill {
      padding: 8px 12px;
      border: 1px solid rgba(148, 163, 184, 0.22);
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      background: rgba(255, 255, 255, 0.88);
      color: var(--text-sub);
      cursor: pointer;
      transition: all .18s ease;
    }
    .pill:hover {
      border-color: rgba(15, 118, 110, 0.24);
      color: var(--primary);
    }
    .pill.active {
      border-color: transparent;
      color: #fff;
      background: linear-gradient(135deg, #0f766e 0%, #2563eb 100%);
      box-shadow: 0 10px 24px rgba(37, 99, 235, 0.18);
    }
    .chip {
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(37, 99, 235, 0.08);
      color: #1d4ed8;
      font-size: 12px;
      font-weight: 700;
    }
    .input-compact { max-width: 220px; }
    .flex-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }

    @media (max-width: 480px) {
      body { padding: 12px; }
      .card { padding: 22px; border-radius: 24px; }
      button { width: 100%; }
    }
`;

const GITHUB_ICON = `<svg viewBox="0 0 16 16" version="1.1" width="18" height="18" aria-hidden="true" fill="currentColor" style="vertical-align:middle;"><path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38l-.01-1.49C3.99 14.91 3.48 13.5 3.48 13.5c-.36-.92-.88-1.17-.88-1.17-.72-.5.06-.49.06-.49.79.06 1.2.82 1.2.82.71 1.21 1.86.86 2.31.66.07-.52.28-.86.5-1.06-2-.22-4.1-1-4.1-4.43 0-.98.35-1.78.92-2.41-.09-.22-.4-1.11.09-2.31 0 0 .76-.24 2.49.92a8.64 8.64 0 0 1 4.53 0c1.72-1.16 2.48-.92 2.48-.92.5 1.2.19 2.09.1 2.31.57.63.92 1.43.92 2.41 0 3.44-2.1 4.2-4.11 4.42.29.25.54.73.54 1.48l-.01 2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg>`;

/* Public register page (no admin-query APIs exposed) */
function renderRegisterPage({
  globals,
  selectedGlobalId,
  skuDisplayList,
  protectedPrefixes,
  turnstileSiteKey,
  inviteMode,
  adminPath,
}) {
  const disableGlobal = disableSelectIfSingle(globals);
  const selectedGlobal = globals.find(g => g.id === selectedGlobalId) || globals[0] || null;
  const disableSku = disableSelectIfSingle(skuDisplayList);
  const safeAdminPath = escapeHtml(adminPath);
  const selectedGlobalLabel = selectedGlobal ? escapeHtml(selectedGlobal.label) : '未配置租户';
  const initialSkuName = skuDisplayList?.[0]?.name || '';
  const initialSkuLabel = skuDisplayList?.[0]?.label || '暂无 SKU';
  const safeInitialSkuName = escapeHtml(initialSkuName);
  const safeInitialSkuLabel = escapeHtml(initialSkuLabel);
  const skuSummary = skuDisplayList?.length ? `${skuDisplayList.length} 个可选订阅` : '暂无可选订阅';
  const modeTitle = inviteMode ? '邀请码控制注册范围' : '保留开放式自助开通';
  const modeDesc = inviteMode
    ? '只有持有有效邀请码的成员才能创建账号，适合需要细粒度控制的场景。'
    : '适合内部成员快速开通 Microsoft 365 账号和许可证。';
  const registrationTitle = inviteMode ? 'Office 365 邀请码注册' : 'Office 365 自助开通';
  const registrationDesc = inviteMode
    ? '校验邀请码后自动创建账号并分配许可证。'
    : '选择全局与订阅后，系统会自动完成账号创建与许可证分配。';

  const globalOptions = globals
    .map((g) => {
      const sel = selectedGlobal && g.id === selectedGlobal.id ? 'selected' : '';
      return `<div class="option ${sel}" data-id="${escapeHtml(g.id)}">${escapeHtml(g.label)}</div>`;
    })
    .join('');

  const skuOptions = (list) =>
    (list || [])
      .map((x) => `<div class="option" data-value="${escapeHtml(x.name)}">${escapeHtml(x.label)}</div>`)
      .join('');

  const siteKeyScript = turnstileSiteKey
    ? `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
    : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>${inviteMode ? 'Office365 邀请码自助注册' : 'Office 365 自助开通'}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${baseStyles}
html,body{max-width:100%;overflow-x:hidden;}
body.register-body{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:28px;}
.register-shell{width:min(1120px,100%);display:grid;grid-template-columns:minmax(0,1.12fr) minmax(380px,.88fr);gap:24px;align-items:stretch;}
.register-hero{position:relative;overflow:hidden;padding:34px 30px;border-radius:32px;background:linear-gradient(145deg,rgba(15,23,42,.94),rgba(15,118,110,.9));color:#fff;box-shadow:0 28px 60px rgba(15,23,42,.24);animation:fadeInUp .45s ease both;}
.register-hero::before,.register-hero::after{content:'';position:absolute;border-radius:999px;pointer-events:none;}
.register-hero::before{width:260px;height:260px;top:-92px;right:-72px;background:rgba(245,158,11,.2);filter:blur(10px);}
.register-hero::after{width:220px;height:220px;left:-72px;bottom:-96px;background:rgba(96,165,250,.14);filter:blur(8px);}
.register-hero > *{position:relative;z-index:1;}
.register-kicker{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.16);font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;}
.register-title{margin:18px 0 12px;font-size:clamp(30px,4vw,48px);line-height:1.02;letter-spacing:-.03em;}
.register-desc{margin:0;max-width:620px;font-size:15px;line-height:1.8;color:rgba(255,255,255,.78);}
.register-highlights{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:26px;}
.register-highlight{padding:16px;border-radius:22px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.14);backdrop-filter:blur(10px);}
.register-highlight .mini-label{display:block;margin-bottom:8px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:rgba(255,255,255,.65);}
.register-highlight strong{display:block;font-size:18px;line-height:1.2;}
.register-highlight p{margin:8px 0 0;font-size:13px;line-height:1.7;color:rgba(255,255,255,.72);}
.register-note-list{display:grid;gap:10px;margin-top:24px;}
.register-note{display:flex;gap:12px;align-items:flex-start;padding:14px 16px;border-radius:20px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.1);}
.register-note-index{flex:0 0 auto;width:28px;height:28px;border-radius:12px;display:grid;place-items:center;background:rgba(255,255,255,.16);font-weight:900;font-size:12px;}
.register-note span:last-child{font-size:13px;line-height:1.7;color:rgba(255,255,255,.76);}
.register-card{position:relative;display:flex;flex-direction:column;justify-content:space-between;}
.form-top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:18px;}
.form-heading{max-width:460px;}
.form-heading h2{margin:10px 0 10px;font-size:28px;line-height:1.1;letter-spacing:-.02em;}
.form-heading p{margin:0;color:var(--text-sub);font-size:14px;line-height:1.8;}
.form-badge{display:inline-flex;align-items:center;padding:7px 12px;border-radius:999px;background:rgba(15,118,110,.1);color:var(--primary);font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;}
.form-tags{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;}
.form-tag{padding:9px 12px;border-radius:999px;background:rgba(15,23,42,.05);color:#334155;font-size:12px;font-weight:800;}
.form-tag strong{color:#0f172a;}
.input-group{margin-bottom:16px;}
.hint{margin-top:8px;font-size:12px;line-height:1.6;color:var(--text-sub);}
.hint.error{color:#b42318;font-weight:800;}
.custom-select{position:relative;}
.select-trigger{min-height:52px;border:1px solid rgba(148,163,184,.24);border-radius:18px;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;background:rgba(255,255,255,.86);cursor:pointer;gap:10px;box-shadow:inset 0 1px 0 rgba(255,255,255,.9),0 1px 2px rgba(15,23,42,.03);transition:border-color .18s ease,box-shadow .18s ease,transform .18s ease;}
.select-trigger:hover{border-color:rgba(15,118,110,.32);box-shadow:0 8px 18px rgba(15,23,42,.05);}
.select-trigger span{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:700;color:#0f172a;}
.select-trigger.disabled{cursor:not-allowed;opacity:.65;box-shadow:none;}
.select-arrow{flex:0 0 auto;width:10px;height:10px;border-right:2px solid #64748b;border-bottom:2px solid #64748b;transform:rotate(45deg) translateY(-2px);}
.options-container{position:absolute;top:calc(100% + 10px);left:0;right:0;background:rgba(255,255,255,.97);border-radius:18px;border:1px solid rgba(148,163,184,.18);box-shadow:0 20px 40px rgba(15,23,42,.12);opacity:0;visibility:hidden;transform:translateY(-6px);transition:all .18s ease;z-index:50;overflow:hidden;max-height:48vh;overflow-y:auto;}
.options-container.open{opacity:1;visibility:visible;transform:translateY(0);}
.option{padding:14px 16px;font-size:14px;cursor:pointer;word-break:break-word;transition:background .18s ease,color .18s ease;}
.option:hover{background:rgba(15,118,110,.08);color:var(--primary);}
.option.selected{background:rgba(37,99,235,.1);color:#1d4ed8;font-weight:800;}
.field-tips{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:18px 0 8px;}
.field-tip{padding:14px;border-radius:18px;background:var(--surface-muted);border:1px solid rgba(148,163,184,.14);}
.field-tip .mini-label{display:block;margin-bottom:6px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#64748b;}
.field-tip strong{display:block;font-size:14px;line-height:1.5;}
.field-tip p{margin:6px 0 0;font-size:12px;line-height:1.6;color:var(--text-sub);}
.cf-turnstile{display:flex;justify-content:center;margin:18px 0;}
#btn{width:100%;margin-top:12px;min-height:52px;font-size:15px;}
.form-footer{margin-top:20px;padding-top:18px;border-top:1px solid rgba(148,163,184,.16);display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--text-sub);}
.footer-links{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
.icon-link{display:inline-flex;gap:6px;align-items:center;color:var(--text-sub);font-weight:700;}
.footer-links .admin-link{padding:8px 12px;border-radius:999px;background:rgba(15,118,110,.08);color:var(--primary);}

/* 威慑性弹窗 */
.danger-modal{position:fixed;top:0;left:0;width:100%;height:100%;display:none;align-items:center;justify-content:center;background:rgba(15,23,42,.56);backdrop-filter:blur(6px);z-index:2000;padding:14px;}
.danger-modal .dlg{width:92vw;max-width:520px;background:#fff;border-radius:24px;box-shadow:0 28px 68px rgba(15,23,42,.35);overflow:hidden;}
.danger-modal .bar{background:linear-gradient(135deg,#991b1b,#dc2626);color:#fff;padding:16px 18px;font-weight:900;display:flex;align-items:center;justify-content:space-between;}
.danger-modal .bar .x{width:34px;height:34px;border-radius:12px;background:rgba(255,255,255,.16);display:flex;align-items:center;justify-content:center;font-weight:900;cursor:pointer;}
.danger-modal .content{padding:18px;line-height:1.8;color:#111827;}
.danger-modal .content strong{color:#b91c1c;}
.danger-modal .actions{padding:0 18px 18px;display:flex;gap:10px;}
.danger-modal .actions button{width:100%;background:linear-gradient(135deg,#b91c1c,#ef4444);box-shadow:0 12px 28px rgba(220,38,38,.2);}
.danger-modal .actions button:hover{transform:none;filter:none;background:linear-gradient(135deg,#991b1b,#dc2626);}

@media (max-width: 980px){
  body.register-body{padding:20px;}
  .register-shell{grid-template-columns:1fr;}
  .register-highlights{grid-template-columns:repeat(3,minmax(0,1fr));}
}
@media (max-width: 720px){
  .register-hero{padding:26px 22px;}
  .register-card{padding:24px;}
  .register-highlights{grid-template-columns:1fr;}
  .field-tips{grid-template-columns:1fr;}
}
@media (max-width: 480px){
  body.register-body{padding:16px;}
  .register-title{font-size:30px;}
  .form-heading h2{font-size:24px;}
  .form-tags{justify-content:flex-start;}
}
</style>
${siteKeyScript}
</head>
<body class="register-body">

<div class="danger-modal" id="banModal" role="dialog" aria-modal="true">
  <div class="dlg">
    <div class="bar">
      <span>⚠️ 安全拦截</span>
      <span class="x" onclick="hideBan()">✕</span>
    </div>
    <div class="content">
      <div style="font-size:16px;font-weight:900;margin-bottom:8px;">该用户名被<strong>禁止注册</strong>！</div>
      <div>请勿尝试注册<strong>非法/敏感</strong>用户名，否则系统将持续拦截并记录行为。</div>
      <div style="margin-top:10px;color:#6b7280;font-size:12px;">建议更换一个普通用户名（仅字母/数字）。</div>
    </div>
    <div class="actions">
      <button type="button" onclick="hideBan()">我已知晓</button>
    </div>
  </div>
</div>

<div class="register-shell">
  <section class="register-hero">
    <div class="register-kicker">Cloudflare Worker · Microsoft 365</div>
    <h1 class="register-title">${modeTitle}</h1>
    <p class="register-desc">${modeDesc}</p>

    <div class="register-highlights">
      <div class="register-highlight">
        <span class="mini-label">当前租户</span>
        <strong>${selectedGlobalLabel}</strong>
        <p>切换租户后会自动刷新页面，并展示该租户可分配的订阅与余量。</p>
      </div>
      <div class="register-highlight">
        <span class="mini-label">订阅可见性</span>
        <strong>${escapeHtml(skuSummary)}</strong>
        <p>注册只暴露前台所需数据，不开放后台查询接口。</p>
      </div>
      <div class="register-highlight">
        <span class="mini-label">保护规则</span>
        <strong>${protectedPrefixes?.length || 0} 条敏感前缀</strong>
        <p>命中高风险用户名时，系统会直接拦截注册并提示更换名称。</p>
      </div>
    </div>

    <div class="register-note-list">
      <div class="register-note">
        <span class="register-note-index">01</span>
        <span>用户名只允许字母和数字，适合直接映射为邮箱前缀，避免后续目录清理成本。</span>
      </div>
      <div class="register-note">
        <span class="register-note-index">02</span>
        <span>密码需要满足 4 类字符中的任意 3 类，页面会实时提示当前是否满足强度要求。</span>
      </div>
      <div class="register-note">
        <span class="register-note-index">03</span>
        <span>${inviteMode ? '邀请码会在注册时校验范围与次数，防止被重复滥用。' : '账号创建成功后可直接前往 Office.com 登录，无需再经过后台二次审批。'} </span>
      </div>
    </div>
  </section>

  <section class="card register-card">
    <div>
      <div class="form-top">
        <div class="form-heading">
          <span class="form-badge">${inviteMode ? 'Invite Only' : 'Self Service'}</span>
          <h2>${registrationTitle}</h2>
          <p>${registrationDesc}</p>
        </div>
        <div class="form-tags">
          <span class="form-tag">租户 <strong>${selectedGlobalLabel}</strong></span>
          <span class="form-tag">${escapeHtml(skuSummary)}</span>
          <span class="form-tag">${inviteMode ? '需要邀请码' : '无需邀请码'}</span>
        </div>
      </div>

      <form id="regForm">
        <input type="hidden" name="globalId" id="globalId" value="${selectedGlobal ? escapeHtml(selectedGlobal.id) : ''}">
        <input type="hidden" name="skuName" id="skuName" value="${safeInitialSkuName}">

        <div class="input-group">
          <span class="label">选择全局</span>
          <div class="custom-select">
            <div class="select-trigger ${disableGlobal ? 'disabled' : ''}" id="globalTrigger">
              <span>${selectedGlobalLabel}</span>
              <div class="select-arrow"></div>
            </div>
            <div class="options-container" id="globalOptions">${globalOptions}</div>
          </div>
          <div class="hint">切换全局会自动刷新页面，以获取最新的订阅余量。</div>
        </div>

        <div class="input-group">
          <span class="label">选择订阅类型</span>
          <div class="custom-select">
            <div class="select-trigger ${disableSku ? 'disabled' : ''}" id="skuTrigger">
              <span>${safeInitialSkuLabel}</span>
              <div class="select-arrow"></div>
            </div>
            <div class="options-container" id="skuOptions">${skuOptions(skuDisplayList)}</div>
          </div>
        </div>

        <div class="input-group">
          <span class="label">用户名 (仅字母和数字)</span>
          <input type="text" id="username" required pattern="[a-zA-Z0-9]+" placeholder="例如：user123" autocomplete="off">
          <div class="hint" id="userHint"></div>
        </div>

        <div class="input-group">
          <span class="label">密码（8 位以上，4 选 3）</span>
          <input type="password" id="password" required placeholder="设置强密码" autocomplete="new-password">
          <div class="hint" id="pwdHint">密码需满足：长度 ≥ 8，且大写 / 小写 / 数字 / 符号四类中满足任意三类。</div>
        </div>

        ${
          inviteMode
            ? `<div class="input-group">
                <span class="label">邀请码</span>
                <input type="text" id="inviteCode" required placeholder="请输入有效邀请码">
               </div>`
            : ''
        }

        <div class="field-tips">
          <div class="field-tip">
            <span class="mini-label">命名建议</span>
            <strong>优先使用短且稳定的用户名</strong>
            <p>避免敏感前缀、特殊语义或与管理员账号混淆的命名。</p>
          </div>
          <div class="field-tip">
            <span class="mini-label">开通结果</span>
            <strong>创建完成后立即可登录</strong>
            <p>页面会返回完整账号信息，并保留你刚刚设置的密码。</p>
          </div>
        </div>

        ${turnstileSiteKey ? `<div class="cf-turnstile" data-sitekey="${turnstileSiteKey}"></div>` : ''}

        <button type="submit" id="btn">创建并分配账号</button>
        <div id="msg" class="message"></div>
      </form>
    </div>

    <div class="form-footer">
      <span>Powered by Cloudflare Workers</span>
      <div class="footer-links">
        <a class="icon-link" href="${GITHUB_LINK}" target="_blank" rel="noopener noreferrer">${GITHUB_ICON} CF-M365-Admin</a>
        <a class="icon-link admin-link" href="${safeAdminPath}/login">进入后台管理</a>
      </div>
    </div>
  </section>
</div>

<script>
  const globals = ${JSON.stringify(globals)};
  const selectedGlobalId = ${JSON.stringify(selectedGlobal ? selectedGlobal.id : '')};
  const protectedPrefixes = ${JSON.stringify((protectedPrefixes || []).map(s=>String(s).toLowerCase()))};
  const inviteMode = ${inviteMode ? 'true' : 'false'};
  const turnstileOn = ${turnstileSiteKey ? 'true' : 'false'};

  function openSelect(triggerId, containerId, disabled) {
    const trigger = document.getElementById(triggerId);
    const container = document.getElementById(containerId);
    if (disabled) { trigger.classList.add('disabled'); return; }
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      container.classList.toggle('open');
    });
    document.addEventListener('click', () => container.classList.remove('open'));
  }

  openSelect('globalTrigger', 'globalOptions', ${disableGlobal ? 'true' : 'false'});
  openSelect('skuTrigger', 'skuOptions', ${disableSku ? 'true' : 'false'});

  // 切换全局：直接刷新页面（避免暴露后台查询 API）
  document.querySelectorAll('#globalOptions .option').forEach(opt => {
    opt.addEventListener('click', () => {
      const gid = opt.getAttribute('data-id');
      if (!gid || gid === selectedGlobalId) return;
      const u = new URL(location.href);
      u.searchParams.set('g', gid);
      location.href = u.toString();
    });
  });

  // SKU 选择
  document.querySelectorAll('#skuOptions .option').forEach(opt => {
    opt.addEventListener('click', () => {
      const v = opt.getAttribute('data-value');
      document.getElementById('skuName').value = v || '';
      document.getElementById('skuTrigger').querySelector('span').innerText = opt.innerText;
      document.getElementById('skuOptions').classList.remove('open');
    });
  });

  function showBan(){ document.getElementById('banModal').style.display='flex'; }
  function hideBan(){ document.getElementById('banModal').style.display='none'; }

  function checkComplexity(pwd) {
    if(!pwd || pwd.length < 8) return false;
    let s=0; if(/[a-z]/.test(pwd))s++; if(/[A-Z]/.test(pwd))s++; if(/\\d/.test(pwd))s++; if(/[^a-zA-Z0-9]/.test(pwd))s++;
    return s>=3;
  }

  function isBannedUsername(name){
    const u = (name||'').trim().toLowerCase();
    if(!u) return false;
    return protectedPrefixes.includes(u);
  }

  const btn = document.getElementById('btn');
  const userEl = document.getElementById('username');
  const pwdEl = document.getElementById('password');
  const userHint = document.getElementById('userHint');
  const pwdHint = document.getElementById('pwdHint');

  function validateForm(){
    const username = userEl.value.trim();
    const password = pwdEl.value || '';
    let ok = true;

    // username format
    if(username && !/^[a-zA-Z0-9]+$/.test(username)){
      userHint.className='hint error';
      userHint.innerText='用户名只能包含字母和数字。';
      ok=false;
    } else if(isBannedUsername(username)){
      userHint.className='hint error';
      userHint.innerText='该用户名属于敏感/高危用户名，禁止注册。';
      ok=false;
    } else {
      userHint.className='hint';
      userHint.innerText='';
    }

    // password complexity
    if(password && !checkComplexity(password)){
      pwdHint.className='hint error';
      pwdHint.innerText='密码不符合要求：长度≥8，且大写/小写/数字/符号四类中满足任意三类。';
      ok=false;
    } else {
      pwdHint.className='hint';
      pwdHint.innerText='密码需满足：长度 ≥ 8，且大写/小写/数字/符号四类中满足任意三类。';
    }

    // password contains username
    if(username && password && password.toLowerCase().includes(username.toLowerCase())){
      pwdHint.className='hint error';
      pwdHint.innerText='密码不能包含用户名（大小写不敏感）。';
      ok=false;
    }

    // required selections
    const globalId = document.getElementById('globalId').value;
    const skuName = document.getElementById('skuName').value;
    if(!globalId || !skuName) ok=false;

    btn.disabled = !ok;
    return ok;
  }

  userEl.addEventListener('input', validateForm);
  pwdEl.addEventListener('input', validateForm);
  validateForm();

  document.getElementById('regForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const msg = document.getElementById('msg');

    const username = userEl.value.trim();
    if(isBannedUsername(username)){
      showBan();
      msg.className='message error';
      msg.style.display='block';
      msg.innerText='❌ 该用户名被禁止注册！请勿尝试注册非法用户名！';
      return;
    }
    if(!validateForm()){
      msg.className='message error';
      msg.style.display='block';
      msg.innerText='❌ 请先修正表单错误后再提交。';
      return;
    }

    const password = pwdEl.value;
    const skuName = document.getElementById('skuName').value;
    const globalId = document.getElementById('globalId').value;
    const inviteCode = inviteMode ? document.getElementById('inviteCode').value.trim() : '';

    if(inviteMode && !inviteCode){ msg.className='message error'; msg.style.display='block'; msg.innerText='请填写邀请码'; return; }

    btn.disabled = true; btn.innerText = '正在创建...';
    msg.style.display='none';

    const form = new FormData();
    form.append('username', username);
    form.append('password', password);
    form.append('skuName', skuName);
    form.append('globalId', globalId);
    if(inviteMode) form.append('inviteCode', inviteCode);
    if(turnstileOn){
      const v = document.querySelector('[name="cf-turnstile-response"]');
      form.append('cf-turnstile-response', v ? v.value : '');
    }

    try{
      const res = await fetch('/', { method:'POST', body: form });
      const data = await res.json();
      msg.style.display='block';
      if(data.success){
        msg.className='message success';
        msg.innerHTML = '🎉 开通成功！<br>账号: '+data.email+'<br>密码: (您刚才设置的)<br><a href="https://portal.office.com" target="_blank" style="color:#166534;font-weight:900;">前往 Office.com 登录</a>';
        document.getElementById('regForm').reset();
      }else{
        msg.className='message error';
        msg.innerText = '❌ '+(data.message||'失败');
        if((data.message||'').includes('禁止注册')){ showBan(); }
      }
      if(turnstileOn && typeof turnstile!=='undefined') turnstile.reset();
    }catch(err){
      msg.className='message error'; msg.style.display='block'; msg.innerText='网络异常，请稍后重试';
    }finally{ btn.disabled=false; btn.innerText='创建并分配账号'; validateForm(); }
  });

  // Expose for inline handler
  window.hideBan = hideBan;
</script>
</body></html>`;
}

const ADMIN_PAGE_META = {
  dashboard: {
    kicker: 'Operations Overview',
    description: '集中查看租户活跃度、存储使用量和 Graph 报表可用性。',
    focus: '汇总指标',
    tip: '适合先判断哪些租户需要进一步排查或补授权。',
  },
  users: {
    kicker: 'Directory Workspace',
    description: '筛选、检索并批量维护已开通用户及其许可证分配状态。',
    focus: '目录用户',
    tip: '支持按全局、订阅和关键字快速收敛结果集。',
  },
  globals: {
    kicker: 'Tenant Inventory',
    description: '维护每个全局租户的连接参数、默认域和可用订阅映射。',
    focus: '全局配置',
    tip: '新增或修改租户后，前台注册页会立即感知变化。',
  },
  apps: {
    kicker: 'Enterprise Apps',
    description: '查看和审批企业应用管理员同意请求，统一追踪审批状态。',
    focus: '同意审批',
    tip: '待审批请求和已通过请求可在同一页面中筛选切换。',
  },
  invites: {
    kicker: 'Access Control',
    description: '生成、导出和回收邀请码，控制注册入口与可用范围。',
    focus: '邀请码池',
    tip: '筛选结果支持批量选中与移动端快捷操作。',
  },
  settings: {
    kicker: 'System Config',
    description: '调整后台入口、Turnstile 配置和受保护用户名策略。',
    focus: '系统设置',
    tip: '建议先维护保护前缀，再开放前台自助注册。',
  },
};

/* Admin layout */
function adminLayout({ title, content, adminPath, active }) {
  const safeAdminPath = escapeHtml(adminPath);
  const meta = ADMIN_PAGE_META[active] || {
    kicker: 'Admin Workspace',
    description: '统一管理租户、用户和系统配置。',
    focus: title,
    tip: '当前页面为后台管理模块。',
  };

  return `<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>${baseStyles}
html,body{max-width:100%;overflow-x:hidden;}
body.admin-body{padding:0;margin:0;background:linear-gradient(180deg,#f7f8fc 0%,#eef4f9 100%);}
.admin-shell{min-height:100vh;}
.nav{position:sticky;top:0;z-index:120;padding:18px 24px 16px;background:rgba(255,255,255,.82);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid rgba(148,163,184,.14);box-shadow:0 14px 32px rgba(15,23,42,.05);}
.nav-top{max-width:1320px;margin:0 auto 16px;display:flex;justify-content:space-between;gap:16px;align-items:flex-start;}
.brand-lockup{display:flex;align-items:flex-start;gap:14px;min-width:0;}
.brand-mark{flex:0 0 auto;width:50px;height:50px;border-radius:18px;display:grid;place-items:center;background:linear-gradient(135deg,#0f766e 0%,#2563eb 100%);color:#fff;font-size:18px;font-weight:900;box-shadow:0 16px 28px rgba(37,99,235,.18);}
.brand-copy{min-width:0;}
.brand-title{font-size:18px;font-weight:900;line-height:1.15;color:#0f172a;}
.brand-sub{margin-top:6px;color:#64748b;font-size:13px;line-height:1.6;max-width:680px;}
.nav-actions{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap;}
.mode-badge{display:inline-flex;align-items:center;gap:8px;padding:9px 12px;border-radius:999px;background:rgba(245,158,11,.14);color:#b45309;font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;}
.nav-link{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:999px;background:rgba(241,245,249,.96);border:1px solid rgba(148,163,184,.16);color:#334155;font-weight:800;white-space:nowrap;}
.nav-link:hover{color:var(--primary);border-color:rgba(15,118,110,.24);}
.tabs{max-width:1320px;margin:0 auto;display:flex;gap:10px;overflow-x:auto;padding-bottom:4px;scrollbar-width:none;}
.tabs::-webkit-scrollbar{display:none;}
.tab{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:12px 16px;border-radius:16px;background:rgba(241,245,249,.84);border:1px solid transparent;color:#334155;text-decoration:none;font-weight:800;white-space:nowrap;box-shadow:inset 0 1px 0 rgba(255,255,255,.88);}
.tab:hover{border-color:rgba(15,118,110,.18);color:var(--primary);}
.tab.active{background:linear-gradient(135deg,#0f766e 0%,#2563eb 100%);color:#fff;box-shadow:0 14px 28px rgba(37,99,235,.18);}
.container{max-width:1320px;margin:0 auto;padding:28px 18px 36px;}
.page-hero{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:16px;margin:0 0 20px;}
.page-hero-main,.page-hero-side{border-radius:28px;border:1px solid rgba(255,255,255,.78);box-shadow:var(--shadow-md);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);}
.page-hero-main{padding:28px;background:linear-gradient(135deg,rgba(15,118,110,.09),rgba(37,99,235,.08));}
.page-hero-side{padding:16px;background:rgba(255,255,255,.78);}
.eyebrow{display:inline-flex;align-items:center;padding:8px 12px;border-radius:999px;background:rgba(15,118,110,.1);color:var(--primary);font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;}
.page-title{margin:14px 0 8px;font-size:clamp(28px,4vw,42px);line-height:1.04;letter-spacing:-.03em;color:#0f172a;}
.page-description{max-width:760px;color:#64748b;font-size:14px;line-height:1.8;}
.page-side-grid{display:grid;gap:12px;height:100%;}
.hero-card{padding:16px;border-radius:22px;background:rgba(15,23,42,.03);border:1px solid rgba(148,163,184,.12);}
.hero-card .mini-label{display:block;margin-bottom:8px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#64748b;}
.hero-card strong{display:block;font-size:20px;line-height:1.2;color:#0f172a;}
.hero-card p{margin:8px 0 0;color:#64748b;font-size:13px;line-height:1.7;}
.section{background:rgba(255,255,255,.84);border-radius:24px;border:1px solid rgba(255,255,255,.74);box-shadow:var(--shadow-md);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);padding:24px;margin-bottom:18px;}
.badge{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;background:rgba(245,158,11,.14);color:#b45309;font-weight:800;font-size:12px;letter-spacing:.06em;text-transform:uppercase;}
.table-wrap{overflow-x:auto;}
input[type=checkbox]{width:18px;height:18px;accent-color:var(--primary);}
.modal{position:fixed;top:0;left:0;width:100%;height:100%;display:none;align-items:center;justify-content:center;background:rgba(15,23,42,.38);backdrop-filter:blur(4px);z-index:1000;padding:16px;}
.modal .dialog{background:rgba(255,255,255,.96);border-radius:24px;padding:22px;min-width:320px;max-width:92vw;max-height:85vh;overflow:auto;box-shadow:0 24px 54px rgba(15,23,42,.22);animation:fadeInUp .22s ease;}
.modal .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}
.modal .footer{display:flex;justify-content:flex-end;gap:10px;margin-top:14px;}
.modal-close{width:34px;height:34px;padding:0;border-radius:12px;background:#e2e8f0;color:#334155;display:flex;align-items:center;justify-content:center;font-weight:900;line-height:1;box-shadow:none;}
.modal-close:hover{background:#cbd5e1;transform:none;box-shadow:none;filter:none;}
.btn-ghost{background:rgba(241,245,249,.96);color:#334155;border:1px solid rgba(148,163,184,.16);box-shadow:none;}
.btn-ghost:hover{background:#e2e8f0;transform:none;box-shadow:none;filter:none;}
.btn-danger{background:linear-gradient(135deg,#dc2626,#ef4444);box-shadow:0 12px 26px rgba(220,38,38,.18);}
.btn-danger:hover{background:linear-gradient(135deg,#b91c1c,#dc2626);box-shadow:0 14px 30px rgba(220,38,38,.22);}
label.inline{display:flex;align-items:center;gap:8px;margin:6px 0;}
.pagination{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.page-input{width:90px;}
.search-box{display:flex;gap:8px;flex-wrap:wrap;align-items:center;}
.subtle{color:#64748b;font-size:12px;line-height:1.7;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:18px;}
.stat-card{background:linear-gradient(135deg,#ffffff,#f7fbff);border:1px solid rgba(148,163,184,.16);border-radius:22px;padding:18px;box-shadow:0 12px 24px rgba(15,23,42,.05);}
.stat-card .kicker{font-size:12px;color:#64748b;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
.stat-card .value{font-size:30px;font-weight:900;color:#111827;margin:8px 0 6px;line-height:1.1;}
.stat-card .meta{font-size:12px;color:#64748b;line-height:1.7;}
.status-pill{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;font-size:12px;font-weight:800;background:#ecfdf5;color:#166534;}
.status-pill.warn{background:#fff7ed;color:#c2410c;}
.status-pill.muted{background:#f3f4f6;color:#475569;}
.empty-state{padding:24px;border:1px dashed rgba(148,163,184,.5);border-radius:18px;background:#f8fafc;color:#64748b;text-align:center;}

@media (max-width: 980px){
  .nav{padding:16px 16px 14px;}
  .nav-top{flex-direction:column;align-items:flex-start;margin-bottom:14px;}
  .nav-actions{justify-content:flex-start;}
  .page-hero{grid-template-columns:1fr;}
}

/* -------- Responsive (mobile) -------- */
@media (max-width: 720px){
  body.admin-body{padding:0;}
  .brand-lockup{align-items:center;}
  .brand-mark{width:44px;height:44px;border-radius:16px;}
  .tabs{width:100%;padding-bottom:2px;}
  .tab{min-height:44px;padding:10px 14px;}
  .container{padding:18px 12px 26px;}
  .page-hero-main,.page-hero-side{padding:20px;}
  .section{padding:16px;}
  .input-compact{max-width:100%;}
  .modal .dialog{min-width:unset;width:92vw;}
  .toolbar{gap:8px;}
  .toolbar button,.pagination button,.modal .footer button{padding:10px 12px;font-size:13px;min-height:44px;}
  .toolbar input,.toolbar select{padding:10px 12px;font-size:13px;}
  .search-box{width:100%;}
  .pagination{gap:6px;}
  .page-input{width:78px;}
  .stat-card .value{font-size:24px;}
}

/* Responsive tables -> stack rows into cards */
@media (max-width: 720px){
  .table-wrap{overflow-x:visible;}
  .table{border-spacing:0 12px;}
  .table thead{display:none;}
  .table tr{display:block;background:rgba(255,255,255,.96);border-radius:18px;box-shadow:0 8px 22px rgba(15,23,42,.08);overflow:hidden;}
  .table td{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;width:100%;background:transparent;box-shadow:none;border-radius:0;padding:10px 14px;word-break:break-word;}
  .table td:not(:last-child){border-bottom:1px solid #eef2f7;}
  .table td::before{content:attr(data-label);font-weight:800;color:#64748b;font-size:12px;min-width:92px;}
  .table td:first-child{justify-content:flex-start;}
  .table td:first-child::before{content:'';min-width:0;}
  .table td code{word-break:break-all;}
  .tag{white-space:normal;}
}
</style>
</head><body class="admin-body">
<div class="admin-shell">
  <div class="nav">
    <div class="nav-top">
      <div class="brand-lockup">
        <div class="brand-mark">365</div>
        <div class="brand-copy">
          <div class="brand-title">Office 365 Admin</div>
          <div class="brand-sub">单 Worker 管理界面，集中维护租户、用户、自助注册入口和邀请码策略。</div>
        </div>
      </div>
      <div class="nav-actions">
        <span class="mode-badge">安全模式</span>
        <a class="nav-link" href="${GITHUB_LINK}" target="_blank" rel="noopener noreferrer">${GITHUB_ICON}<span>GitHub</span></a>
        <a class="nav-link" href="/" target="_blank" rel="noopener noreferrer">打开前台页面</a>
      </div>
    </div>
    <div class="tabs">
      <a class="tab ${active==='dashboard'?'active':''}" href="${safeAdminPath}/dashboard">看板</a>
      <a class="tab ${active==='users'?'active':''}" href="${safeAdminPath}/users">用户</a>
      <a class="tab ${active==='globals'?'active':''}" href="${safeAdminPath}/globals">全局账户</a>
      <a class="tab ${active==='apps'?'active':''}" href="${safeAdminPath}/enterprise-apps">企业应用</a>
      <a class="tab ${active==='invites'?'active':''}" href="${safeAdminPath}/invites">邀请码</a>
      <a class="tab ${active==='settings'?'active':''}" href="${safeAdminPath}/settings">设置</a>
    </div>
  </div>

  <div class="container">
    <div class="page-hero">
      <div class="page-hero-main">
        <span class="eyebrow">${meta.kicker}</span>
        <h1 class="page-title">${title}</h1>
        <div class="page-description">${meta.description}</div>
      </div>
      <div class="page-hero-side">
        <div class="page-side-grid">
          <div class="hero-card">
            <span class="mini-label">当前模块</span>
            <strong>${meta.focus}</strong>
            <p>${meta.tip}</p>
          </div>
          <div class="hero-card">
            <span class="mini-label">快速提示</span>
            <strong>路径：${safeAdminPath}</strong>
            <p>顶部导航保持常驻，可在后台模块之间快速切换，不必返回首页。</p>
          </div>
        </div>
      </div>
    </div>
${content}
  </div>
</div>
</body></html>`;
}

/* Setup page */
function renderSetup(adminPath) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>初始化安装</title>
<style>${baseStyles}
body{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px;}
.card{width:100%;max-width:520px;}
h2{margin:0 0 12px 0;}
.desc{color:#6b7280;font-size:14px;margin-bottom:16px;}
.row{margin-bottom:14px;}
.helper{font-size:12px;color:#6b7280;margin-top:6px;line-height:1.5;}
</style></head><body>
<div class="card">
  <h2>首次安装</h2>
  <div class="desc">设置后台用户名、密码与自定义后台路径。保存后会写入 KV 并上锁。</div>
  <form id="setupForm">
    <div class="row">
      <span class="label">管理员用户名</span>
      <input type="text" id="user" required placeholder="例如：admin" pattern="[a-zA-Z0-9_\-]{3,32}">
      <div class="helper">3-32 位，仅字母/数字/_/-</div>
    </div>
    <div class="row">
      <span class="label">管理员密码</span>
      <input type="password" id="pwd" required placeholder="至少 8 位强密码">
    </div>
    <div class="row">
      <span class="label">后台路径 (例如 /admin)</span>
      <input type="text" id="path" value="${adminPath}" required pattern="\/[a-zA-Z0-9\-_/]+">
    </div>
    <button type="submit" id="btn">保存并进入后台</button>
  </form>
  <div id="msg" class="message" style="display:none;"></div>
  <div class="footer" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">${GITHUB_ICON}<a href="${GITHUB_LINK}" target="_blank">CF-M365-Admin</a></div>
</div>
<script>
document.getElementById('setupForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const username = (document.getElementById('user').value || '').trim();
  const pwd = document.getElementById('pwd').value;
  const path = (document.getElementById('path').value || '/admin').trim();
  const btn = document.getElementById('btn');
  const msg = document.getElementById('msg');

  if(!/^[a-zA-Z0-9_\-]{3,32}$/.test(username)){
    msg.innerText='用户名格式不正确（3-32位，仅字母/数字/_/-）';
    msg.className='message error'; msg.style.display='block'; return;
  }
  if(!pwd || pwd.length<8){
    msg.innerText='密码至少 8 位';
    msg.className='message error'; msg.style.display='block'; return;
  }
  btn.disabled=true; btn.innerText='正在保存...';
  msg.style.display='none';

  const res = await fetch('${adminPath}/setup',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username, password:pwd, adminPath:path})
  });
  const data = await res.json();
  if(data.success){ window.location.href = path + '/login'; }
  else {
    msg.className='message error'; msg.style.display='block';
    msg.innerText=data.message||'保存失败';
    btn.disabled=false; btn.innerText='保存并进入后台';
  }
});
</script>
</body></html>`;
}

/* Login page */
function renderLogin(adminPath) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录后台</title>
<style>${baseStyles}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.card{max-width:440px;width:100%;}
.row{margin-bottom:12px;}
</style></head><body>
<div class="card">
  <div class="header-row" style="margin-bottom:10px;">
    <h2>后台登录</h2>
    <a href="${GITHUB_LINK}" class="icon-link" target="_blank">${GITHUB_ICON}</a>
  </div>
  <form id="loginForm">
    <div class="row">
      <span class="label">用户名</span>
      <input type="text" id="user" required placeholder="请输入后台用户名">
    </div>
    <div class="row">
      <span class="label">密码</span>
      <input type="password" id="pwd" required placeholder="请输入后台密码">
    </div>
    <button type="submit" id="btn" style="margin-top:8px;">登录</button>
  </form>
  <div id="msg" class="message" style="display:none;"></div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const username = (document.getElementById('user').value||'').trim();
  const pwd = document.getElementById('pwd').value;
  const btn = document.getElementById('btn');
  const msg = document.getElementById('msg');
  btn.disabled=true; btn.innerText='验证中...';
  msg.style.display='none';
  const res = await fetch('${adminPath}/login',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username, password:pwd})
  });
  const data = await res.json();
  if(data.success){ window.location.href='${adminPath}/users'; }
  else {
    msg.className='message error'; msg.style.display='block';
    msg.innerText=data.message||'登录失败';
    btn.disabled=false; btn.innerText='登录';
  }
});
</script>
</body></html>`;
}

function renderDashboardPage(adminPath) {
  return adminLayout({
    title: '管理看板',
    adminPath,
    active: 'dashboard',
    content: `
<div class="section">
  <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
    <div>
      <div class="badge">Microsoft 365 Usage</div>
      <h2 style="margin:10px 0 6px;">租户看板</h2>
      <div class="subtle">显示最近 7 天活跃用户数，以及 SharePoint + OneDrive 已用存储量。</div>
      <div class="subtle">需要在对应应用上授予并完成管理员同意 <code>Reports.Read.All</code>。</div>
    </div>
    <div class="toolbar" style="margin:0;">
      <button id="btnDashRefresh">🔄 刷新看板</button>
    </div>
  </div>
</div>

<div class="stats-grid" id="dashboardStats">
  <div class="stat-card"><div class="kicker">全局数</div><div class="value">-</div><div class="meta">加载中...</div></div>
  <div class="stat-card"><div class="kicker">活跃用户数</div><div class="value">-</div><div class="meta">加载中...</div></div>
  <div class="stat-card"><div class="kicker">已用存储量</div><div class="value">-</div><div class="meta">加载中...</div></div>
</div>

<div class="section">
  <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px;">
    <div>
      <h3 style="margin:0;">全局明细</h3>
      <div class="subtle" id="dashboardMeta">正在读取报表...</div>
    </div>
  </div>
  <div class="table-wrap">
    <table class="table">
      <thead>
        <tr>
          <th>全局</th>
          <th>活跃用户数</th>
          <th>已用存储量</th>
          <th>SharePoint</th>
          <th>OneDrive</th>
          <th>状态</th>
        </tr>
      </thead>
      <tbody id="dashboardBody">
        <tr><td colspan="6" style="text-align:center;">加载中...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<script>
const adminPath = '${adminPath}';

function esc(v){
  return (v ?? '').toString()
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

function formatCount(v){
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString('zh-CN') : '--';
}

function formatBytes(v){
  const n = Number(v);
  if(!Number.isFinite(n) || n < 0) return '--';
  if(n === 0) return '0 B';
  const units = ['B','KB','MB','GB','TB','PB'];
  let idx = 0;
  let val = n;
  while(val >= 1024 && idx < units.length - 1){
    val /= 1024;
    idx++;
  }
  const fixed = val >= 100 || idx === 0 ? 0 : val >= 10 ? 1 : 2;
  return val.toFixed(fixed) + ' ' + units[idx];
}

function renderSummary(summary){
  const wrap = document.getElementById('dashboardStats');
  wrap.innerHTML = [
    '<div class="stat-card">'
      + '<div class="kicker">全局数</div>'
      + '<div class="value">' + formatCount(summary.globalsTotal) + '</div>'
      + '<div class="meta">已配置并参与看板统计的租户数量</div>'
    + '</div>',
    '<div class="stat-card">'
      + '<div class="kicker">活跃用户数</div>'
      + '<div class="value">' + formatCount(summary.activeUsers) + '</div>'
      + '<div class="meta">最近 7 天，已成功读取 ' + formatCount(summary.activeUsersReady) + ' / ' + formatCount(summary.globalsTotal) + ' 个全局</div>'
    + '</div>',
    '<div class="stat-card">'
      + '<div class="kicker">已用存储量</div>'
      + '<div class="value">' + formatBytes(summary.storageBytes) + '</div>'
      + '<div class="meta">SharePoint ' + formatBytes(summary.sharePointBytes) + ' + OneDrive ' + formatBytes(summary.oneDriveBytes) + '</div>'
    + '</div>'
  ].join('');
}

function renderRows(items){
  const body = document.getElementById('dashboardBody');
  if(!items.length){
    body.innerHTML = '<tr><td colspan="6"><div class="empty-state">当前还没有配置任何全局租户。</div></td></tr>';
    return;
  }
  body.innerHTML = items.map(item=>{
    const activeText = item.activeUsers == null
      ? '<span style="color:#9ca3af;">--</span><div class="subtle">' + esc(item.activeUsersError || '暂无数据') + '</div>'
      : '<strong>' + formatCount(item.activeUsers) + '</strong><div class="subtle">报表日期：' + esc(item.activeUsersReportDate || '-') + '</div>';
    const storageText = item.totalStorageBytes == null
      ? '<span style="color:#9ca3af;">--</span><div class="subtle">' + esc(item.storageError || '暂无数据') + '</div>'
      : '<strong>' + formatBytes(item.totalStorageBytes) + '</strong><div class="subtle">报表日期：' + esc(item.storageReportDate || '-') + '</div>';
    let statusClass = 'status-pill';
    let statusText = '正常';
    if(item.activeUsers == null && item.totalStorageBytes == null){
      statusClass = 'status-pill warn';
      statusText = '报表不可用';
    }else if(item.activeUsers == null || item.totalStorageBytes == null){
      statusClass = 'status-pill muted';
      statusText = '部分可用';
    }
    return '<tr>'
      + '<td data-label="全局"><strong>' + esc(item.label) + '</strong><div class="subtle">' + esc(item.reportRefreshDate || '') + '</div></td>'
      + '<td data-label="活跃用户数">' + activeText + '</td>'
      + '<td data-label="已用存储量">' + storageText + '</td>'
      + '<td data-label="SharePoint">' + (item.sharePointBytes == null ? '<span style="color:#9ca3af;">--</span>' : formatBytes(item.sharePointBytes)) + '</td>'
      + '<td data-label="OneDrive">' + (item.oneDriveBytes == null ? '<span style="color:#9ca3af;">--</span>' : formatBytes(item.oneDriveBytes)) + '</td>'
      + '<td data-label="状态"><span class="' + statusClass + '">' + statusText + '</span></td>'
    + '</tr>';
  }).join('');
}

async function loadDashboard(){
  const btn = document.getElementById('btnDashRefresh');
  btn.disabled = true;
  btn.innerText = '刷新中...';
  document.getElementById('dashboardMeta').innerText = '正在读取 Graph 报表...';
  try{
    const res = await fetch(adminPath + '/api/dashboard');
    const data = await res.json().catch(()=>({}));
    if(!res.ok || !data.success){
      document.getElementById('dashboardMeta').innerText = data.message || '看板加载失败';
      document.getElementById('dashboardBody').innerHTML = '<tr><td colspan="6"><div class="empty-state">' + esc(data.message || '看板加载失败') + '</div></td></tr>';
      return;
    }
    renderSummary(data.summary || {});
    renderRows(data.items || []);
    const metaParts = [];
    metaParts.push('统计周期：最近 7 天');
    if(data.summary){
      metaParts.push('活跃用户已读取 ' + formatCount(data.summary.activeUsersReady) + ' / ' + formatCount(data.summary.globalsTotal) + ' 个全局');
      metaParts.push('存储已读取 ' + formatCount(data.summary.storageReady) + ' / ' + formatCount(data.summary.globalsTotal) + ' 个全局');
    }
    document.getElementById('dashboardMeta').innerText = metaParts.join(' · ');
  }catch(e){
    document.getElementById('dashboardMeta').innerText = e.message || '看板加载失败';
    document.getElementById('dashboardBody').innerHTML = '<tr><td colspan="6"><div class="empty-state">' + esc(e.message || '看板加载失败') + '</div></td></tr>';
  }finally{
    btn.disabled = false;
    btn.innerText = '🔄 刷新看板';
  }
}

document.getElementById('btnDashRefresh').onclick = loadDashboard;
loadDashboard();
</script>`
  });
}

/* Admin pages */
function renderUsersPage(adminPath) {
  return adminLayout({
    title: '用户管理',
    adminPath,
    active: 'users',
    content: `
<div class="section">
  <div class="toolbar">
    <button id="btnRefresh">🔄 刷新</button>
    <button id="btnLic">📊 查看订阅</button>
    <button id="btnPwd">🔑 重置密码</button>
    <button id="btnDel" class="btn-danger">🗑️ 批量删除</button>
  </div>
  <div class="toolbar" id="globalFilters"></div>
  <div class="toolbar search-box">
    <span class="label" style="margin:0;">筛选/搜索：</span>
    <select id="searchField" class="input-compact">
      <option value="displayName">用户名</option>
      <option value="userPrincipalName">账号</option>
      <option value="license">订阅</option>
      <option value="_globalLabel">全局</option>
    </select>
    <input id="searchText" class="input-compact" placeholder="输入关键词，支持模糊">
    <button id="btnSearch" class="btn-ghost">搜索</button>
    <button id="btnClear" class="btn-ghost">清空</button>
  </div>
  <div class="pagination" style="margin:4px 0;">
    <span class="label" style="margin:0;">分页:</span>
    <select id="pageSize">
      <option value="20" selected>20/页</option>
      <option value="30">30/页</option>
      <option value="50">50/页</option>
      <option value="100">100/页</option>
    </select>
    <span id="pageInfo"></span>
    <button id="prevPage">上一页</button>
    <button id="nextPage">下一页</button>
    <input class="page-input" id="jumpPage" type="number" min="1" placeholder="页码">
    <button id="goPage">跳转</button>
  </div>
  <div id="status" style="color:#107c10;font-weight:700;margin-bottom:6px;"></div>
  <div class="table-wrap">
    <table class="table" id="userTable">
      <thead>
        <tr>
          <th><input type="checkbox" id="chkAll"></th>
          <th data-sort="displayName">用户名 <span class="arrow" id="arr-displayName">↕</span></th>
          <th data-sort="userPrincipalName">账号 <span class="arrow" id="arr-userPrincipalName">↕</span></th>
          <th data-sort="_licSort">订阅 <span class="arrow" id="arr-_licSort">↕</span></th>
          <th data-sort="createdDateTime">创建时间 <span class="arrow" id="arr-createdDateTime">↕</span></th>
          <th data-sort="_globalLabel">全局 <span class="arrow" id="arr-_globalLabel">↕</span></th>
          <th>UUID</th>
        </tr>
      </thead>
      <tbody id="userBody"></tbody>
    </table>
  </div>
</div>

<div class="modal" id="modalPwd">
  <div class="dialog" style="max-width:420px;">
    <div class="header"><h3 style="margin:0;">重置密码</h3><button class="modal-close" onclick="closeModal('modalPwd')" aria-label="Close">✕</button></div>
    <div>
      <label class="inline"><input type="radio" name="pwdType" value="auto" checked> 自动生成高强度密码</label>
      <label class="inline"><input type="radio" name="pwdType" value="custom"> 自定义密码</label>
      <input type="password" id="customPwd" style="display:none;margin-top:8px;" placeholder="输入新密码" autocomplete="new-password">
    </div>
    <div class="footer">
      <button class="btn-ghost" onclick="closeModal('modalPwd')">取消</button>
      <button id="confirmPwd">确认</button>
    </div>
    <div id="pwdResult" style="font-size:12px;color:#1f2937;margin-top:10px;"></div>
  </div>
</div>

<div class="modal" id="modalLic">
  <div class="dialog" style="max-width:520px;">
    <div class="header"><h3 style="margin:0;">订阅余量</h3><button class="modal-close" onclick="closeModal('modalLic')" aria-label="Close">✕</button></div>
    <div id="licContent">加载中...</div>
  </div>
</div>

<script>
const adminPath = '${adminPath}';
let globalsCache = [];
let usersCache = [];
let sortKey = 'displayName';
let sortDir = 1; // asc by default
let currentPage = 1;
let pageSize = 20;
let filterGlobal = 'ALL';
let searchField = 'displayName';
let searchText = '';

function closeModal(id){ document.getElementById(id).style.display='none'; }
function openModal(id){ document.getElementById(id).style.display='flex'; }

function updateArrows(){
  document.querySelectorAll('#userTable th[data-sort]').forEach(th=>{
    const key=th.getAttribute('data-sort');
    th.classList.remove('active');
    const arrow = document.getElementById('arr-'+key);
    if(arrow) arrow.innerText='↕';
    if(key===sortKey){
      th.classList.add('active');
      if(arrow) arrow.innerText = sortDir===1 ? '↑' : '↓';
    }
  });
}

function renderGlobalsFilter(){
  const wrap = document.getElementById('globalFilters');
  wrap.innerHTML = '<span class="label" style="margin:0;">按全局筛选：</span>';
  const allPill = document.createElement('div');
  allPill.className='pill active'; allPill.innerText='全部';
  allPill.onclick=()=>{ filterGlobal='ALL'; document.querySelectorAll('.pill').forEach(p=>p.classList.remove('active')); allPill.classList.add('active'); renderUserRows(); };
  wrap.appendChild(allPill);
  globalsCache.forEach(g=>{
    const pill=document.createElement('div'); pill.className='pill'; pill.innerText=g.label;
    pill.onclick=()=>{ filterGlobal=g.id; document.querySelectorAll('.pill').forEach(p=>p.classList.remove('active')); pill.classList.add('active'); renderUserRows(); };
    wrap.appendChild(pill);
  });
}

function applyFilterSort(list){
  let data = [...list];
  if(filterGlobal!=='ALL') data = data.filter(u=>u._globalId===filterGlobal);
  if(searchText){
    const txt = searchText.toLowerCase();
    data = data.filter(u=>{
      if(searchField==='displayName') return (u.displayName||'').toLowerCase().includes(txt);
      if(searchField==='userPrincipalName') return (u.userPrincipalName||'').toLowerCase().includes(txt);
      if(searchField==='_globalLabel') return (u._globalLabel||'').toLowerCase().includes(txt);
      if(searchField==='license'){
        return (u._licSort||'').toLowerCase().includes(txt);
      }
      return true;
    });
  }
  data.sort((a,b)=>{
    const va = a[sortKey] || '';
    const vb = b[sortKey] || '';
    if(typeof va === 'string') return sortDir * va.localeCompare(vb, 'zh-CN');
    return sortDir * ((va>vb)-(va<vb));
  });
  return data;
}

function renderUserRows(){
  updateArrows();
  const body=document.getElementById('userBody');
  const data = applyFilterSort(usersCache);
  const total = data.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  currentPage = Math.min(currentPage, totalPages);
  const start = (currentPage-1)*pageSize;
  const pageData = data.slice(start, start+pageSize);

  if(!pageData.length){ body.innerHTML='<tr><td colspan="7" style="text-align:center;">暂无数据</td></tr>'; }
  else {
    body.innerHTML=pageData.map(u=>{
      const lic = (u.assignedLicenses||[]).map(l=>'<span class="tag">'+(l.name||l.skuId)+'</span>').join('') || '<span style="color:#9ca3af;">无</span>';
      return '<tr>'+
        '<td data-label="选择"><input type="checkbox" class="chk" data-g="'+u._globalId+'" value="'+u.id+'"></td>'+
        '<td data-label="用户名"><strong>'+ (u.displayName||'') +'</strong></td>'+
        '<td data-label="账号">'+u.userPrincipalName+'</td>'+
        '<td data-label="订阅">'+lic+'</td>'+
        '<td data-label="创建时间">'+new Date(u.createdDateTime).toLocaleString()+'</td>'+
        '<td data-label="全局">'+u._globalLabel+'</td>'+
        '<td data-label="UUID" style="font-size:11px;color:#9ca3af;">'+u.id+'</td>'+
      '</tr>';
    }).join('');
  }
  document.getElementById('pageInfo').innerText = '第 '+currentPage+' / '+totalPages+' 页 · 共 '+total+' 条';
}

async function fetchGlobals(){
  const res = await fetch(adminPath + '/api/globals');
  const data = await res.json();
  globalsCache = data;
  renderGlobalsFilter();
}

async function fetchUsers(){
  document.getElementById('status').innerText='正在加载用户...';
  const res = await fetch(adminPath + '/api/users');
  const data = await res.json();
  usersCache = data;
  renderUserRows();
  document.getElementById('status').innerText='加载完成';
  setTimeout(()=>document.getElementById('status').innerText='', 2000);
}

document.getElementById('btnRefresh').onclick=fetchUsers;
document.getElementById('btnPwd').onclick=()=>{
  if(getSelected().length===0) return alert('请选择用户');
  document.querySelector('input[name="pwdType"][value="auto"]').checked = true;
  document.getElementById('customPwd').value = '';
  document.getElementById('customPwd').style.display = 'none';
  document.getElementById('pwdResult').innerText = '';
  openModal('modalPwd');
};
document.getElementById('btnLic').onclick=async()=>{
  openModal('modalLic');
  document.getElementById('licContent').innerText='查询中...';
  const res = await fetch(adminPath + '/api/licenses');
  const data = await res.json();
  document.getElementById('licContent').innerHTML = data.map(i=>{
    const remain=i.total-i.used;
    const pct=i.total?Math.round(i.used/i.total*100):0;
    const exp = i.expiresAt ? new Date(i.expiresAt).toLocaleString() : '-';
    return '<div style="margin:8px 0;">'
      + '<strong>'+i.globalLabel+' / '+i.skuPartNumber+'</strong>'
      + '<div style="color:#6b7280;font-size:12px;margin-top:4px;line-height:1.6;">总量 '+i.total+'，已用 '+i.used+'，剩余 '+remain+'，使用率 '+pct+'%</div>'
      + '<div style="color:#6b7280;font-size:12px;margin-top:2px;line-height:1.6;">订阅到期时间：'+exp+'</div>'
      + '<div style="margin-top:6px;height:6px;background:#e5e7eb;border-radius:8px;overflow:hidden;">'
      + '<div style="width:'+pct+'%;height:100%;background:var(--primary);"></div>'
      + '</div>'
      + '</div>';
  }).join('') || '暂无数据';
};
document.getElementById('btnDel').onclick=async()=>{
  const sel=getSelected(); if(!sel.length) return alert('请选择用户');
  if(!confirm('确认删除选中的 '+sel.length+' 个用户？不可恢复')) return;
  document.getElementById('status').innerText='删除中...';
  for (const item of sel){
    await fetch(adminPath + '/api/users/'+item.g+'/'+item.id,{method:'DELETE'});
  }
  fetchUsers();
};

function getSelected(){
  return Array.from(document.querySelectorAll('.chk:checked')).map(c=>({id:c.value,g:c.getAttribute('data-g')}));
}
document.getElementById('chkAll').onchange=(e)=>{
  document.querySelectorAll('.chk').forEach(c=>c.checked=e.target.checked);
};

document.querySelectorAll('input[name="pwdType"]').forEach(r=>{
  r.onchange=()=>{ document.getElementById('customPwd').style.display = r.value==='custom' ? 'block' : 'none'; };
});
document.getElementById('confirmPwd').onclick=async()=>{
  const sel=getSelected(); if(!sel.length) return alert('请选择用户');
  const btn = document.getElementById('confirmPwd');
  const resultEl = document.getElementById('pwdResult');
  const type=document.querySelector('input[name="pwdType"]:checked').value;
  let pwd='';
  if(type==='custom'){ pwd=document.getElementById('customPwd').value; if(!pwd) return alert('请输入密码'); }
  const successList=[];
  const failedList=[];
  btn.disabled = true;
  btn.innerText = '处理中...';
  resultEl.innerText = '正在重置密码...';
  try{
    for(const s of sel){
      const finalPwd = type==='auto' ? generatePass() : pwd;
      try{
        const selectedUser = usersCache.find(u=>u.id===s.id && u._globalId===s.g);
        const res = await fetch(adminPath + '/api/users/'+s.g+'/'+s.id+'/password',{
          method:'PATCH',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({password:finalPwd})
        });
        const data = await res.json().catch(()=>({}));
        const fallbackLabel = (selectedUser && (selectedUser.userPrincipalName || selectedUser.displayName)) || s.id;
        const label = data.userPrincipalName || data.displayName || fallbackLabel;
        if(!res.ok || !data.success){
          failedList.push(label+' => 失败：'+(data.message || data.error || ('HTTP '+res.status)));
          continue;
        }
        successList.push(label+' => '+finalPwd);
      }catch(e){
        failedList.push(s.id+' => 失败：'+(e.message || '请求失败'));
      }
    }
    const lines = ['处理完成：成功 '+successList.length+' 个，失败 '+failedList.length+' 个'];
    if(successList.length){
      lines.push('', '成功：', successList.join('\\n'));
    }
    if(failedList.length){
      lines.push('', '失败：', failedList.join('\\n'));
    }
    resultEl.innerText = lines.join('\\n');
    if(successList.length) fetchUsers();
  }finally{
    btn.disabled = false;
    btn.innerText = '确认';
  }
};
function generatePass(){
  const chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  let p=""; for(let i=0;i<12;i++) p+=chars[Math.floor(Math.random()*chars.length)];
  return p+"Aa1!";
}

// sorting
document.querySelectorAll('#userTable th[data-sort]').forEach(th=>{
  th.onclick=()=>{
    const key=th.getAttribute('data-sort');
    if(sortKey===key) sortDir*=-1; else {sortKey=key; sortDir=1;}
    renderUserRows();
  };
});
updateArrows();

// pagination controls
document.getElementById('pageSize').onchange=(e)=>{ pageSize=parseInt(e.target.value)||20; currentPage=1; renderUserRows(); };
document.getElementById('prevPage').onclick=()=>{ if(currentPage>1){ currentPage--; renderUserRows(); } };
document.getElementById('nextPage').onclick=()=>{
  const data=applyFilterSort(usersCache);
  const totalPages=Math.max(1,Math.ceil(data.length/pageSize));
  if(currentPage<totalPages){ currentPage++; renderUserRows(); }
};
document.getElementById('goPage').onclick=()=>{ const val=parseInt(document.getElementById('jumpPage').value)||1; const data=applyFilterSort(usersCache); const totalPages=Math.max(1,Math.ceil(data.length/pageSize)); currentPage=Math.min(Math.max(1,val),totalPages); renderUserRows(); };

// search
document.getElementById('btnSearch').onclick=()=>{
  searchField=document.getElementById('searchField').value;
  searchText=document.getElementById('searchText').value.trim();
  currentPage=1;
  renderUserRows();
};
document.getElementById('btnClear').onclick=()=>{
  document.getElementById('searchText').value='';
  searchText='';
  currentPage=1;
  renderUserRows();
};

(async()=>{ await fetchGlobals(); await fetchUsers(); })();
</script>
    `,
  });
}

function renderGlobalsPage(adminPath) {
  return adminLayout({
    title: '全局账户',
    adminPath,
    active: 'globals',
    content: `
<div class="section">
  <div class="toolbar">
    <button id="btnAdd">➕ 新增全局</button>
    <div class="search-box">
      <span class="label" style="margin:0;">搜索：</span>
      <input id="gSearch" class="input-compact" placeholder="名称/域/租户">
      <button id="gSearchBtn" class="btn-ghost">搜索</button>
      <button id="gClearBtn" class="btn-ghost">清空</button>
    </div>
  </div>
  <div class="table-wrap">
    <table class="table" id="gTable">
      <thead><tr>
        <th data-sort="label">名称 <span class="arrow" id="garr-label">↕</span></th>
        <th data-sort="defaultDomain">域 <span class="arrow" id="garr-defaultDomain">↕</span></th>
        <th data-sort="tenantId">租户 <span class="arrow" id="garr-tenantId">↕</span></th>
        <th data-sort="skuCount">SKU 数 <span class="arrow" id="garr-skuCount">↕</span></th>
        <th>操作</th>
      </tr></thead>
      <tbody id="gBody"></tbody>
    </table>
  </div>
</div>

<div class="modal" id="modalG">
  <div class="dialog" style="max-width:720px;">
    <div class="header"><h3 id="gTitle" style="margin:0;">新增全局</h3><button class="modal-close" onclick="closeModal('modalG')" aria-label="Close">✕</button></div>
    <div class="row"><span class="label">展示名称（用户可见）</span><input id="gLabel"></div>
    <div class="row"><span class="label">默认邮箱后缀 (不含 @)</span><input id="gDomain"></div>
    <div class="row"><span class="label">租户 ID</span><input id="gTenant"></div>
    <div class="row"><span class="label">客户端 ID</span><input id="gClientId"></div>
    <div class="row"><span class="label">客户端密钥</span><input id="gSecret"></div>
    <div class="row"><span class="label">SKU JSON (键为展示名, 值为 SKU ID)</span><textarea id="gSku" rows="4" placeholder='例如 {"E5开发版":"xxx","A1教育":"yyy"}'></textarea>
    <div class="toolbar" style="margin-top:6px;">
      <button id="btnFetchSku" class="btn-ghost" disabled>点我获取SKU</button>
      <span style="color:#6b7280;font-size:12px;line-height:1.4;">填入租户ID/客户端ID/客户端密钥后即可获取</span>
    </div>
    <div class="footer">
      <button class="btn-ghost" onclick="closeModal('modalG')">取消</button>
      <button id="btnSaveG">保存</button>
    </div>
  </div>
</div>

<script>
const adminPath='${adminPath}';
let editingId=null;
let gSortKey='label', gSortDir=1;
let gSearchText='';
let globalsData=[];

function closeModal(id){ document.getElementById(id).style.display='none'; }
function openModal(id){ document.getElementById(id).style.display='flex'; }

function updateGArrows(){
  ['label','defaultDomain','tenantId','skuCount'].forEach(k=>{
    const th=document.querySelector('#gTable th[data-sort="'+k+'"]');
    const arr=document.getElementById('garr-'+k);
    if(th){ th.classList.remove('active'); if(arr) arr.innerText='↕'; }
    if(k===gSortKey){ if(th) th.classList.add('active'); if(arr) arr.innerText=gSortDir===1?'↑':'↓'; }
  });
}

function renderGlobals(){
  updateGArrows();
  let list=[...globalsData];
  if(gSearchText){
    const t=gSearchText.toLowerCase();
    list=list.filter(x=>(x.label||'').toLowerCase().includes(t)||(x.defaultDomain||'').toLowerCase().includes(t)||(x.tenantId||'').toLowerCase().includes(t));
  }
  list.sort((a,b)=>{
    const va=a[gSortKey]||''; const vb=b[gSortKey]||'';
    if(typeof va==='string') return gSortDir*va.localeCompare(vb);
    return gSortDir*((va>vb)-(va<vb));
  });
  const body=document.getElementById('gBody');
  body.innerHTML=list.map(g=>{
    return '<tr>'+
      '<td data-label="名称"><strong>'+g.label+'</strong></td>'+
      '<td data-label="域">'+g.defaultDomain+'</td>'+
      '<td data-label="租户ID">'+g.tenantId+'</td>'+
      '<td data-label="SKU数">'+g.skuCount+'</td>'+
      '<td data-label="操作"><button class="btn" onclick="editG(\\\''+g.id+'\\\')">编辑</button> <button class="btn-danger" onclick="delG(\\\''+g.id+'\\\')">删除</button></td>'+
    '</tr>';
  }).join('') || '<tr><td colspan="5" style="text-align:center;">暂无全局</td></tr>';
}

async function loadGlobals(){
  const res = await fetch(adminPath+'/api/globals');
  const data = await res.json();
  globalsData = data.map(g=>({...g, skuCount:Object.keys(g.skuMap||{}).length}));
  renderGlobals();
}

document.getElementById('btnAdd').onclick=()=>{editingId=null; document.getElementById('gTitle').innerText='新增全局'; openModal('modalG');};

window.editG=async(id)=>{
  const res=await fetch(adminPath+'/api/globals/'+id);
  const g=await res.json();
  editingId=id;
  document.getElementById('gTitle').innerText='编辑全局';
  document.getElementById('gLabel').value=g.label||'';
  document.getElementById('gDomain').value=g.defaultDomain||'';
  document.getElementById('gTenant').value=g.tenantId||'';
  document.getElementById('gClientId').value=g.clientId||'';
  document.getElementById('gSecret').value=g.clientSecret||'';
  document.getElementById('gSku').value=JSON.stringify(g.skuMap||{}, null, 2);
  openModal('modalG');
};

window.delG=async(id)=>{
  if(!confirm('删除该全局？')) return;
  await fetch(adminPath+'/api/globals/'+id,{method:'DELETE'});
  loadGlobals();
};

document.getElementById('btnSaveG').onclick=async()=>{
  const payload={
    label:document.getElementById('gLabel').value.trim(),
    defaultDomain:document.getElementById('gDomain').value.trim(),
    tenantId:document.getElementById('gTenant').value.trim(),
    clientId:document.getElementById('gClientId').value.trim(),
    clientSecret:document.getElementById('gSecret').value.trim(),
    skuMap:document.getElementById('gSku').value
  };
  const method = editingId ? 'PATCH' : 'POST';
  const url = adminPath+'/api/globals'+(editingId?'/'+editingId:'');
  const res = await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const d = await res.json();
  if(d.success){ closeModal('modalG'); loadGlobals(); }
  else alert(d.message||'保存失败');
};

function canFetchSku(){
  const t=(document.getElementById('gTenant').value||'').trim();
  const c=(document.getElementById('gClientId').value||'').trim();
  const s=(document.getElementById('gSecret').value||'').trim();
  return !!(t && c && s);
}
function refreshFetchBtn(){
  const btn=document.getElementById('btnFetchSku');
  btn.disabled = !canFetchSku();
}
['gTenant','gClientId','gSecret'].forEach(id=>{
  const el=document.getElementById(id);
  if(el) el.addEventListener('input', refreshFetchBtn);
});
refreshFetchBtn();

document.getElementById('btnFetchSku').onclick=async()=>{
  if(!canFetchSku()){ alert('请先填写租户ID、客户端ID、客户端密钥'); return; }
  const payload={
    tenantId:(document.getElementById('gTenant').value||'').trim(),
    clientId:(document.getElementById('gClientId').value||'').trim(),
    clientSecret:(document.getElementById('gSecret').value||'').trim()
  };
  const res=await fetch(adminPath+'/api/fetch_skus',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await res.json();
  if(data.success){ document.getElementById('gSku').value=JSON.stringify(data.map||{},null,2); }
  else alert(data.message||'获取失败');
};

document.querySelectorAll('#gTable th[data-sort]').forEach(th=>{
  th.onclick=()=>{
    const k=th.getAttribute('data-sort');
    if(gSortKey===k) gSortDir*=-1; else {gSortKey=k; gSortDir=1;}
    renderGlobals();
  };
});
document.getElementById('gSearchBtn').onclick=()=>{ gSearchText=document.getElementById('gSearch').value.trim(); renderGlobals(); };
document.getElementById('gClearBtn').onclick=()=>{ document.getElementById('gSearch').value=''; gSearchText=''; renderGlobals(); };

loadGlobals();
</script>
    `,
  });
}

function renderEnterpriseAppsPage(adminPath) {
  return adminLayout({
    title: '企业应用',
    adminPath,
    active: 'apps',
    content: `
<div class="section">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start;">
    <div>
      <h3 style="margin:0 0 8px;">管理员同意请求</h3>
      <div style="color:#6b7280;font-size:13px;line-height:1.7;max-width:860px;">
        支持查看 <strong>开启中</strong> 和 <strong>已通过</strong> 两类企业应用请求。功能依赖 Microsoft Graph 应用权限 <code>ConsentRequest.ReadWrite.All</code>，
        并且对应全局应用必须已经完成管理员同意。
      </div>
    </div>
    <div class="toolbar" style="margin:0;">
      <button id="btnRefreshConsent">🔄 刷新</button>
    </div>
  </div>
</div>

<div class="section">
  <style>
    .consent-groups{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;}
    .consent-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;}
    .consent-requester{margin-bottom:10px;}
    .consent-requester:last-child{margin-bottom:0;}
    .consent-chip-list{display:flex;flex-wrap:wrap;gap:6px;}
    .consent-actions{display:flex;gap:8px;flex-wrap:wrap;}
    .consent-actions button{min-width:96px;}
    .consent-error{padding:12px 14px;border-radius:12px;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;margin-bottom:12px;}
    .consent-subtle{color:#6b7280;font-size:12px;line-height:1.6;}
    @media (max-width: 720px){
      .consent-actions{width:100%;}
      .consent-actions button{width:100%;}
    }
  </style>

  <div id="consentGroupFilters" class="consent-groups"></div>
  <div id="consentGlobalFilters" class="consent-filters"></div>

  <div class="toolbar" style="justify-content:space-between;align-items:center;">
    <div class="search-box">
      <input class="input-compact" id="consentSearch" placeholder="搜索应用、App ID、请求人、权限">
      <button id="btnConsentSearch">搜索</button>
      <button id="btnConsentClear" class="btn-ghost">清空</button>
    </div>
    <div id="consentSummary" class="consent-subtle"></div>
  </div>

  <div id="consentErrors"></div>

  <div class="table-wrap">
    <table class="table" id="consentTable">
      <thead>
        <tr>
          <th>全局</th>
          <th>应用</th>
          <th>待审批权限</th>
          <th>请求人</th>
          <th>申请理由</th>
          <th>最近请求</th>
          <th>状态</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody id="consentBody">
        <tr><td colspan="8" style="text-align:center;">正在加载...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div class="modal" id="modalConsentDecision">
  <div class="dialog">
    <div class="header">
      <strong id="consentDecisionTitle">审批请求</strong>
      <button class="modal-close" id="btnConsentDecisionClose" type="button">×</button>
    </div>
    <div id="consentDecisionDesc" style="color:#6b7280;font-size:13px;line-height:1.7;"></div>
    <div class="row" style="margin-top:12px;">
      <span class="label">审批备注</span>
      <textarea id="consentDecisionJustification" rows="4" placeholder="批准可留空，拒绝建议填写原因"></textarea>
    </div>
    <div class="footer">
      <button type="button" class="btn-ghost" id="btnConsentDecisionCancel">取消</button>
      <button type="button" id="btnConsentDecisionConfirm">确认</button>
    </div>
  </div>
</div>

<script>
const adminPath='${adminPath}';
let consentRequestsCache=[];
let consentErrorsCache=[];
let consentGroup='open';
let consentFilterGlobal='ALL';
let consentSearchText='';
let consentDecisionContext=null;

function esc(v){
  return (v ?? '')
    .toString()
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
function openModal(id){ document.getElementById(id).style.display='flex'; }
function closeModal(id){ document.getElementById(id).style.display='none'; }
function formatDate(v){ return v ? new Date(v).toLocaleString() : '-'; }

function renderConsentErrors(){
  const wrap = document.getElementById('consentErrors');
  if(!consentErrorsCache.length){ wrap.innerHTML=''; return; }
  wrap.innerHTML = consentErrorsCache.map(item=>{
    return '<div class="consent-error"><strong>'+esc(item.globalLabel || '未命名全局')+'</strong>：'+esc(item.message || '读取失败')+'</div>';
  }).join('');
}

function renderConsentGlobalFilters(){
  const wrap = document.getElementById('consentGlobalFilters');
  const globalMap = new Map();
  consentRequestsCache
    .filter(item => item.requestGroup === consentGroup)
    .forEach(item=>{
    if(item.globalId) globalMap.set(item.globalId, item.globalLabel || '未命名全局');
  });
  if(!globalMap.size){ wrap.innerHTML=''; return; }
  const items = [{id:'ALL',label:'全部'}].concat(Array.from(globalMap.entries()).map(([id,label])=>({id,label})));
  wrap.innerHTML = items.map(item=>{
    const active = consentFilterGlobal === item.id ? ' active' : '';
    return '<button type="button" class="pill'+active+'" data-global="'+esc(item.id)+'">'+esc(item.label)+'</button>';
  }).join('');
  wrap.querySelectorAll('.pill').forEach(btn=>{
    btn.onclick=()=>{
      consentFilterGlobal = btn.getAttribute('data-global') || 'ALL';
      renderConsentRequests();
    };
  });
}

function renderConsentGroupFilters(){
  const wrap = document.getElementById('consentGroupFilters');
  const counts = { open: 0, approved: 0 };
  consentRequestsCache.forEach(item=>{
    if(item.requestGroup === 'approved') counts.approved++;
    else if(item.requestGroup === 'open') counts.open++;
  });
  const items = [
    { id:'open', label:'开启的请求', count: counts.open },
    { id:'approved', label:'已通过的请求', count: counts.approved },
  ];
  wrap.innerHTML = items.map(item=>{
    const active = consentGroup === item.id ? ' active' : '';
    return '<button type="button" class="pill'+active+'" data-group="'+esc(item.id)+'">'+esc(item.label)+'（'+esc(String(item.count))+'）</button>';
  }).join('');
  wrap.querySelectorAll('.pill').forEach(btn=>{
    btn.onclick=()=>{
      consentGroup = btn.getAttribute('data-group') || 'open';
      consentFilterGlobal = 'ALL';
      renderConsentRequests();
    };
  });
}

function getFilteredConsentRequests(){
  let list = consentRequestsCache.filter(item => item.requestGroup === consentGroup);
  if(consentFilterGlobal !== 'ALL'){
    list = list.filter(item => item.globalId === consentFilterGlobal);
  }
  if(consentSearchText){
    const txt = consentSearchText.toLowerCase();
    list = list.filter(item=>{
      const requestors = (item.requestors || []).map(x => [x.displayName, x.userPrincipalName].filter(Boolean).join(' ')).join(' ');
      const reasons = (item.reasons || []).join(' ');
      const scopes = (item.pendingScopes || []).join(' ');
      const haystack = [
        item.globalLabel,
        item.appDisplayName,
        item.appId,
        requestors,
        reasons,
        scopes,
      ].join(' ').toLowerCase();
      return haystack.includes(txt);
    });
  }
  return list.sort((a,b)=>{
    const ta = new Date(a.latestCreatedDateTime || 0).getTime();
    const tb = new Date(b.latestCreatedDateTime || 0).getTime();
    return tb - ta;
  });
}

function openConsentDecision(decision, globalId, appConsentRequestId){
  const item = consentRequestsCache.find(x => x.globalId === globalId && x.appConsentRequestId === appConsentRequestId && x.requestGroup === 'open');
  if(!item) return;
  consentDecisionContext = { decision, globalId, appConsentRequestId, appDisplayName: item.appDisplayName || '未命名应用', requestCount: item.requestCount || 0 };
  const isDeny = decision === 'Deny';
  document.getElementById('consentDecisionTitle').innerText = isDeny ? '拒绝企业应用请求' : '批准企业应用请求';
  document.getElementById('consentDecisionDesc').innerHTML =
    '将对 <strong>'+esc(item.appDisplayName || '未命名应用')+'</strong> 的 <strong>'+esc(String(item.requestCount || 0))+'</strong> 条开启中请求执行'+(isDeny ? '拒绝' : '批准')+'。'
    + (isDeny ? '<br>建议填写拒绝原因，便于后续审计。' : '<br>批准时备注可留空。');
  document.getElementById('consentDecisionJustification').value = '';
  document.getElementById('btnConsentDecisionConfirm').innerText = isDeny ? '确认拒绝' : '确认批准';
  openModal('modalConsentDecision');
}

function renderConsentRequests(){
  renderConsentGroupFilters();
  renderConsentGlobalFilters();
  renderConsentErrors();
  const list = getFilteredConsentRequests();
  const summaryLabel = consentGroup === 'approved' ? '已通过的请求' : '开启的请求';
  document.getElementById('consentSummary').innerText = '当前筛选 ' + list.length + ' 条' + summaryLabel;
  const body = document.getElementById('consentBody');
  body.innerHTML = list.map(item=>{
    const isApproved = item.requestGroup === 'approved';
    const scopes = (item.pendingScopes || []).length
      ? '<div class="consent-chip-list">'+(item.pendingScopes || []).map(x => '<span class="tag">'+esc(x)+'</span>').join('')+'</div>'
      : '<span style="color:#9ca3af;">未返回权限</span>';
    const requestors = (item.requestors || []).length
      ? (item.requestors || []).map(x=>{
          const name = x.displayName || x.userPrincipalName || '未知用户';
          const upn = x.userPrincipalName && x.userPrincipalName !== name ? '<div class="consent-subtle">'+esc(x.userPrincipalName)+'</div>' : '';
          return '<div class="consent-requester"><strong>'+esc(name)+'</strong>'+upn+'</div>';
        }).join('')
      : '<span style="color:#9ca3af;">未知</span>';
    const reasons = (item.reasons || []).length
      ? '<div class="consent-chip-list">'+(item.reasons || []).map(x => '<span class="tag">'+esc(x)+'</span>').join('')+'</div>'
      : '<span style="color:#9ca3af;">未填写</span>';
    const app = '<strong>'+esc(item.appDisplayName || '未命名应用')+'</strong>'
      + '<div class="consent-subtle">App ID: '+esc(item.appId || '-')+'</div>'
      + '<div class="consent-subtle">请求 ID: '+esc(item.appConsentRequestId || '-')+'</div>';
    const status = isApproved
      ? '<span class="tag" style="background:#dcfce7;color:#166534;">已通过 '+esc(String(item.requestCount || 0))+' 条</span>'
        + '<div class="consent-subtle">最近通过：'+esc(formatDate(item.latestReviewedDateTime || item.sortDateTime))+'</div>'
        + ((item.reviewNotes || []).length ? '<div class="consent-chip-list" style="margin-top:6px;">'+(item.reviewNotes || []).map(x => '<span class="tag" style="background:#ecfccb;color:#3f6212;">'+esc(x)+'</span>').join('')+'</div>' : '')
      : '<span class="tag" style="background:#fef3c7;color:#92400e;">待审批 '+esc(String(item.requestCount || 0))+' 条</span>';
    const actions = isApproved
      ? '<span class="consent-subtle">已完成</span>'
      : '<div class="consent-actions">'
        + '<button type="button" class="btn-approve" data-global="'+esc(item.globalId)+'" data-id="'+esc(item.appConsentRequestId)+'">批准全部</button>'
        + '<button type="button" class="btn-danger btn-deny" data-global="'+esc(item.globalId)+'" data-id="'+esc(item.appConsentRequestId)+'">拒绝全部</button>'
        + '</div>';
    return '<tr>'
      + '<td data-label="全局">'+esc(item.globalLabel || '-')+'</td>'
      + '<td data-label="应用">'+app+'</td>'
      + '<td data-label="待审批权限">'+scopes+'</td>'
      + '<td data-label="请求人">'+requestors+'</td>'
      + '<td data-label="申请理由">'+reasons+'</td>'
      + '<td data-label="最近时间">'+esc(formatDate(item.sortDateTime || item.latestCreatedDateTime))+'</td>'
      + '<td data-label="状态">'+status+'</td>'
      + '<td data-label="操作">'+actions+'</td>'
      + '</tr>';
  }).join('') || '<tr><td colspan="8" style="text-align:center;">'+(consentGroup === 'approved' ? '暂无已通过的企业应用请求' : '暂无开启中的企业应用请求')+'</td></tr>';

  document.querySelectorAll('.btn-approve').forEach(btn=>{
    btn.onclick=()=>openConsentDecision('Approve', btn.getAttribute('data-global'), btn.getAttribute('data-id'));
  });
  document.querySelectorAll('.btn-deny').forEach(btn=>{
    btn.onclick=()=>openConsentDecision('Deny', btn.getAttribute('data-global'), btn.getAttribute('data-id'));
  });
}

async function loadConsentRequests(){
  const btn = document.getElementById('btnRefreshConsent');
  btn.disabled = true;
  btn.innerText = '正在刷新...';
  try{
    const res = await fetch(adminPath + '/api/consent-requests');
    const data = await res.json().catch(()=>({}));
    consentRequestsCache = Array.isArray(data.items) ? data.items : [];
    consentErrorsCache = Array.isArray(data.errors) ? data.errors : [];
    if(!res.ok && !consentErrorsCache.length){
      consentErrorsCache = [{globalLabel:'系统', message:data.message || '加载失败'}];
    }
    renderConsentRequests();
  }catch(err){
    consentRequestsCache = [];
    consentErrorsCache = [{globalLabel:'系统', message:'网络异常，请稍后重试'}];
    renderConsentRequests();
  }finally{
    btn.disabled = false;
    btn.innerText = '🔄 刷新';
  }
}

document.getElementById('btnRefreshConsent').onclick=loadConsentRequests;
document.getElementById('btnConsentSearch').onclick=()=>{
  consentSearchText = (document.getElementById('consentSearch').value || '').trim();
  renderConsentRequests();
};
document.getElementById('btnConsentClear').onclick=()=>{
  document.getElementById('consentSearch').value = '';
  consentSearchText = '';
  renderConsentRequests();
};
document.getElementById('consentSearch').addEventListener('keydown',(e)=>{
  if(e.key === 'Enter'){
    e.preventDefault();
    document.getElementById('btnConsentSearch').click();
  }
});

document.getElementById('btnConsentDecisionClose').onclick=()=>closeModal('modalConsentDecision');
document.getElementById('btnConsentDecisionCancel').onclick=()=>closeModal('modalConsentDecision');
document.getElementById('modalConsentDecision').addEventListener('click',(e)=>{
  if(e.target.id === 'modalConsentDecision') closeModal('modalConsentDecision');
});

document.getElementById('btnConsentDecisionConfirm').onclick=async()=>{
  if(!consentDecisionContext) return;
  const decision = consentDecisionContext.decision;
  const justification = (document.getElementById('consentDecisionJustification').value || '').trim();
  if(decision === 'Deny' && !justification){
    alert('拒绝时请填写原因');
    return;
  }
  const btn = document.getElementById('btnConsentDecisionConfirm');
  btn.disabled = true;
  btn.innerText = decision === 'Deny' ? '正在拒绝...' : '正在批准...';
  try{
    const res = await fetch(adminPath + '/api/consent-requests/decision',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        globalId: consentDecisionContext.globalId,
        appConsentRequestId: consentDecisionContext.appConsentRequestId,
        decision,
        justification
      })
    });
    const data = await res.json().catch(()=>({}));
    if(data.success){
      alert(data.message || '审批成功');
      closeModal('modalConsentDecision');
      loadConsentRequests();
    }else{
      alert(data.message || '审批失败');
    }
  }catch(err){
    alert('网络异常，请稍后重试');
  }finally{
    btn.disabled = false;
    btn.innerText = decision === 'Deny' ? '确认拒绝' : '确认批准';
  }
};

loadConsentRequests();
</script>
    `,
  });
}

function renderInvitesPage(adminPath, globals) {
  return adminLayout({
    title: '邀请码管理',
    adminPath,
    active: 'invites',
    content: `
<style>
.invite-tools,.invite-select-tools{align-items:center;}
.invite-select-tools .chip{font-weight:700;display:inline-flex;align-items:center;justify-content:center;min-height:40px;}
.invite-mobile-bar{display:none;}
.invite-code{font-size:13px;word-break:break-all;}
@media (max-width: 720px){
  .invite-tools button,
  .invite-select-tools button,
  .pagination button{
    flex:1 1 calc(50% - 8px);
    min-height:44px;
  }
  .invite-select-tools .chip{
    width:100%;
    min-height:44px;
  }
  .invite-mobile-bar{
    position:sticky;
    bottom:12px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
    margin-top:14px;
    padding:12px;
    border-radius:16px;
    background:rgba(17,24,39,0.94);
    box-shadow:0 16px 40px rgba(0,0,0,0.24);
    z-index:20;
  }
  .invite-mobile-bar .meta{
    color:#fff;
    font-size:13px;
    font-weight:800;
    white-space:nowrap;
  }
  .invite-mobile-bar .actions{
    display:flex;
    gap:8px;
    flex:1;
    justify-content:flex-end;
  }
  .invite-mobile-bar .actions button{
    min-height:44px;
    box-shadow:none;
  }
}
</style>
<div class="section">
  <div class="toolbar invite-tools">
    <button id="btnGen">🎲 生成邀请码</button>
    <button id="btnDelInvites" class="btn-danger">🗑️ 删除所选</button>
    <button id="btnExport">⬇️ 导出所选</button>
    <button id="btnRefreshInvites">🔄 刷新</button>
  </div>
  <div class="toolbar invite-select-tools">
    <button id="btnSelectPage" class="btn-ghost">全选当前页</button>
    <button id="btnSelectFiltered" class="btn-ghost">全选筛选结果</button>
    <button id="btnClearInviteSelection" class="btn-ghost">清空选择</button>
    <span id="inviteSelectionInfo" class="chip">未选择邀请码</span>
  </div>
  <div class="toolbar search-box">
    <span class="label" style="margin:0;">筛选/搜索：</span>
    <select id="iSearchField" class="input-compact">
      <option value="code">邀请码</option>
      <option value="status">状态</option>
      <option value="scope">限制范围</option>
    </select>
    <input id="iSearchText" class="input-compact" placeholder="输入关键词，支持模糊">
    <button id="iSearchBtn" class="btn-ghost">搜索</button>
    <button id="iClearBtn" class="btn-ghost">清空</button>
  </div>
  <div class="toolbar" style="gap:6px;">
    <span class="label" style="margin:0;">排序:</span>
    <select id="sortKey" style="max-width:180px;">
      <option value="code" selected>邀请码首字母</option>
      <option value="createdAt">生成时间</option>
      <option value="usedAt">使用时间</option>
      <option value="status">使用状态</option>
      <option value="scope">限制范围</option>
    </select>
  </div>
  <div class="pagination" style="margin:4px 0%;">
    <span class="label" style="margin:0;">分页:</span>
    <select id="pageSizeInvite">
      <option value="20" selected>20/页</option>
      <option value="30">30/页</option>
      <option value="50">50/页</option>
      <option value="100">100/页</option>
    </select>
    <span id="pageInfoInvite"></span>
    <button id="prevInvite">上一页</button>
    <button id="nextInvite">下一页</button>
    <input class="page-input" id="jumpInvite" type="number" min="1" placeholder="页码">
    <button id="goInvite">跳转</button>
  </div>
  <div class="table-wrap">
    <table class="table" id="inviteTable">
      <thead><tr>
        <th><input type="checkbox" id="chkInvitePage" title="全选当前页"></th>
        <th data-sort="code">邀请码 <span class="arrow" id="iarr-code">↕</span></th>
        <th data-sort="limit">限制次数 <span class="arrow" id="iarr-limit">↕</span></th>
        <th data-sort="used">已用 <span class="arrow" id="iarr-used">↕</span></th>
        <th data-sort="status">状态 <span class="arrow" id="iarr-status">↕</span></th>
        <th data-sort="scope">限制范围 <span class="arrow" id="iarr-scope">↕</span></th>
        <th data-sort="createdAt">生成时间 <span class="arrow" id="iarr-createdAt">↕</span></th>
        <th data-sort="usedAt">最近使用 <span class="arrow" id="iarr-usedAt">↕</span></th>
      </tr></thead>
      <tbody id="inviteBody"></tbody>
    </table>
  </div>
  <div class="invite-mobile-bar" id="inviteMobileBar">
    <div class="meta" id="inviteMobileCount">未选择</div>
    <div class="actions">
      <button id="btnMobileExport" class="btn-ghost">导出</button>
      <button id="btnMobileDelete" class="btn-danger">删除</button>
    </div>
  </div>
</div>

<div class="modal" id="modalGen">
  <div class="dialog" style="max-width:620px;">
    <div class="header"><h3 style="margin:0;">生成邀请码</h3><button class="modal-close" onclick="closeModal('modalGen')" aria-label="Close">✕</button></div>
    <div class="row"><span class="label">选择字符集 (至少选一项)</span>
      <label class="inline"><input type="checkbox" id="cUpper" checked> 大写</label>
      <label class="inline"><input type="checkbox" id="cLower" checked> 小写</label>
      <label class="inline"><input type="checkbox" id="cDigit" checked> 数字</label>
      <label class="inline"><input type="checkbox" id="cSym" checked> 特殊符号</label>
    </div>
    <div class="row"><span class="label">邀请码长度</span><input id="cLen" type="number" value="16" min="4"></div>
    <div class="row"><span class="label">生成数量</span><input id="cQty" type="number" value="10" min="1"></div>
    <div class="row"><span class="label">每个邀请码可使用次数</span><input id="cLimit" type="number" value="1" min="1"></div>
    <div class="row">
      <span class="label">限制可注册的全局+订阅 (至少选一项)</span>
      <div id="scopeWrap" style="max-height:200px;overflow:auto;border:1px solid #e5e7eb;border-radius:12px;padding:10px;background:#fafafa;"></div>
    </div>
    <div class="footer">
      <button class="btn-ghost" onclick="closeModal('modalGen')">取消生成</button>
      <button id="doGen">确定生成</button>
    </div>
  </div>
</div>

<script>
const adminPath='${adminPath}';
const globalsList = ${JSON.stringify(globals)};
function closeModal(id){ document.getElementById(id).style.display='none'; }
function openModal(id){ document.getElementById(id).style.display='flex'; }

let invitesCache=[];
let sortKey='code';
let sortDir=1; // default asc
let invitePage=1;
let invitePageSize=20;
let iSearchField='code';
let iSearchText='';
const selectedInviteCodes = new Set();

function updateIArrows(){
  ['code','limit','used','status','scope','createdAt','usedAt'].forEach(k=>{
    const th=document.querySelector('th[data-sort="'+k+'"]');
    const arr=document.getElementById('iarr-'+k);
    if(th){ th.classList.remove('active'); if(arr) arr.innerText='↕'; }
    if(k===sortKey){ if(th) th.classList.add('active'); if(arr) arr.innerText=sortDir===1?'↑':'↓'; }
  });
}

function buildScopeOptions(){
  const wrap=document.getElementById('scopeWrap');
  wrap.innerHTML = globalsList.map(g=>{
    const sku = Object.keys(g.skuMap||{});
    if(!sku.length) return '';
    return '<div style="margin-bottom:8px;"><strong>'+g.label+'</strong><br>'+sku.map(s=>{
      return '<label class="inline" style="margin-left:8px;"><input type="checkbox" class="scopeChk" data-g="'+g.id+'" data-sku="'+s+'"> '+g.label+' / '+s+'</label>';
    }).join('')+'</div>';
  }).join('') || '<div style="color:#9ca3af;">暂无全局/订阅</div>';
}

function normalizeInviteSelection(){
  const existing = new Set(invitesCache.map(item => item.code));
  Array.from(selectedInviteCodes).forEach(code => {
    if(!existing.has(code)) selectedInviteCodes.delete(code);
  });
}

function getFilteredInvites(){
  let list=[...invitesCache];
  if(iSearchText){
    const t=iSearchText.toLowerCase();
    list=list.filter(c=>{
      if(iSearchField==='code') return (c.code||'').toLowerCase().includes(t);
      if(iSearchField==='status'){
        const st = c.used>=c.limit ? '已用完' : '可用';
        return st.toLowerCase().includes(t);
      }
      if(iSearchField==='scope'){
        const scopeText = (c.allowed||[]).map(s=>{
          const g=globalsList.find(x=>x.id===s.globalId);
          return (g?g.label:'')+' '+s.skuName;
        }).join(' ');
        return scopeText.toLowerCase().includes(t);
      }
      return true;
    });
  }
  list.sort((a,b)=>{
    if(sortKey==='status'){
      return sortDir * (((a.used>=a.limit)?1:0) - ((b.used>=b.limit)?1:0));
    }
    if(sortKey==='scope'){
      const sa=(a.allowed||[]).map(s=>s.globalId+s.skuName).join(',');
      const sb=(b.allowed||[]).map(s=>s.globalId+s.skuName).join(',');
      return sortDir * sa.localeCompare(sb);
    }
    const va=a[sortKey]||0;
    const vb=b[sortKey]||0;
    if(typeof va==='string') return sortDir*va.localeCompare(vb);
    return sortDir*((va>vb)-(va<vb));
  });
  return list;
}

function getCurrentPageData(list){
  const totalPages=Math.max(1,Math.ceil(list.length/invitePageSize));
  invitePage=Math.min(invitePage,totalPages);
  const start=(invitePage-1)*invitePageSize;
  return {
    totalPages,
    start,
    pageData:list.slice(start,start+invitePageSize),
  };
}

function getSelectedInviteCodes(){
  normalizeInviteSelection();
  return Array.from(selectedInviteCodes);
}

function setBulkActionDisabled(disabled){
  ['btnDelInvites','btnExport','btnMobileDelete','btnMobileExport'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.disabled = disabled;
  });
}

function updateInviteSelectionState(filteredList, pageData){
  normalizeInviteSelection();
  const selectedCount = selectedInviteCodes.size;
  const visibleSelected = pageData.filter(item => selectedInviteCodes.has(item.code)).length;
  const selectionInfo = document.getElementById('inviteSelectionInfo');
  const mobileCount = document.getElementById('inviteMobileCount');
  const pageToggle = document.getElementById('chkInvitePage');

  selectionInfo.innerText = selectedCount
    ? '已选 ' + selectedCount + ' 条 · 当前筛选 ' + filteredList.length + ' 条'
    : '未选择邀请码';
  mobileCount.innerText = selectedCount ? '已选 ' + selectedCount + ' 条' : '未选择';

  pageToggle.checked = !!pageData.length && visibleSelected === pageData.length;
  pageToggle.indeterminate = visibleSelected > 0 && visibleSelected < pageData.length;
  setBulkActionDisabled(selectedCount === 0);
}

document.getElementById('btnGen').onclick=()=>{buildScopeOptions(); openModal('modalGen');};
document.getElementById('btnRefreshInvites').onclick=loadInvites;
document.getElementById('btnSelectPage').onclick=()=>{
  const filtered = getFilteredInvites();
  const { pageData } = getCurrentPageData(filtered);
  pageData.forEach(item => selectedInviteCodes.add(item.code));
  renderInvites();
};
document.getElementById('btnSelectFiltered').onclick=()=>{
  getFilteredInvites().forEach(item => selectedInviteCodes.add(item.code));
  renderInvites();
};
document.getElementById('btnClearInviteSelection').onclick=()=>{
  selectedInviteCodes.clear();
  renderInvites();
};
document.getElementById('chkInvitePage').onchange=(e)=>{
  const filtered = getFilteredInvites();
  const { pageData } = getCurrentPageData(filtered);
  pageData.forEach(item => {
    if(e.target.checked) selectedInviteCodes.add(item.code);
    else selectedInviteCodes.delete(item.code);
  });
  renderInvites();
};

document.getElementById('doGen').onclick=async()=>{
  const chars=[];
  if(document.getElementById('cUpper').checked) chars.push('upper');
  if(document.getElementById('cLower').checked) chars.push('lower');
  if(document.getElementById('cDigit').checked) chars.push('digit');
  if(document.getElementById('cSym').checked) chars.push('sym');
  if(!chars.length) return alert('至少选择一个字符集');
  const scopes = Array.from(document.querySelectorAll('.scopeChk:checked')).map(c=>({globalId:c.getAttribute('data-g'), skuName:c.getAttribute('data-sku')}));
  if(!scopes.length) return alert('至少选择一个可用范围');
  const payload={
    sets:chars,
    length:parseInt(document.getElementById('cLen').value)||16,
    quantity:parseInt(document.getElementById('cQty').value)||1,
    limit:parseInt(document.getElementById('cLimit').value)||1,
    scopes
  };
  const res=await fetch(adminPath+'/api/invites/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await res.json();
  if(data.success){ alert('生成完成，新增 '+data.count+' 条'); closeModal('modalGen'); loadInvites(); }
  else alert(data.message||'生成失败');
};

async function deleteSelectedInvites(){
  const sel = getSelectedInviteCodes();
  if(!sel.length) return alert('请选择邀请码');
  if(!confirm('确认删除选中邀请码？')) return;
  await fetch(adminPath+'/api/invites/bulk',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({codes:sel})});
  selectedInviteCodes.clear();
  loadInvites();
}

function exportSelectedInvites(){
  const sel = getSelectedInviteCodes();
  if(!sel.length) return alert('请选择邀请码');
  const blob = new Blob([sel.join('\\n')], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='invites.txt'; a.click();
  URL.revokeObjectURL(url);
}

document.getElementById('btnDelInvites').onclick=deleteSelectedInvites;
document.getElementById('btnExport').onclick=exportSelectedInvites;
document.getElementById('btnMobileDelete').onclick=deleteSelectedInvites;
document.getElementById('btnMobileExport').onclick=exportSelectedInvites;

document.getElementById('sortKey').onchange=()=>{ sortKey=document.getElementById('sortKey').value; renderInvites(); };
document.querySelectorAll('th[data-sort]').forEach(th=>{
  th.onclick=()=>{ const k=th.getAttribute('data-sort'); if(k===sortKey) sortDir*=-1; else {sortKey=k; sortDir=1;} renderInvites(); };
});

document.getElementById('pageSizeInvite').onchange=(e)=>{ invitePageSize=parseInt(e.target.value)||20; invitePage=1; renderInvites(); };
document.getElementById('prevInvite').onclick=()=>{ if(invitePage>1){ invitePage--; renderInvites(); } };
document.getElementById('nextInvite').onclick=()=>{
  const total=Math.max(1,Math.ceil(getFilteredInvites().length/invitePageSize));
  if(invitePage<total){ invitePage++; renderInvites(); }
};
document.getElementById('goInvite').onclick=()=>{
  const val=parseInt(document.getElementById('jumpInvite').value)||1;
  const total=Math.max(1,Math.ceil(getFilteredInvites().length/invitePageSize));
  invitePage=Math.min(Math.max(1,val), total);
  renderInvites();
};

document.getElementById('iSearchBtn').onclick=()=>{ iSearchField=document.getElementById('iSearchField').value; iSearchText=document.getElementById('iSearchText').value.trim(); invitePage=1; renderInvites(); };
document.getElementById('iClearBtn').onclick=()=>{ document.getElementById('iSearchText').value=''; iSearchText=''; invitePage=1; renderInvites(); };
document.getElementById('iSearchText').addEventListener('keydown',(e)=>{ if(e.key==='Enter'){ e.preventDefault(); document.getElementById('iSearchBtn').click(); } });
document.getElementById('jumpInvite').addEventListener('keydown',(e)=>{ if(e.key==='Enter'){ e.preventDefault(); document.getElementById('goInvite').click(); } });

function renderInvites(){
  updateIArrows();
  normalizeInviteSelection();
  const list = getFilteredInvites();
  const total=list.length;
  const { totalPages, pageData } = getCurrentPageData(list);
  const body=document.getElementById('inviteBody');
  body.innerHTML = pageData.map(c=>{
    const status = c.used >= c.limit ? '<span class="tag" style="background:#fee2e2;color:#991b1b;">已用完</span>' : '<span class="tag" style="background:#dcfce7;color:#166534;">可用</span>';
    const scope = (c.allowed||[]).map(s=>{
      const g = globalsList.find(x=>x.id===s.globalId);
      return '<span class="tag">'+(g?g.label:'?')+' / '+s.skuName+'</span>';
    }).join('') || '<span style="color:#9ca3af;">未设置</span>';
    return '<tr>'+
      '<td data-label="选择"><input type="checkbox" class="inviteChk" value="'+c.code+'" '+(selectedInviteCodes.has(c.code)?'checked':'')+'></td>'+
      '<td data-label="邀请码"><code class="invite-code">'+c.code+'</code></td>'+
      '<td data-label="限制次数">'+c.limit+'</td>'+
      '<td data-label="已用">'+c.used+'</td>'+
      '<td data-label="状态">'+status+'</td>'+
      '<td data-label="限制范围">'+scope+'</td>'+
      '<td data-label="生成时间">'+new Date(c.createdAt).toLocaleString()+'</td>'+
      '<td data-label="最近使用">'+ (c.usedAt?new Date(c.usedAt).toLocaleString():'-') +'</td>'+
    '</tr>';
  }).join('') || '<tr><td colspan="8" style="text-align:center;">暂无邀请码</td></tr>';
  document.getElementById('pageInfoInvite').innerText='第 '+invitePage+' / '+totalPages+' 页 · 共 '+total+' 条';
  document.querySelectorAll('.inviteChk').forEach(chk=>{
    chk.onchange=()=>{
      if(chk.checked) selectedInviteCodes.add(chk.value);
      else selectedInviteCodes.delete(chk.value);
      updateInviteSelectionState(list, pageData);
    };
  });
  updateInviteSelectionState(list, pageData);
}

async function loadInvites(){
  const res = await fetch(adminPath+'/api/invites?sort='+sortKey);
  const data = await res.json();
  invitesCache = data;
  normalizeInviteSelection();
  renderInvites();
}

loadInvites();
</script>
    `,
  });
}

function renderSettingsPage(adminPath, cfg) {
  const protectedPrefixes = (cfg.protectedPrefixes || []).join(',');
  return adminLayout({
    title: '设置',
    adminPath,
    active: 'settings',
    content: `
<div class="section">
  <h3 style="margin-top:0;">后台账号</h3>
  <div class="row"><span class="label">后台用户名</span><input id="sAdminUser" value="${cfg.adminUsername || 'admin'}" placeholder="例如：admin"></div>
  <div class="row"><span class="label">后台新密码</span><input id="sAdminPwd" type="password" placeholder="留空不修改（至少 8 位）"></div>
  <div style="color:#6b7280;font-size:12px;line-height:1.6;margin-top:6px;">
    说明：修改用户名/密码后，当前会话不受影响，下次登录按新账号登录。
  </div>
</div>

<div class="section">
  <h3 style="margin-top:0;">基础设置</h3>
  <div class="row"><span class="label">后台路径</span><input id="sPath" value="${cfg.adminPath}" placeholder="/admin"></div>
  <div class="row"><span class="label">Turnstile Site Key (留空关闭)</span><input id="sSite" value="${cfg.turnstile.siteKey||''}"></div>
  <div class="row"><span class="label">Turnstile Secret Key (留空关闭)</span><input id="sSecret" value="${cfg.turnstile.secretKey||''}"></div>
  <div class="row"><label class="inline"><input type="checkbox" id="sInvite" ${cfg.invite?.enabled?'checked':''}> 启用邀请码注册</label></div>
</div>

<div class="section">
  <h3 style="margin-top:0;">额外保护账户（禁止注册）</h3>
  <div class="row">
    <span class="label">额外保护账户（英文逗号,分隔）</span>
    <textarea id="sProtectPrefixes" rows="3" placeholder="例如：admin,superadmin,root">${protectedPrefixes}</textarea>
  </div>
  <div style="color:#6b7280;font-size:12px;line-height:1.6;">
    说明：<br/>
    1) 此处仅匹配邮箱的 <strong>@ 前缀（local-part）</strong>，例如 <code>admin@abc.onmicrosoft.com</code> 只需配置 <code>admin</code>。<br/>
    2) 命中的用户名将 <strong>禁止在前台注册</strong>，并且若账号已存在，将 <strong>禁止通过面板或 API 删除</strong>（防误删/防篡改）。<br/>
    3) 默认已内置常见敏感用户名（如 admin/root 等），建议不要清空。
  </div>

  <div class="toolbar" style="margin-top:14px;">
    <button id="btnSaveSetting">💾 保存</button>
  </div>
</div>

<script>
const adminPath='${adminPath}';
function parseCommaList(v){
  return (v||'')
    .split(',')
    .map(s=>s.trim())
    .filter(Boolean);
}
document.getElementById('btnSaveSetting').onclick=async()=>{
  const adminUsername = (document.getElementById('sAdminUser').value || '').trim();
  const adminPassword = document.getElementById('sAdminPwd').value || '';
  const payload={
    adminPath: (document.getElementById('sPath').value || '/admin').trim(),
    adminUsername,
    adminPassword: adminPassword ? adminPassword : undefined,
    turnstile: { siteKey: (document.getElementById('sSite').value||'').trim(), secretKey: (document.getElementById('sSecret').value||'').trim() },
    protectedPrefixes: parseCommaList(document.getElementById('sProtectPrefixes').value),
    inviteEnabled: document.getElementById('sInvite').checked
  };
  const res=await fetch(adminPath+'/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await res.json();
  if(data.success){
    alert('保存成功');
    if(data.newPath && data.newPath !== adminPath){ location.href = data.newPath + '/settings'; }
  } else alert(data.message||'保存失败');
};
</script>
    `,
  });
}

/* -------------------- Core Logic -------------------- */
async function getAccessTokenForGlobal(global, fetcher) {
  const params = new URLSearchParams();
  params.append('client_id', global.clientId);
  params.append('scope', 'https://graph.microsoft.com/.default');
  params.append('client_secret', global.clientSecret);
  params.append('grant_type', 'client_credentials');
  const res = await fetcher(`https://login.microsoftonline.com/${global.tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    body: params,
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('获取令牌失败');
  return data.access_token;
}

async function fetchSubscribedSkus(global, fetcher) {
  const token = await getAccessTokenForGlobal(global, fetcher);
  const resp = await fetcher('https://graph.microsoft.com/v1.0/subscribedSkus', {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err?.error?.message || '获取订阅 SKU 失败');
  }
  const data = await resp.json();
  return Array.isArray(data.value) ? data.value : [];
}

async function graphRequestJson(url, token, fetcher, options = {}) {
  const headers = { Authorization: `Bearer ${token}`, ...(options.headers || {}) };
  const resp = await fetcher(url, { ...options, headers });
  const text = await resp.text().catch(() => '');
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  if (!resp.ok) {
    const message = data?.error?.message || data?.raw || `Graph 请求失败（${resp.status}）`;
    const err = new Error(message);
    err.status = resp.status;
    err.details = text.slice(0, 500);
    throw err;
  }
  return data;
}

async function graphRequestCollection(url, token, fetcher, optionsOrMaxPages = {}, maxPages = 10) {
  const options =
    typeof optionsOrMaxPages === 'number'
      ? {}
      : (optionsOrMaxPages || {});
  const pageLimit =
    typeof optionsOrMaxPages === 'number'
      ? optionsOrMaxPages
      : maxPages;
  let nextUrl = url;
  let pages = 0;
  const items = [];
  while (nextUrl && pages < pageLimit) {
    const data = await graphRequestJson(nextUrl, token, fetcher, options);
    if (Array.isArray(data.value)) items.push(...data.value);
    nextUrl = data['@odata.nextLink'] || '';
    pages++;
  }
  return items;
}

function parseMetricNumber(value) {
  const raw = (value ?? '').toString().replace(/,/g, '').trim();
  if (!raw) return null;
  const num = Number(raw);
  return Number.isFinite(num) ? num : null;
}

function parseCsvLine(line) {
  const values = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === ',' && !inQuotes) {
      values.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  values.push(current);
  return values;
}

function parseCsvTable(text) {
  const normalized = (text || '').replace(/^\uFEFF/, '').trim();
  if (!normalized) return [];
  const lines = normalized.split(/\r?\n/).filter((line) => line.trim() !== '');
  if (lines.length < 2) return [];
  const headers = parseCsvLine(lines.shift());
  return lines.map((line) => {
    const cols = parseCsvLine(line);
    const row = {};
    headers.forEach((header, idx) => {
      row[header] = cols[idx] ?? '';
    });
    return row;
  });
}

function getLatestReportRows(rows) {
  const candidates = (rows || [])
    .map((row) => {
      const reportDate = (row['Report Date'] || '').toString().trim();
      return { row, reportDate, ts: Date.parse(reportDate) };
    })
    .filter((item) => item.reportDate && Number.isFinite(item.ts));
  if (!candidates.length) return [];
  let latest = candidates[0];
  for (const item of candidates) {
    if (item.ts > latest.ts) latest = item;
  }
  return candidates.filter((item) => item.reportDate === latest.reportDate).map((item) => item.row);
}

function getReportRefreshDate(rows) {
  const latestRows = getLatestReportRows(rows);
  return latestRows[0]?.['Report Refresh Date'] || '';
}

function getSingleValueSnapshot(rows, fieldName) {
  const latestRows = getLatestReportRows(rows);
  if (!latestRows.length) return { value: null, reportDate: '', refreshDate: '' };
  const row = latestRows[0];
  return {
    value: parseMetricNumber(row[fieldName]),
    reportDate: row['Report Date'] || '',
    refreshDate: row['Report Refresh Date'] || '',
  };
}

function getSummedValueSnapshot(rows, fieldName) {
  const latestRows = getLatestReportRows(rows);
  if (!latestRows.length) return { value: null, reportDate: '', refreshDate: '' };
  const values = latestRows
    .map((row) => parseMetricNumber(row[fieldName]))
    .filter((value) => value !== null);
  if (!values.length) {
    return {
      value: null,
      reportDate: latestRows[0]?.['Report Date'] || '',
      refreshDate: latestRows[0]?.['Report Refresh Date'] || '',
    };
  }
  return {
    value: values.reduce((sum, value) => sum + value, 0),
    reportDate: latestRows[0]?.['Report Date'] || '',
    refreshDate: latestRows[0]?.['Report Refresh Date'] || '',
  };
}

function buildDashboardMetricError(error, fallback = '读取报表失败') {
  if (!error) return fallback;
  if (error.status === 403) {
    return `${fallback}：缺少 Reports.Read.All 或尚未完成管理员同意`;
  }
  if (error.status === 404) {
    return `${fallback}：当前租户或云环境不支持该报表`;
  }
  return error.message || fallback;
}

function buildPasswordResetErrorMessage(error, fallback = '重置密码失败') {
  if (!error) return fallback;
  const raw = (error.message || '').toString();
  const lower = raw.toLowerCase();
  if (error.status === 403 || lower.includes('insufficient privileges')) {
    return `${fallback}：当前全局缺少重置密码所需权限。请为应用授予并完成管理员同意 User-PasswordProfile.ReadWrite.All，并为企业应用分配 User Administrator；若目标账号是管理员，通常还需要 Privileged Authentication Administrator 或更高权限。`;
  }
  if (error.status === 404) {
    return `${fallback}：未找到目标用户，或当前全局无权访问该用户。`;
  }
  if (error.status === 400 && lower.includes('password')) {
    return `${fallback}：Graph 拒绝了新密码，请检查密码复杂度、历史密码限制或租户密码策略。`;
  }
  return raw || fallback;
}

async function fetchGraphReportCsv(path, token, fetcher) {
  const resp = await fetcher(`https://graph.microsoft.com/v1.0${path}`, {
    headers: { Authorization: `Bearer ${token}` },
    redirect: 'manual',
  });

  if (resp.status === 302) {
    const location = resp.headers.get('Location') || resp.headers.get('location');
    if (!location) {
      const err = new Error('报表下载地址缺失');
      err.status = 502;
      throw err;
    }
    const downloadResp = await fetcher(location);
    if (!downloadResp.ok) {
      const text = await downloadResp.text().catch(() => '');
      const err = new Error(text || `报表下载失败（${downloadResp.status}）`);
      err.status = downloadResp.status;
      err.details = text.slice(0, 500);
      throw err;
    }
    return await downloadResp.text();
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    let message = `报表请求失败（${resp.status}）`;
    if (text) {
      try {
        const data = JSON.parse(text);
        message = data?.error?.message || text;
      } catch {
        message = text;
      }
    }
    const err = new Error(message);
    err.status = resp.status;
    err.details = text.slice(0, 500);
    throw err;
  }

  return await resp.text();
}

async function getDashboardMetricsForGlobal(global, fetcher) {
  const token = await getAccessTokenForGlobal(global, fetcher);
  const result = {
    globalId: global.id,
    label: global.label || '未命名全局',
    activeUsers: null,
    activeUsersReportDate: '',
    activeUsersError: '',
    sharePointBytes: null,
    oneDriveBytes: null,
    totalStorageBytes: null,
    storageReportDate: '',
    storageError: '',
    reportRefreshDate: '',
  };

  const [activeReport, sharePointReport, oneDriveReport] = await Promise.allSettled([
    fetchGraphReportCsv('/reports/getOffice365ActiveUserCounts(period=\'D7\')', token, fetcher),
    fetchGraphReportCsv('/reports/getSharePointSiteUsageStorage(period=\'D7\')', token, fetcher),
    fetchGraphReportCsv('/reports/getOneDriveUsageStorage(period=\'D7\')', token, fetcher),
  ]);

  if (activeReport.status === 'fulfilled') {
    const snapshot = getSingleValueSnapshot(parseCsvTable(activeReport.value), 'Office 365');
    result.activeUsers = snapshot.value;
    result.activeUsersReportDate = snapshot.reportDate;
    result.reportRefreshDate = snapshot.refreshDate || result.reportRefreshDate;
  } else {
    result.activeUsersError = buildDashboardMetricError(activeReport.reason, '活跃用户报表不可用');
  }

  const storageErrors = [];
  if (sharePointReport.status === 'fulfilled') {
    const snapshot = getSummedValueSnapshot(parseCsvTable(sharePointReport.value), 'Storage Used (Byte)');
    result.sharePointBytes = snapshot.value;
    result.storageReportDate = snapshot.reportDate || result.storageReportDate;
    result.reportRefreshDate = snapshot.refreshDate || result.reportRefreshDate;
  } else {
    storageErrors.push(buildDashboardMetricError(sharePointReport.reason, 'SharePoint 存储报表不可用'));
  }

  if (oneDriveReport.status === 'fulfilled') {
    const snapshot = getSummedValueSnapshot(parseCsvTable(oneDriveReport.value), 'Storage Used (Byte)');
    result.oneDriveBytes = snapshot.value;
    result.storageReportDate = snapshot.reportDate || result.storageReportDate;
    result.reportRefreshDate = snapshot.refreshDate || result.reportRefreshDate;
  } else {
    storageErrors.push(buildDashboardMetricError(oneDriveReport.reason, 'OneDrive 存储报表不可用'));
  }

  if (result.sharePointBytes !== null || result.oneDriveBytes !== null) {
    result.totalStorageBytes = (result.sharePointBytes || 0) + (result.oneDriveBytes || 0);
  } else if (storageErrors.length) {
    result.storageError = storageErrors.join('；');
  }

  return result;
}

function normalizeConsentDecision(decision) {
  const value = (decision || '').toString().trim().toLowerCase();
  if (value === 'approve' || value === 'approved') return 'Approve';
  if (value === 'deny' || value === 'denied' || value === 'reject') return 'Deny';
  return '';
}

function buildConsentErrorMessage(error, fallback = '操作失败') {
  if (!error) return fallback;
  if (error.status === 403) {
    return `${fallback}：当前全局可能缺少 ConsentRequest.ReadWrite.All 权限，或该权限尚未完成管理员同意`;
  }
  if (error.status === 404) {
    return `${fallback}：请求不存在，或已被其他管理员处理`;
  }
  if (error.status === 409) {
    return `${fallback}：请求状态已变化，请刷新后重试`;
  }
  return error.message || fallback;
}

function formatPendingScope(scope) {
  const parts = [
    scope?.resourceAppDisplayName,
    scope?.displayName,
    scope?.value,
  ].filter(Boolean);
  return parts.join(' / ') || scope?.id || '';
}

function collectConsentRequestPeople(userRequests) {
  const requestorSet = new Set();
  const reasonSet = new Set();
  const requestors = [];
  const reasons = [];
  let latestCreatedDateTime = '';

  userRequests.forEach((request) => {
    const user = request?.createdBy?.user || {};
    const key = [user.id, user.userPrincipalName, user.displayName].filter(Boolean).join('|');
    if (key && !requestorSet.has(key)) {
      requestorSet.add(key);
      requestors.push({
        id: user.id || '',
        displayName: user.displayName || '',
        userPrincipalName: user.userPrincipalName || '',
      });
    }

    const reason = (request?.reason || '').toString().trim();
    if (reason && !reasonSet.has(reason)) {
      reasonSet.add(reason);
      reasons.push(reason);
    }

    const created = request?.createdDateTime || '';
    if (created && (!latestCreatedDateTime || new Date(created) > new Date(latestCreatedDateTime))) {
      latestCreatedDateTime = created;
    }
  });

  return { requestors, reasons, latestCreatedDateTime };
}

function extractApprovedStageInfo(userRequests) {
  const noteSet = new Set();
  const reviewNotes = [];
  let latestReviewedDateTime = '';

  userRequests.forEach((request) => {
    const stages = Array.isArray(request?.approval?.stages) ? request.approval.stages : [];
    stages.forEach((stage) => {
      if (normalizeLower(stage?.reviewResult) !== 'approve') return;
      const note = (stage?.justification || '').toString().trim();
      if (note && !noteSet.has(note)) {
        noteSet.add(note);
        reviewNotes.push(note);
      }
      const reviewed = stage?.reviewedDateTime || '';
      if (reviewed && (!latestReviewedDateTime || new Date(reviewed) > new Date(latestReviewedDateTime))) {
        latestReviewedDateTime = reviewed;
      }
    });
  });

  return { reviewNotes, latestReviewedDateTime };
}

function buildConsentRequestGroupItem(base, requestGroup, userRequests) {
  if (!userRequests.length) return null;
  const { requestors, reasons, latestCreatedDateTime } = collectConsentRequestPeople(userRequests);
  const { reviewNotes, latestReviewedDateTime } = requestGroup === 'approved'
    ? extractApprovedStageInfo(userRequests)
    : { reviewNotes: [], latestReviewedDateTime: '' };

  return {
    ...base,
    requestGroup,
    requestors,
    reasons,
    reviewNotes,
    latestCreatedDateTime,
    latestReviewedDateTime,
    requestCount: userRequests.length,
    sortDateTime: latestReviewedDateTime || latestCreatedDateTime || '',
  };
}

async function listConsentRequestsForGlobal(global, fetcher) {
  const token = await getAccessTokenForGlobal(global, fetcher);
  const baseUrl = `https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests?$top=100`;
  const appRequests = await graphRequestCollection(baseUrl, token, fetcher);

  const items = await Promise.all(
    appRequests.map(async (item) => {
      const userUrl = `https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/${item.id}/userConsentRequests?$top=100`;
      const userRequests = await graphRequestCollection(userUrl, token, fetcher);
      if (!userRequests.length) return null;

      const scopeSet = new Set();
      const pendingScopes = (item.pendingScopes || [])
        .map((scope) => formatPendingScope(scope))
        .filter((scope) => {
          if (!scope || scopeSet.has(scope)) return false;
          scopeSet.add(scope);
          return true;
        });

      const base = {
        globalId: global.id,
        globalLabel: global.label,
        appConsentRequestId: item.id,
        appId: item.appId || '',
        appDisplayName: item.appDisplayName || '',
        pendingScopes,
      };

      const openRequests = userRequests.filter((request) => normalizeLower(request?.status) === 'inprogress');
      const approvedRequests = userRequests.filter((request) => {
        if (normalizeLower(request?.status) !== 'completed') return false;
        const stages = Array.isArray(request?.approval?.stages) ? request.approval.stages : [];
        return stages.some((stage) => normalizeLower(stage?.reviewResult) === 'approve');
      });

      return [
        buildConsentRequestGroupItem(base, 'open', openRequests),
        buildConsentRequestGroupItem(base, 'approved', approvedRequests),
      ].filter(Boolean);
    }),
  );

  return items.flat().filter(Boolean);
}

async function applyConsentDecisionForGlobal(global, appConsentRequestId, decision, justification, fetcher) {
  const normalizedDecision = normalizeConsentDecision(decision);
  if (!normalizedDecision) throw new Error('无效的审批动作');

  const token = await getAccessTokenForGlobal(global, fetcher);
  const userFilter = encodeURIComponent("status eq 'InProgress'");
  const userUrl = `https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/${appConsentRequestId}/userConsentRequests?$filter=${userFilter}&$top=100`;
  const userRequests = await graphRequestCollection(userUrl, token, fetcher);
  if (!userRequests.length) {
    return { processed: 0, skipped: 0, failed: 0 };
  }

  const stageTasks = [];
  let skipped = 0;
  userRequests.forEach((request) => {
    const stages = Array.isArray(request?.approval?.stages) ? request.approval.stages : [];
    const activeStages = stages.filter((stage) => normalizeLower(stage?.status) === 'inprogress');
    if (!activeStages.length) {
      skipped++;
      return;
    }
    activeStages.forEach((stage) => {
      stageTasks.push({
        userConsentRequestId: request.id,
        approvalStageId: stage.id,
      });
    });
  });

  if (!stageTasks.length) {
    return { processed: 0, skipped, failed: 0 };
  }

  const results = await Promise.allSettled(
    stageTasks.map((task) =>
      graphRequestJson(
        `https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/${appConsentRequestId}/userConsentRequests/${task.userConsentRequestId}/approval/stages/${task.approvalStageId}`,
        token,
        fetcher,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reviewResult: normalizedDecision,
            justification: (justification || '').toString().trim() || undefined,
          }),
        },
      ),
    ),
  );

  const failed = results.filter((item) => item.status === 'rejected');
  return {
    processed: results.length - failed.length,
    skipped,
    failed: failed.length,
    message: failed[0]?.reason ? buildConsentErrorMessage(failed[0].reason, '审批失败') : '',
  };
}

function remainingFromSubscribedSku(sku) {
  const enabled = Number(sku?.prepaidUnits?.enabled ?? 0);
  const consumed = Number(sku?.consumedUnits ?? 0);
  const remaining = enabled - consumed;
  return Number.isFinite(remaining) ? Math.max(0, remaining) : 0;
}
function getEnvHiddenList(env) {
  if (!env.HIDDEN_USER) return [];
  return env.HIDDEN_USER.split(/[;,]/).map(s => s.trim()).filter(Boolean);
}

function normalizeLower(v) {
  return (v || '').toString().trim().toLowerCase();
}

function getLocalPartFromUpn(upn) {
  const v = normalizeLower(upn);
  const at = v.indexOf('@');
  return at >= 0 ? v.slice(0, at) : v;
}

function buildProtectionSets(env, cfg) {
  const emailSet = new Set();
  (cfg.protectedUsers || []).forEach(u => {
    const x = normalizeLower(u);
    if (x) emailSet.add(x);
  });
  getEnvHiddenList(env).forEach(u => {
    const x = normalizeLower(u);
    if (x) emailSet.add(x);
  });

  const prefixSet = new Set();
  (cfg.protectedPrefixes || []).forEach(p => {
    const x = normalizeLower(p);
    if (x) prefixSet.add(x);
  });

  return { emailSet, prefixSet };
}

function isProtectedUpn(upn, env, cfg) {
  const { emailSet, prefixSet } = buildProtectionSets(env, cfg);
  const v = normalizeLower(upn);
  if (!v) return false;
  if (emailSet.has(v)) return true;
  const local = getLocalPartFromUpn(v);
  if (prefixSet.has(local)) return true;
  return false;
}
function filterProtectedUsers(list, env, cfg) {
  const { emailSet, prefixSet } = buildProtectionSets(env, cfg);
  return list.filter(u => {
    const upn = normalizeLower(u.userPrincipalName || '');
    if (emailSet.has(upn)) return false;
    const local = getLocalPartFromUpn(upn);
    if (prefixSet.has(local)) return false;
    return true;
  });
}

function validateInviteUsage(invites, inviteCode, globalId, skuName) {
  const idx = invites.findIndex((item) => item.code === inviteCode);
  if (idx === -1) return { ok: false, message: '邀请码无效' };

  const invite = invites[idx];
  const used = Number(invite.used || 0);
  const limit = Number(invite.limit || 0);
  if (used >= limit) return { ok: false, message: '邀请码已用完' };

  const allowed = Array.isArray(invite.allowed) ? invite.allowed : [];
  const matched = allowed.some((item) => item.globalId === globalId && item.skuName === skuName);
  if (!matched) return { ok: false, message: '邀请码不允许当前全局/订阅' };

  return { ok: true, idx, invite };
}

async function consumeInviteAfterSuccess(env, inviteCode, globalId, skuName) {
  const invites = await getInvites(env);
  const result = validateInviteUsage(invites, inviteCode, globalId, skuName);
  if (!result.ok) return result;

  invites[result.idx] = {
    ...result.invite,
    used: Number(result.invite.used || 0) + 1,
    usedAt: Date.now(),
  };
  await saveInvites(env, invites);
  return { ok: true };
}

async function rollbackCreatedUser(global, userId, token, fetchImpl = fetch) {
  try {
    const accessToken = token || (await getAccessTokenForGlobal(global, fetchImpl));
    const resp = await fetchImpl(`https://graph.microsoft.com/v1.0/users/${userId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (resp.ok || resp.status === 204 || resp.status === 404) return { ok: true };

    const details = await resp.text().catch(() => '');
    return { ok: false, details: details.slice(0, 300) };
  } catch (error) {
    return { ok: false, details: error?.message || 'rollback_failed' };
  }
}

async function handleRegister(env, req, cfg) {
  const form = await req.formData();
  const username = (form.get('username')||'').trim();
  const password = form.get('password')||'';
  const skuName = form.get('skuName');
  const globalId = form.get('globalId');
  const inviteCode = form.get('inviteCode');
  const turnstileToken = form.get('cf-turnstile-response');
  const clientIp = req.headers.get('CF-Connecting-IP');

  const global = (cfg.globals||[]).find(g=>g.id===globalId);
  if(!global) return jsonResponse({success:false,message:'请选择有效全局'},400);
  const skuMap = global.skuMap||{};
  const skuId = skuMap[skuName];
  if(!skuId) return jsonResponse({success:false,message:'请选择有效订阅'},400);
  if(!/^[a-zA-Z0-9]+$/.test(username)) return jsonResponse({success:false,message:'用户名格式错误'},400);

  // invitation check
  if(cfg.invite?.enabled){
    const inviteCheck = validateInviteUsage(await getInvites(env), inviteCode, globalId, skuName);
    if(!inviteCheck.ok) return jsonResponse({success:false,message:inviteCheck.message},400);
  }

  // turnstile verify
  if(cfg.turnstile?.secretKey && turnstileToken){
    const ver = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({secret:cfg.turnstile.secretKey,response:turnstileToken,remoteip:clientIp})
    });
    const verData = await ver.json();
    if(!verData.success) return jsonResponse({success:false,message:'人机验证失败'},400);
  }

  const userEmail = `${username}@${global.defaultDomain}`;
  if(isProtectedUpn(userEmail, env, cfg)) {
    return jsonResponse({success:false,message:'该用户名被禁止注册！请勿尝试注册非法用户名！'},403);
  }

  if(password.toLowerCase().includes(username.toLowerCase())) return jsonResponse({success:false,message:'密码不能包含用户名'},400);
  if(!checkPasswordComplexity(password)) return jsonResponse({success:false,message:'密码不符合复杂度'},400);

  const token = await getAccessTokenForGlobal(global, fetch);
  // create user
  const createResp = await fetch('https://graph.microsoft.com/v1.0/users',{
    method:'POST',
    headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'},
    body:JSON.stringify({
      accountEnabled:true,
      displayName:username,
      mailNickname:username,
      userPrincipalName:userEmail,
      passwordProfile:{forceChangePasswordNextSignIn:false,password},
      usageLocation:"CN"
    })
  });
  if(!createResp.ok){
    const err = await createResp.json().catch(()=>({}));
    return jsonResponse({success:false,message:err.error?.message||'创建失败'},400);
  }
  const newUser = await createResp.json();

  // assign license
  const licResp = await fetch(`https://graph.microsoft.com/v1.0/users/${newUser.id}/assignLicense`,{
    method:'POST',
    headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'},
    body:JSON.stringify({addLicenses:[{disabledPlans:[],skuId}],removeLicenses:[]})
  });
  if(!licResp.ok){
    const err = await licResp.json().catch(()=>({}));
    const rollback = await rollbackCreatedUser(global, newUser.id, token);
    const detail = err.error?.message || '未知错误';
    if(!rollback.ok){
      return jsonResponse({success:false,message:'订阅分配失败，且账号回滚失败，请管理员手动检查：' + detail},400);
    }
    return jsonResponse({success:false,message:'订阅分配失败，已回滚新建账号：' + detail},400);
  }
  if(cfg.invite?.enabled){
    try{
      const consumeResult = await consumeInviteAfterSuccess(env, inviteCode, globalId, skuName);
      if(!consumeResult.ok){
        const rollback = await rollbackCreatedUser(global, newUser.id, token);
        if(!rollback.ok){
          return jsonResponse({success:false,message:'邀请码状态冲突，且账号回滚失败，请管理员手动检查'},409);
        }
        return jsonResponse({success:false,message:(consumeResult.message || '邀请码不可用') + '，已回滚本次注册'},409);
      }
    }catch(error){
      const rollback = await rollbackCreatedUser(global, newUser.id, token);
      if(!rollback.ok){
        return jsonResponse({success:false,message:'邀请码保存失败，且账号回滚失败，请管理员手动检查'},500);
      }
      return jsonResponse({success:false,message:'邀请码保存失败，已回滚本次注册'},500);
    }
  }
  return jsonResponse({success:true,email:userEmail});
}

/* -------------------- Request Handler -------------------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let cfg = await getConfig(env);
    const adminPath = cfg.adminPath || '/admin';
    const installed = !!(await env.CONFIG_KV.get(KV.INSTALL_LOCK));
    const isSetupPath = url.pathname === `${adminPath}/setup`;
    const isLoginPath = url.pathname === `${adminPath}/login`;

    // redirect to setup if not installed
    if(!installed && !isSetupPath) return redirect(`${adminPath}/setup`);

    /* ---------- Setup ---------- */
    if(isSetupPath){
      if(request.method==='GET') return htmlResponse(renderSetup(adminPath));
      if(request.method==='POST'){
        const body = await request.json().catch(()=>({}));
        const username = (body.username || '').toString().trim();
        const password = (body.password || '').toString();

        if(!/^[a-zA-Z0-9_\-]{3,32}$/.test(username)){
          return jsonResponse({success:false,message:'用户名格式不正确（3-32位，仅字母/数字/_/-）'},400);
        }
        if(!password || password.length<8){
          return jsonResponse({success:false,message:'密码至少 8 位'},400);
        }

        const newPath = (body.adminPath || '/admin').toString().trim() || '/admin';
        const hash = await sha256(password);

        cfg = mergeConfig({ ...cfg, adminUsername: username, adminPasswordHash: hash, adminPath: newPath });
        await setConfig(env, cfg);
        await env.CONFIG_KV.put(KV.INSTALL_LOCK,'1');
        return jsonResponse({success:true});
      }
    }

    /* ---------- Login ---------- */
    if(isLoginPath){
      if(request.method==='GET') return htmlResponse(renderLogin(adminPath));
      if(request.method==='POST'){
        const body = await request.json().catch(()=>({}));
        const username = (body.username || '').toString().trim();
        const pwdHash = await sha256((body.password||'').toString());

        const cfgUser = (cfg.adminUsername || 'admin').toString().trim();
        if(username.toLowerCase() !== cfgUser.toLowerCase() || pwdHash !== cfg.adminPasswordHash){
          return jsonResponse({success:false,message:'用户名或密码错误'},401);
        }

        const token = await createSession(env);
        return new Response(JSON.stringify({success:true}),{
          headers:{
            'Content-Type':'application/json',
            'Set-Cookie':`ADMIN_SESSION=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`
          }
        });
      }
    }

    /* ---------- Admin HTML Pages ---------- */
    if(url.pathname === adminPath){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return redirect(`${adminPath}/dashboard`);
    }
    if(url.pathname === `${adminPath}/dashboard`){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return htmlResponse(renderDashboardPage(adminPath));
    }
    if(url.pathname === `${adminPath}/users`){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return htmlResponse(renderUsersPage(adminPath));
    }
    if(url.pathname === `${adminPath}/globals`){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return htmlResponse(renderGlobalsPage(adminPath));
    }
    if(url.pathname === `${adminPath}/enterprise-apps`){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return htmlResponse(renderEnterpriseAppsPage(adminPath));
    }
    if(url.pathname === `${adminPath}/invites`){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return htmlResponse(renderInvitesPage(adminPath, cfg.globals||[]));
    }
    if(url.pathname === `${adminPath}/settings`){
      if(!(await verifySession(env, request))) return redirect(`${adminPath}/login`);
      return htmlResponse(renderSettingsPage(adminPath, cfg));
    }

    /* ---------- Admin APIs (auth required) ---------- */
    if(url.pathname.startsWith(`${adminPath}/api/`)){
      if(!(await verifySession(env, request))) return jsonResponse({error:'unauthorized'},401);

      if(url.pathname === `${adminPath}/api/dashboard` && request.method==='GET'){
        const globals = cfg.globals || [];
        const settled = await Promise.allSettled(globals.map((g) => getDashboardMetricsForGlobal(g, fetch)));
        const items = settled.map((item, index) => {
          if (item.status === 'fulfilled') return item.value;
          const g = globals[index] || {};
          const message = buildDashboardMetricError(item.reason, '读取看板失败');
          return {
            globalId: g.id || '',
            label: g.label || '未命名全局',
            activeUsers: null,
            activeUsersReportDate: '',
            activeUsersError: message,
            sharePointBytes: null,
            oneDriveBytes: null,
            totalStorageBytes: null,
            storageReportDate: '',
            storageError: message,
            reportRefreshDate: '',
          };
        });

        const summary = items.reduce((acc, item) => {
          acc.globalsTotal++;
          if (item.activeUsers !== null) {
            acc.activeUsers += item.activeUsers;
            acc.activeUsersReady++;
          }
          if (item.totalStorageBytes !== null) {
            acc.storageBytes += item.totalStorageBytes;
            acc.storageReady++;
          }
          if (item.sharePointBytes !== null) acc.sharePointBytes += item.sharePointBytes;
          if (item.oneDriveBytes !== null) acc.oneDriveBytes += item.oneDriveBytes;
          return acc;
        }, {
          globalsTotal: 0,
          activeUsers: 0,
          activeUsersReady: 0,
          storageBytes: 0,
          storageReady: 0,
          sharePointBytes: 0,
          oneDriveBytes: 0,
        });

        return jsonResponse({
          success: true,
          period: 'D7',
          summary,
          items,
        });
      }

      // fetch SKU list by credentials (without saving global) - admin only
      if(url.pathname === `${adminPath}/api/fetch_skus` && request.method==='POST'){
        const body = await request.json().catch(()=>({}));
        const tenantId = (body.tenantId||'').trim();
        const clientId = (body.clientId||'').trim();
        const clientSecret = (body.clientSecret||'').trim();
        if(!tenantId || !clientId || !clientSecret) return jsonResponse({success:false,message:'缺少租户/客户端信息'},400);
        try{
          const tmp = { tenantId, clientId, clientSecret };
          const token = await getAccessTokenForGlobal(tmp, fetch);
          const resp = await fetch('https://graph.microsoft.com/v1.0/subscribedSkus',{headers:{Authorization:`Bearer ${token}`}});
          if(!resp.ok){
            const err = await resp.json().catch(()=>({}));
            return jsonResponse({success:false,message:err?.error?.message||'获取失败'},400);
          }
          const data = await resp.json();
          const map = {};
          (data.value||[]).forEach(s=>{ map[s.skuPartNumber] = s.skuId; });
          return jsonResponse({success:true,map});
        }catch(e){
          return jsonResponse({success:false,message:e.message||'获取失败'},400);
        }
      }

      // globals CRUD
      if(url.pathname === `${adminPath}/api/globals` && request.method==='GET'){
        const list = (cfg.globals||[]).map(g=>({...g, clientSecret: undefined}));
        return jsonResponse(list);
      }
      if(url.pathname === `${adminPath}/api/globals` && request.method==='POST'){
        const body = await request.json().catch(()=>({}));
        const id = crypto.randomUUID();
        const item = {
          id,
          label: body.label || '未命名',
          defaultDomain: body.defaultDomain || '',
          tenantId: body.tenantId || '',
          clientId: body.clientId || '',
          clientSecret: body.clientSecret || '',
          skuMap: sanitizeSkuMap(body.skuMap)
        };
        cfg.globals = cfg.globals || [];
        cfg.globals.push(item);
        await setConfig(env, cfg);
        return jsonResponse({success:true,id});
      }
      if(url.pathname.match(`${adminPath}/api/globals/[^/]+$`) && request.method==='GET'){
        const gid = url.pathname.split('/').pop();
        const g = (cfg.globals||[]).find(x=>x.id===gid);
        if(!g) return jsonResponse({error:'not found'},404);
        return jsonResponse(g);
      }
      if(url.pathname.match(`${adminPath}/api/globals/[^/]+$`) && request.method==='PATCH'){
        const gid = url.pathname.split('/').pop();
        const body = await request.json().catch(()=>({}));
        const idx = (cfg.globals||[]).findIndex(x=>x.id===gid);
        if(idx===-1) return jsonResponse({error:'not found'},404);
        cfg.globals[idx] = {
          ...cfg.globals[idx],
          label: body.label || cfg.globals[idx].label,
          defaultDomain: body.defaultDomain || cfg.globals[idx].defaultDomain,
          tenantId: body.tenantId || cfg.globals[idx].tenantId,
          clientId: body.clientId || cfg.globals[idx].clientId,
          clientSecret: body.clientSecret || cfg.globals[idx].clientSecret,
          skuMap: body.skuMap ? sanitizeSkuMap(body.skuMap) : cfg.globals[idx].skuMap
        };
        await setConfig(env, cfg);
        return jsonResponse({success:true});
      }
      if(url.pathname.match(`${adminPath}/api/globals/[^/]+$`) && request.method==='DELETE'){
        const gid = url.pathname.split('/').pop();
        cfg.globals = (cfg.globals||[]).filter(x=>x.id!==gid);
        await setConfig(env, cfg);
        return jsonResponse({success:true});
      }
      if(url.pathname.match(`${adminPath}/api/globals/[^/]+/skus$`) && request.method==='GET'){
        const gid = url.pathname.split('/').slice(-2,-1)[0];
        const g = (cfg.globals||[]).find(x=>x.id===gid);
        if(!g) return jsonResponse({success:false,message:'未找到全局'},404);
        try{
          const token = await getAccessTokenForGlobal(g, fetch);
          const resp = await fetch('https://graph.microsoft.com/v1.0/subscribedSkus',{headers:{Authorization:`Bearer ${token}`}});
          const data = await resp.json();
          const map = {};
          (data.value||[]).forEach(s=>{ map[s.skuPartNumber] = s.skuId; });
          return jsonResponse({success:true,map});
        }catch(e){
          return jsonResponse({success:false,message:e.message},400);
        }
      }

      // admin consent requests for enterprise apps
      if(url.pathname === `${adminPath}/api/consent-requests` && request.method==='GET'){
        const globals = cfg.globals || [];
        const settled = await Promise.allSettled(globals.map(g => listConsentRequestsForGlobal(g, fetch)));
        const items = [];
        const errors = [];
        settled.forEach((result, index) => {
          const g = globals[index];
          if(result.status === 'fulfilled'){
            items.push(...result.value);
          }else{
            errors.push({
              globalId: g?.id || '',
              globalLabel: g?.label || '未命名全局',
              message: buildConsentErrorMessage(result.reason, '读取企业应用请求失败'),
            });
          }
        });
        items.sort((a, b) => new Date(b.sortDateTime || b.latestCreatedDateTime || 0) - new Date(a.sortDateTime || a.latestCreatedDateTime || 0));
        return jsonResponse({success:true,items,errors});
      }
      if(url.pathname === `${adminPath}/api/consent-requests/decision` && request.method==='POST'){
        const body = await request.json().catch(()=>({}));
        const globalId = (body.globalId || '').toString().trim();
        const appConsentRequestId = (body.appConsentRequestId || '').toString().trim();
        const decision = normalizeConsentDecision(body.decision);
        const justification = (body.justification || '').toString().trim();
        if(!globalId || !appConsentRequestId){
          return jsonResponse({success:false,message:'缺少全局或请求标识'},400);
        }
        if(!decision){
          return jsonResponse({success:false,message:'无效的审批动作'},400);
        }
        if(decision === 'Deny' && !justification){
          return jsonResponse({success:false,message:'拒绝时请填写原因'},400);
        }

        const g = (cfg.globals||[]).find(x=>x.id===globalId);
        if(!g) return jsonResponse({success:false,message:'未找到对应全局'},404);

        try{
          const result = await applyConsentDecisionForGlobal(g, appConsentRequestId, decision, justification, fetch);
          if(result.failed){
            return jsonResponse({
              success:false,
              message:`已处理 ${result.processed} 条请求，但仍有 ${result.failed} 条失败。${result.message || '请刷新后重试'}`
            },409);
          }
          if(result.processed === 0){
            return jsonResponse({success:false,message:'没有可处理的待审批请求，可能已被其他管理员处理'},409);
          }
          return jsonResponse({
            success:true,
            message:`已${decision === 'Deny' ? '拒绝' : '批准'} ${result.processed} 条请求${result.skipped ? `，跳过 ${result.skipped} 条非活动审批阶段` : ''}`
          });
        }catch(e){
          return jsonResponse({success:false,message:buildConsentErrorMessage(e, '审批失败')}, e.status || 400);
        }
      }

      // settings
      if(url.pathname === `${adminPath}/api/config` && request.method==='POST'){
        const body = await request.json().catch(()=>({}));

        // admin path
        const newPath = (body.adminPath || adminPath).toString().trim() || adminPath;

        // admin credentials
        if(body.adminUsername !== undefined){
          const u = (body.adminUsername || '').toString().trim();
          if(!/^[a-zA-Z0-9_\-]{3,32}$/.test(u)){
            return jsonResponse({success:false,message:'用户名格式不正确（3-32位，仅字母/数字/_/-）'},400);
          }
          cfg.adminUsername = u;
        }
        if(body.adminPassword){
          const p = body.adminPassword.toString();
          if(p.length < 8){
            return jsonResponse({success:false,message:'密码至少 8 位'},400);
          }
          cfg.adminPasswordHash = await sha256(p);
        }

        // others
        cfg.turnstile = body.turnstile || cfg.turnstile;
        cfg.protectedUsers = Array.isArray(body.protectedUsers) ? body.protectedUsers : (cfg.protectedUsers||[]);
        cfg.protectedPrefixes = Array.isArray(body.protectedPrefixes) ? body.protectedPrefixes : (cfg.protectedPrefixes||[]);
        cfg.invite = { ...(cfg.invite||{}), enabled: !!body.inviteEnabled };
        cfg.adminPath = newPath;

        cfg = mergeConfig(cfg);
        await setConfig(env, cfg);
        return jsonResponse({success:true,newPath});
      }

      // users list
      if(url.pathname === `${adminPath}/api/users` && request.method==='GET'){
        let result = [];
        for(const g of (cfg.globals||[])){
          try{
            const token = await getAccessTokenForGlobal(g, fetch);
            let arr = await graphRequestCollection(
              'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,assignedLicenses&$top=100&$orderby=createdDateTime desc&$count=true',
              token,
              fetch,
              { headers: { ConsistencyLevel: 'eventual' } },
              100,
            );
            arr = filterProtectedUsers(arr, env, cfg);

            const idToName = Object.entries(g.skuMap || {}).reduce((m,[k,v]) => { m[v]=k; return m; }, {});
            arr.forEach(u=>{
              u.assignedLicenses = (u.assignedLicenses||[]).map(l=>{
                const name = idToName[l.skuId] || l.skuId || '';
                return {...l,name};
              });
              u._licSort = (u.assignedLicenses||[]).map(l=>l.name||'').join(','); // for sorting/search
              u._globalId = g.id; u._globalLabel = g.label;
            });
            result = result.concat(arr);
          }catch(e){
            console.error('Failed to fetch users for global', g?.label || g?.id || 'unknown', e?.message || e);
          }
        }
        return jsonResponse(result);
      }

      // delete user
      if(url.pathname.match(`${adminPath}/api/users/[^/]+/[^/]+$`) && request.method==='DELETE'){
        const parts = url.pathname.split('/');
        const userId = parts.pop();
        const gId = parts.pop();
        const g = (cfg.globals||[]).find(x=>x.id===gId);
        if(!g) return jsonResponse({error:'not found'},404);
        const token = await getAccessTokenForGlobal(g, fetch);

        // pre-check protected (fail-closed to avoid mis-delete)
        const checkResp = await fetch(`https://graph.microsoft.com/v1.0/users/${userId}?$select=userPrincipalName`,{
          headers:{Authorization:`Bearer ${token}`}
        });
        if(!checkResp.ok){
          return jsonResponse({error:'cannot_verify_user'},502);
        }
        const user = await checkResp.json();
        const upn = user.userPrincipalName || '';
        if(isProtectedUpn(upn, env, cfg)) return jsonResponse({error:'forbidden'},403);

        const delResp = await fetch(`https://graph.microsoft.com/v1.0/users/${userId}`,{
          method:'DELETE',
          headers:{Authorization:`Bearer ${token}`}
        });
        if(!delResp.ok){
          const t = await delResp.text().catch(()=> '');
          return jsonResponse({error:'delete_failed', details: t.slice(0,300)}, delResp.status);
        }
        return jsonResponse({success:true});
      }

      // reset password
      if(url.pathname.match(`${adminPath}/api/users/[^/]+/[^/]+/password$`) && request.method==='PATCH'){
        const parts = url.pathname.split('/');
        const userId = parts[parts.length-2];
        const gId = parts[parts.length-3];
        const body = await request.json().catch(()=>({}));
        const password = (body.password || '').toString();
        if(!password) return jsonResponse({success:false,message:'缺少新密码'},400);
        const g = (cfg.globals||[]).find(x=>x.id===gId);
        if(!g) return jsonResponse({error:'not found'},404);
        try{
          const token = await getAccessTokenForGlobal(g, fetch);
          await graphRequestJson(`https://graph.microsoft.com/v1.0/users/${userId}`, token, fetch, {
            method:'PATCH',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({passwordProfile:{forceChangePasswordNextSignIn:false,password}})
          });
          return jsonResponse({success:true,userId});
        }catch(e){
          return jsonResponse({success:false,message:buildPasswordResetErrorMessage(e),userId}, e.status || 500);
        }
      }

      // licenses
      if(url.pathname === `${adminPath}/api/licenses` && request.method==='GET'){
        let list = [];
        for(const g of (cfg.globals||[])){
          try{
            const token = await getAccessTokenForGlobal(g, fetch);

            // subscription expiry/renew time (nextLifecycleDateTime)
            let expiryBySkuId = {};
            try{
              const subResp = await fetch('https://graph.microsoft.com/v1.0/directory/subscriptions?$select=skuId,skuPartNumber,nextLifecycleDateTime,status',{
                headers:{Authorization:`Bearer ${token}`}
              });
              if(subResp.ok){
                const subData = await subResp.json().catch(()=>({}));
                (subData.value||[]).forEach(cs=>{
                  const skuId = (cs.skuId||'').toString().toLowerCase();
                  const dt = cs.nextLifecycleDateTime;
                  if(!skuId || !dt) return;
                  if(!expiryBySkuId[skuId] || new Date(dt) < new Date(expiryBySkuId[skuId])) expiryBySkuId[skuId] = dt;
                });
              }
            }catch(e){}

            const resp = await fetch('https://graph.microsoft.com/v1.0/subscribedSkus',{headers:{Authorization:`Bearer ${token}`}});
            const data = await resp.json();
            (data.value||[]).forEach(s=>{
              const skuIdLower = (s.skuId||'').toString().toLowerCase();
              list.push({
                globalId:g.id,
                globalLabel:g.label,
                skuPartNumber:s.skuPartNumber,
                skuId:s.skuId,
                total:s.prepaidUnits?.enabled||0,
                used:s.consumedUnits||0,
                expiresAt: expiryBySkuId[skuIdLower] || null
              });
            });
          }catch(e){}
        }
        return jsonResponse(list);
      }

      // invites
      if(url.pathname === `${adminPath}/api/invites` && request.method==='GET'){
        await ensureInvites(env);
        let list = await getInvites(env);
        return jsonResponse(list);
      }
      if(url.pathname === `${adminPath}/api/invites/generate` && request.method==='POST'){
        const body = await request.json().catch(()=>({}));
        const sets = body.sets||[];
        const length = body.length||16;
        const qty = body.quantity||1;
        const limit = body.limit||1;
        const scopes = body.scopes||[];
        const dict = {
          upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
          lower: 'abcdefghijklmnopqrstuvwxyz',
          digit: '0123456789',
          sym: '!@#$%^&*()-_=+[]{}<>?'
        };
        let pool = '';
        sets.forEach(s=>{ if(dict[s]) pool+=dict[s]; });
        if(!pool) return jsonResponse({success:false,message:'请选择字符集'},400);
        if(!scopes.length) return jsonResponse({success:false,message:'请选择限制范围'},400);
        await ensureInvites(env);
        const invites = await getInvites(env);
        for(let i=0;i<qty;i++){
          let code=''; for(let j=0;j<length;j++) code+=pool[Math.floor(Math.random()*pool.length)];
          invites.push({code,limit,used:0,createdAt:Date.now(),usedAt:null,allowed:scopes});
        }
        await saveInvites(env,invites);
        return jsonResponse({success:true,count:qty});
      }
      if(url.pathname === `${adminPath}/api/invites/bulk` && request.method==='DELETE'){
        const body = await request.json().catch(()=>({codes:[]}));
        const codes = body.codes||[];
        const invites = await getInvites(env);
        const filtered = invites.filter(c=>!codes.includes(c.code));
        await saveInvites(env, filtered);
        return jsonResponse({success:true,removed: codes.length});
      }
    }

    /* ---------- Public register page ---------- */
    if(request.method === 'GET' && url.pathname === '/'){
      const globals = (cfg.globals || []).map(g => ({ id: g.id, label: g.label }));
      const selectedGlobalId = url.searchParams.get('g') || globals[0]?.id || '';
      const selectedGlobal = (cfg.globals || []).find(g => g.id === selectedGlobalId) || (cfg.globals || [])[0];

      // Build SKU list with remaining counts (server-rendered to avoid exposing admin-query APIs)
      let skuDisplayList = [];
      if (selectedGlobal) {
        try {
          const subscribed = await fetchSubscribedSkus(selectedGlobal, fetch);
          const bySkuId = new Map(subscribed.map(s => [String(s.skuId).toLowerCase(), s]));
          const skuMap = selectedGlobal.skuMap || {};
          skuDisplayList = Object.keys(skuMap).map(name => {
            const skuId = String(skuMap[name] || '').toLowerCase();
            const sku = bySkuId.get(skuId);
            const rem = sku ? remainingFromSubscribedSku(sku) : 0;
            return { name, remaining: rem, label: `${name}（剩余总量：${rem}）` };
          });
          skuDisplayList.sort((a,b)=> (b.remaining - a.remaining) || a.name.localeCompare(b.name));
        } catch {
          // fail closed: still render name list without remaining
          const skuMap = selectedGlobal.skuMap || {};
          skuDisplayList = Object.keys(skuMap).map(name => ({ name, remaining: 0, label: `${name}（剩余总量：0）` }));
        }
      }

      return htmlResponse(renderRegisterPage({
        globals,
        selectedGlobalId,
        skuDisplayList,
        protectedPrefixes: cfg.protectedPrefixes || [],
        turnstileSiteKey: cfg.turnstile?.siteKey || '',
        inviteMode: !!cfg.invite?.enabled,
        adminPath,
      }));
    }

    if(request.method === 'POST' && url.pathname === '/'){
      cfg = await getConfig(env); // refresh
      return handleRegister(env, request, cfg);
    }

    return new Response('Not Found', { status: 404 });
  }
};
