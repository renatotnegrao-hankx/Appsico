'use strict';
/* =====================================================================
   Appsico — prontuário psicológico
   Dados criptografados (AES-256-GCM) e guardados só no celular.
   ===================================================================== */
const CFG = window.APPSICO_CONFIG || { emailjs: {}, autoLockMinutes: 5, backgroundLockSeconds: 60 };

/* ---------------- Plataforma (Capacitor) ---------------- */
const Cap = window.Capacitor;
const NATIVE = !!(Cap && Cap.isNativePlatform && Cap.isNativePlatform());
const plug = n => (NATIVE && Cap.registerPlugin ? Cap.registerPlugin(n) : null);
const FS = plug('Filesystem'), SHARE = plug('Share'), APP = plug('App'), KS = plug('AppsicoKeystore');
const VAULT = 'appsico.vault';

// No navegador (versão para computador) o cofre fica no IndexedDB, que aceita arquivos grandes (fotos).
const IDB = {
  db: null,
  open() { if (this.db) return Promise.resolve(this.db); return new Promise((ok, no) => { if (!window.indexedDB) return no(new Error('sem IndexedDB')); const r = indexedDB.open('appsico', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => ok(this.db = r.result); r.onerror = () => no(r.error); }); },
  async get(k) { const db = await this.open(); return new Promise((ok, no) => { const q = db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => ok(q.result == null ? null : q.result); q.onerror = () => no(q.error); }); },
  async set(k, v) { const db = await this.open(); return new Promise((ok, no) => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = () => ok(); t.onerror = () => no(t.error); }); },
  async del(k) { const db = await this.open(); return new Promise(ok => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').delete(k); t.oncomplete = () => ok(); t.onerror = () => ok(); }); }
};
const Store = {
  async read() {
    if (NATIVE) { try { return (await FS.readFile({ path: VAULT, directory: 'DATA', encoding: 'utf8' })).data; } catch (e) { return null; } }
    try { const v = await IDB.get(VAULT); if (v) return v; } catch (e) {}
    try { return localStorage.getItem(VAULT); } catch (e) { return null; }
  },
  async clear() {
    if (NATIVE) { try { await FS.deleteFile({ path: VAULT, directory: 'DATA' }); } catch (e) {} return; }
    try { await IDB.del(VAULT); } catch (e) {}
    try { localStorage.removeItem(VAULT); } catch (e) {}
  },
  async write(s) {
    if (NATIVE) {
      await FS.writeFile({ path: VAULT + '.new', data: s, directory: 'DATA', encoding: 'utf8' });
      await FS.writeFile({ path: VAULT, data: s, directory: 'DATA', encoding: 'utf8' });
      try { await FS.deleteFile({ path: VAULT + '.new', directory: 'DATA' }); } catch (e) {}
      return;
    }
    try { await IDB.set(VAULT, s); try { localStorage.removeItem(VAULT); } catch (e) {} return; } catch (e) {}
    try { localStorage.setItem(VAULT, s); } catch (e) { throw new Error('armazenamento indisponível'); }
  }
};
// Cópia da chave dos dados protegida pelo Android Keystore (usada na redefinição por e-mail)
const Secure = {
  async set(k, v) { if (KS) return KS.set({ key: k, value: v }); try { localStorage.setItem('ks_' + k, v); } catch (e) {} },
  async get(k) { if (KS) { const r = await KS.get({ key: k }); return (r && r.value) || null; } try { return localStorage.getItem('ks_' + k); } catch (e) { return null; } }
};
const pref = { get(k, d) { try { const v = localStorage.getItem('ui_' + k); return v === null ? d : v; } catch (e) { return d; } }, set(k, v) { try { localStorage.setItem('ui_' + k, v); } catch (e) {} } };

/* ---------------- Criptografia ---------------- */
const te = new TextEncoder(), td = new TextDecoder();
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
function b64e(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
function b64d(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
const ITER = 310000;
async function kdf(secret, salt, it) {
  const base = await crypto.subtle.importKey('raw', te.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: it || ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const aesKey = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
async function seal(key, u8) { const iv = rnd(12); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, u8)); return { iv: b64e(iv), ct: b64e(ct) }; }
async function unseal(key, o) { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(o.iv) }, key, b64d(o.ct))); }
async function sha(s) { return b64e(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))); }
function genRecovery() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const b = rnd(20); let s = '';
  for (let i = 0; i < 20; i++) { s += A[b[i] % A.length]; if (i % 5 === 4 && i < 19) s += '-'; }
  return s;
}
const normRec = s => s.toUpperCase().replace(/[^A-Z0-9]/g, '');

/* ---------------- Cofre ---------------- */
let V = null;        // arquivo do cofre (metadados + dados cifrados)
let DEKraw = null, DEK = null;  // chave dos dados (só na memória enquanto desbloqueado)
let DB = null;       // dados decifrados (só na memória)

async function loadVault() { const s = await Store.read(); V = s ? JSON.parse(s) : null; return V; }
async function writeVault() { await Store.write(JSON.stringify(V)); }
async function persist() {
  if (!DEK || !DB) return;
  V.data = await seal(DEK, te.encode(JSON.stringify(DB)));
  V.updatedAt = new Date().toISOString();
  await writeVault();
}
let saving = Promise.resolve(), saveTimer = null;
function save() {
  if (typeof cloudBloqueia === 'function' && cloudBloqueia()) return;
  if (typeof cloudDirty === 'function') cloudDirty();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { saving = saving.then(persist).catch(e => toast('Erro ao salvar: ' + e.message)); }, 120);
}
async function flush() { clearTimeout(saveTimer); saving = saving.then(persist).catch(() => {}); await saving; }

// O PIN é combinado com um segredo guardado no Android Keystore do aparelho ("pepper"):
// o arquivo de dados copiado para fora do celular não pode ser testado por força bruta.
async function pepper() {
  let p = await Secure.get('pepper');
  if (!p) { p = b64e(rnd(32)); await Secure.set('pepper', p); if ((await Secure.get('pepper')) !== p) throw new Error('chave do aparelho indisponível'); }
  return p;
}
async function wrapWithPassword(pin) { const salt = rnd(16); const k = await kdf(pin + ':' + await pepper(), salt, ITER); return Object.assign({ salt: b64e(salt), it: ITER, kind: 'pin6', len: pin.length }, await seal(k, DEKraw)); }
async function openPw(pin, w) { return openWith(w.kind === 'pin6' ? pin + ':' + await pepper() : pin, w); }
function backupObj() { const o = JSON.parse(JSON.stringify(V)); delete o.pw; delete o.saf; o.guard = { fails: 0, until: 0 }; return o; }
async function openWith(secret, w) { const k = await kdf(secret, b64d(w.salt), w.it); return unseal(k, w); }
async function useDEK(raw) {
  DEKraw = raw; DEK = await aesKey(raw);
  DB = V.data ? JSON.parse(td.decode(await unseal(DEK, V.data))) : { prof: {}, patients: [] };
}

async function createVault({ nome, crp, email, pw, user }) {
  DEKraw = rnd(32); DEK = await aesKey(DEKraw);
  const rec = genRecovery(); const rsalt = rnd(16); const rk = await kdf(normRec(rec), rsalt, ITER);
  V = { v: 1, app: 'appsico', user: user || '', email: email.toLowerCase(), createdAt: new Date().toISOString(),
        pw: await wrapWithPassword(pw), rec: Object.assign({ salt: b64e(rsalt), it: ITER }, await seal(rk, DEKraw)),
        guard: { fails: 0, until: 0 }, data: null };
  DB = { prof: { nome, crp, email: email.toLowerCase() }, patients: [] };
  await Secure.set('dek', b64e(DEKraw));
  await persist();
  return rec;
}
async function setNewPassword(pw) {
  V.pw = await wrapWithPassword(pw); V.guard = { fails: 0, until: 0 };
  await Secure.set('dek', b64e(DEKraw));
  await persist();
}
function lockApp(reason) {
  clearTimeout(saveTimer);
  const go = () => { DEK = null; DEKraw = null; DB = null; S.cur = null; S.view = 'home'; closeModal(); cleanTemp(); showLogin(reason); };
  const nuvem = () => (typeof cloudBeforeLock === 'function' ? cloudBeforeLock() : null);
  if (DEK) saving.then(persist).catch(() => {}).then(nuvem).catch(() => {}).then(() => { if (typeof cloudStop === 'function') cloudStop(); }).then(go); else go();
}

/* ---------------- Utilidades ---------------- */
const uid = () => b64e(rnd(9)).replace(/[+/=]/g, '').slice(0, 12);
const today = () => { const d = new Date(); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 10); };
const nowISO = () => new Date().toISOString();
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtD = d => d ? d.split('-').reverse().join('/') : '—';
const fmtDT = d => d ? new Date(d).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—';
function age(dn) { if (!dn) return null; const b = new Date(dn + 'T00:00'), t = new Date(); let a = t.getFullYear() - b.getFullYear(); const m = t.getMonth() - b.getMonth(); if (m < 0 || (m === 0 && t.getDate() < b.getDate())) a--; return a; }
function addYears(d, n) { if (!d) return ''; const x = new Date(d + 'T00:00'); x.setFullYear(x.getFullYear() + n); return x.toISOString().slice(0, 10); }
const $ = id => document.getElementById(id);
const val = id => ($(id) ? $(id).value.trim() : '');
function toast(m) { const t = $('toast'); t.textContent = m; t.classList.add('show'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2800); }
const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
function pwIssues(p) {
  if (!/^\d{4}$/.test(p)) return ['O PIN deve ter exatamente 4 números.'];
  if (/(\d)\1\1/.test(p)) return ['Não repita o mesmo número 3 vezes seguidas (ex.: 1111, 2223).'];
  if ('01234567890123'.includes(p) || '98765432109876'.includes(p)) return ['Não use números em sequência (ex.: 1234, 4321).'];
  if (/^(\d\d)\1$/.test(p)) return ['Evite padrões repetidos (ex.: 1212).'];
  return [];
}
function pinHint(id) {
  const el = $(id); if (!el || el._hint) return; el._hint = true;
  const h = document.createElement('small'); h.className = 'pin-hint'; h.textContent = 'Sem números repetidos (111) ou em sequência (1234, 4321).';
  el.insertAdjacentElement('afterend', h);
  el.addEventListener('input', () => { const v = el.value.replace(/\D/g, ''); if (v.length < 4) { h.className = 'pin-hint'; h.textContent = 'Sem números repetidos (111) ou em sequência (1234, 4321).'; return; }
    const w = pwIssues(v); h.className = 'pin-hint ' + (w.length ? 'bad' : 'ok'); h.textContent = w.length ? w[0] : 'PIN válido'; });
}
function pwScore(p) { let s = 0; if (p.length >= 8) s++; if (p.length >= 12) s++; if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++; if (/\d/.test(p)) s++; if (/[^A-Za-z0-9]/.test(p)) s++; return s; }
function maskEmail(e) { if (!e) return ''; const [u, d] = e.split('@'); return u.slice(0, 2) + '•••@' + d; }

/* ---------------- Ícones ---------------- */
const I = (p) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const IC = {
  menu: I('<path d="M3 6h18M3 12h18M3 18h18"/>'),
  collapse: I('<path d="M15 18l-6-6 6-6"/>'), expand: I('<path d="M9 18l6-6-6-6"/>'),
  users: I('<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>'),
  plus: I('<path d="M12 5v14M5 12h14"/>'),
  id: I('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="11" r="2.5"/><path d="M14 9h4M14 13h4M6 17h6"/>'),
  chat: I('<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'),
  target: I('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>'),
  trend: I('<path d="M3 17l6-6 4 4 8-8"/><path d="M14 7h7v7"/>'),
  share: I('<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><path d="M16 6l-4-4-4 4M12 2v13"/>'),
  file: I('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h6"/>'),
  shield: I('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
  note: I('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>'),
  clock: I('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
  book: I('<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z"/><path d="M4 19.5V21h16"/>'),
  gear: I('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
  backup: I('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>'),
  bell: I('<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>'),
  help: I('<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>'),
  report: I('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 18v-3M12 18v-6M16 18v-4"/>'),
  docs: I('<path d="M16 3H8a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z"/><path d="M10 8h4M10 12h4M3 7v12a2 2 0 0 0 2 2h9"/>'),
  crown: I('<path d="M2 7l5 5 5-8 5 8 5-5-2 12H4z"/><path d="M4 21h16"/>'),
  check: I('<path d="M20 6L9 17l-5-5"/>'),
  lock: I('<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'),
  back: I('<path d="M19 12H5M12 19l-7-7 7-7"/>'),
  trash: I('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6"/>'),
  grid: I('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>'),
  diag: I('<path d="M9 3h6M10 3v5.5L5.5 17A2.5 2.5 0 0 0 7.7 21h8.6a2.5 2.5 0 0 0 2.2-4L14 8.5V3"/><path d="M7.5 14h9"/>'),
  homeic: I('<path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>'),
  cash: I('<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 12h.01M18 12h.01"/>'),
  exit: I('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>'),
  pagar: I('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/><path d="M15 15h4"/><path d="M8 13.5 6 15.5l-2-2" transform="translate(2 0)"/>'),
  receber: I('<circle cx="12" cy="12" r="9"/><path d="M12 7v10M8.5 13.5 12 17l3.5-3.5"/>'),
  calcash: I('<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/><path d="M14.5 13.5h-3a1.5 1.5 0 0 0 0 3h1a1.5 1.5 0 0 1 0 3h-3M12 12.5v1M12 19.5v1"/>'),
  cal: I('<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18M8 14h2M14 14h2M8 18h2"/>'),
  camera: I('<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>'),
  cert: I('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h7"/><path d="M14 2v6h6v5"/><path d="M8 9h2M8 13h6M8 17h3"/><circle cx="18" cy="17" r="3"/><path d="M16.5 19.5 16 23l2-1 2 1-.5-3.5"/>'),
  receipt: I('<path d="M5 2v20l2.5-1.5L10 22l2-1.5 2 1.5 2.5-1.5L19 22V2l-2.5 1.5L14 2l-2 1.5L10 2 7.5 3.5z"/><path d="M9 8h6M9 12h6M9 16h4"/>'),
  printer: I('<path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>')
};

/* =====================================================================
   ABERTURA E ACESSO
   ===================================================================== */
function authScreen(html) { const a = $('auth'); a.innerHTML = `<div class="box"><img class="logo" src="logo.png" alt="Appsico">${html}</div>`; a.classList.remove('hidden'); $('app').classList.add('hidden'); }
function hideAuth() { $('auth').classList.add('hidden'); $('app').classList.remove('hidden'); }
function busy(btn, on, txt) { if (!btn) return; btn.disabled = on; if (on) { btn._t = btn.textContent; btn.textContent = txt || 'Aguarde…'; } else if (btn._t) btn.textContent = btn._t; }
function pwMeter(inp, bar) { if (!$(inp) || !$(bar)) return; $(inp).addEventListener('input', () => { $(bar).style.width = (pwScore($(inp).value) * 20) + '%'; }); }

function showSetup() {
  authScreen(`<h2>Bem-vindo ao Appsico</h2><div class="sub">Primeiro acesso: crie seu login. Os prontuários ficam criptografados somente neste celular.</div>
    <div class="f"><label>Nome completo</label><input id="uNome" autocomplete="name"></div>
    <div class="f"><label>CRP</label><input id="uCrp" placeholder="06/123456"></div>
    <div class="f"><label>Nome de usuário (para entrar no app)</label><input id="uUser" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="ex.: jsilva"></div>
    <div class="f"><label>E-mail (para redefinir o PIN)</label><input id="uEmail" type="email" autocomplete="email" inputmode="email"></div>
    <div class="f"><label>Crie um PIN de 4 números</label><input id="uPw" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <div class="f"><label>Confirmar PIN</label><input id="uPw2" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <button class="pri" id="uGo">Criar acesso</button><div class="err" id="uErr"></div>
    ${NATIVE ? '<div class="links"><a id="uRestore">Já tenho backup no Google Drive</a></div>' : ''}`);
  if ($('uRestore')) $('uRestore').onclick = showSetupRestore;
  pwMeter('uPw', 'uBar');
  $('uGo').onclick = async () => {
    const nome = val('uNome'), crp = val('uCrp'), user = val('uUser').toLowerCase(), email = val('uEmail'), pw = $('uPw').value, pw2 = $('uPw2').value;
    const err = m => $('uErr').textContent = m;
    if (!nome || !crp) return err('Informe nome e CRP.');
    if (!/^[a-z0-9._-]{3,30}$/.test(user)) return err('Nome de usuário: de 3 a 30 letras ou números, sem espaços e sem acento.');
    if (!emailOk(email)) return err('E-mail inválido.');
    const w = pwIssues(pw); if (w.length) return err(w[0]);
    if (pw !== pw2) return err('Os PINs não conferem.');
    busy($('uGo'), true, 'Criptografando…');
    try { const rec = await createVault({ nome, crp, email, pw, user }); showRecovery(rec); }
    catch (e) { busy($('uGo'), false); err('Não foi possível criar o acesso: ' + e.message); }
  };
}
function showRecovery(rec, next) {
  authScreen(`<h2>Código de recuperação</h2><div class="sub">${typeof CLOUD !== 'undefined' && CLOUD ? 'Se você esquecer a senha da conta, este código é a única forma de reabrir os prontuários: nem o Appsico consegue recuperá-los. Anote e guarde em local seguro, fora do celular.' : 'Se você esquecer o PIN e não tiver acesso ao e-mail, este código é a única forma de abrir os prontuários. Ele também é necessário para restaurar backups. Anote e guarde fora do celular.'}</div>
    <div class="rec-code">${rec}</div>
    <button id="rCopy" style="width:100%;margin-bottom:12px">Copiar código</button>
    <label class="check" style="margin-bottom:12px"><input type="checkbox" id="rOk"> Anotei o código em local seguro</label>
    <button class="pri" id="rGo" disabled>Entrar no Appsico</button>`);
  $('rCopy').onclick = () => navigator.clipboard.writeText(rec).then(() => toast('Código copiado'), () => toast('Selecione e copie manualmente'));
  $('rOk').onchange = e => $('rGo').disabled = !e.target.checked;
  $('rGo').onclick = () => (next ? next() : enterApp());
}
function showLogin(reason) {
  const g = V.guard || { fails: 0, until: 0 };
  authScreen(`<h2>Entrar</h2><div class="sub">${reason ? esc(reason) : 'Prontuários protegidos com criptografia'}</div>
    ${V.user ? `<div class="f"><label>${V.cloud ? 'E-mail da conta' : 'Usuário'}</label><input id="lEmail" autocomplete="username" autocapitalize="none" spellcheck="false" value="${esc(pref.get('lastUser', '') || '')}"></div>`
      : `<div class="f"><label>E-mail</label><input id="lEmail" type="email" inputmode="email" autocomplete="username" value="${esc(pref.get('lastEmail', '') || V.email)}"></div>`}
    ${V.pw && V.pw.kind === 'pin6' ? `<div class="f"><label>PIN</label><input id="lPw" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="${V.pw.len || 6}" autocomplete="off" class="pin"></div>` : `<div class="f"><label>Senha atual</label><input id="lPw" type="password" autocomplete="current-password"><small style="color:var(--muted)">Depois de entrar, você vai criar um PIN de 4 números.</small></div>`}
    <button class="pri" id="lGo">Entrar</button><div class="err" id="lErr"></div>
    <div class="links"><a id="lForgot">Esqueci meu PIN</a></div>`);
  setTimeout(() => { if (V.user && !val('lEmail') && $('lEmail')) $('lEmail').focus(); else if ($('lPw')) $('lPw').focus(); }, 50);
  $('lPw').addEventListener('keydown', e => { if (e.key === 'Enter') $('lGo').click(); });
  $('lPw').addEventListener('input', e => { if (V.pw && V.pw.kind === 'pin6' && e.target.value.length === (V.pw.len || 6) && /^\d+$/.test(e.target.value) && !$('lGo').disabled) $('lGo').click(); });
  $('lForgot').onclick = () => (typeof cloudLinked === 'function' && cloudLinked() ? showPinPelaConta() : showForgot());
  $('lGo').onclick = async () => {
    const err = m => $('lErr').textContent = m;
    const wait = Math.ceil(((V.guard && V.guard.until) || 0) - Date.now()) / 1000;
    if (wait > 0) return err(`Muitas tentativas. Aguarde ${Math.ceil(wait)} s.`);
    const email = val('lEmail').toLowerCase(), pw = $('lPw').value;
    if (!email || !pw) return err(V.user ? 'Informe usuário e PIN.' : 'Informe e-mail e PIN.');
    busy($('lGo'), true, 'Verificando…');
    let raw = null;
    if ((V.user ? email === V.user : email === V.email) && V.pw) { try { raw = await openPw(pw, V.pw); } catch (e) { raw = null; } }
    if (!raw) {
      V.guard = V.guard || { fails: 0, until: 0 }; V.guard.fails++;
      if (V.guard.fails >= 5) V.guard.until = Date.now() + Math.min(300, 30 * Math.pow(2, V.guard.fails - 5)) * 1000;
      try { await writeVault(); } catch (e) {}
      busy($('lGo'), false); $('lPw').value = ''; return err(V.user ? 'Usuário ou PIN incorretos.' : V.pw && V.pw.kind === 'pin6' ? 'E-mail ou PIN incorretos.' : 'E-mail ou senha incorretos.');
    }
    try { await useDEK(raw); } catch (e) { busy($('lGo'), false); return err('Arquivo de dados danificado.'); }
    V.guard = { fails: 0, until: 0 }; pref.set(V.user ? 'lastUser' : 'lastEmail', email);
    await writeVault().catch(() => {});
    if (V.pw.kind !== 'pin6') return showCreatePin('Para mais segurança, o Appsico agora usa um PIN de 4 números. Crie o seu.');
    enterApp();
  };
}

function showCreatePin(msg) {
  authScreen(`<h2>Crie seu PIN</h2><div class="sub">${esc(msg)}</div>
    <div class="f"><label>Novo PIN (4 números)</label><input id="nPw" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <div class="f"><label>Confirmar PIN</label><input id="nPw2" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <button class="pri" id="nGo">Salvar PIN e entrar</button><div class="err" id="nErr"></div>`);
  setTimeout(() => $('nPw') && $('nPw').focus(), 50);
  $('nGo').onclick = async () => {
    const err = m => $('nErr').textContent = m, pin = $('nPw').value, w = pwIssues(pin);
    if (w.length) return err(w[0]);
    if (pin !== $('nPw2').value) return err('Os PINs não conferem.');
    busy($('nGo'), true, 'Salvando…');
    try { await setNewPassword(pin); toast('PIN criado'); enterApp(); } catch (e) { busy($('nGo'), false); err('Não foi possível salvar o PIN: ' + e.message); }
  };
}

/* --- redefinição de senha --- */
let resetState = null;
async function sendCodeEmail(email, code) {
  const c = CFG.emailjs || {};
  if (!c.serviceId || !c.templateId || !c.publicKey) return false;
  const r = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ service_id: c.serviceId, template_id: c.templateId, user_id: c.publicKey,
      template_params: { to_email: email, code, app_name: 'Appsico' } })
  });
  if (!r.ok) throw new Error((await r.text()) || ('HTTP ' + r.status));
  return true;
}
function showForgot() {
  authScreen(`<h2>Redefinir PIN</h2><div class="sub">Enviaremos um código para o e-mail cadastrado (${esc(maskEmail(V.email))}).</div>
    <div class="f"><label>E-mail cadastrado</label><input id="fEmail" type="email" inputmode="email"></div>
    <button class="pri" id="fGo">Enviar código</button><div class="err" id="fErr"></div>
    <div class="links"><a id="fRec">Usar código de recuperação</a> &nbsp;·&nbsp; <a id="fBack">Voltar</a></div>`);
  $('fBack').onclick = () => showLogin();
  $('fRec').onclick = showRecoveryReset;
  $('fGo').onclick = async () => {
    const err = m => $('fErr').textContent = m;
    const email = val('fEmail').toLowerCase();
    if (email !== V.email) return err('Este não é o e-mail cadastrado neste aparelho.');
    if (resetState && Date.now() - resetState.sentAt < 60000) return err('Aguarde 1 minuto para pedir outro código.');
    const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
    busy($('fGo'), true, 'Enviando…');
    let sent = false, dev = false;
    try { sent = await sendCodeEmail(email, code); } catch (e) { busy($('fGo'), false); return err('Falha ao enviar e-mail: ' + e.message); }
    if (!sent) {
      if (NATIVE) { busy($('fGo'), false); return err('O envio de e-mail ainda não foi configurado neste app. Use o código de recuperação.'); }
      dev = true; // pré-visualização no navegador
    }
    resetState = { hash: await sha(code), exp: Date.now() + 10 * 60000, tries: 0, sentAt: Date.now() };
    showResetCode(dev ? code : null);
  };
}
function showResetCode(devCode) {
  authScreen(`<h2>Digite o código</h2><div class="sub">Enviamos um código de 6 dígitos para ${esc(maskEmail(V.email))}. Ele vale por 10 minutos.</div>
    ${devCode ? `<div class="note warn">Pré-visualização no navegador (sem envio de e-mail): o código é <b>${devCode}</b>.</div>` : ''}
    <div class="f"><label>Código</label><input id="cCode" inputmode="numeric" maxlength="6" autocomplete="one-time-code" style="letter-spacing:6px;text-align:center;font-size:20px"></div>
    <div class="f"><label>Novo PIN (4 números)</label><input id="cPw" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <div class="f"><label>Confirmar novo PIN</label><input id="cPw2" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <button class="pri" id="cGo">Redefinir PIN</button><div class="err" id="cErr"></div>
    <div class="links"><a id="cBack">Voltar</a></div>`);
  pwMeter('cPw', 'cBar');
  $('cBack').onclick = () => showLogin();
  $('cGo').onclick = async () => {
    const err = m => $('cErr').textContent = m;
    if (!resetState || Date.now() > resetState.exp) return err('Código expirado. Peça um novo.');
    if (resetState.tries >= 5) return err('Muitas tentativas. Peça um novo código.');
    const pw = $('cPw').value, w = pwIssues(pw);
    if (w.length) return err(w[0]);
    if (pw !== $('cPw2').value) return err('Os PINs não conferem.');
    resetState.tries++;
    if ((await sha(val('cCode'))) !== resetState.hash) return err('Código incorreto.');
    busy($('cGo'), true, 'Salvando…');
    try {
      const k = await Secure.get('dek'); if (!k) throw new Error('chave do aparelho não encontrada');
      await useDEK(b64d(k));
      await setNewPassword(pw); resetState = null;
      toast('PIN redefinido'); enterApp();
    } catch (e) { busy($('cGo'), false); DEK = null; DEKraw = null; DB = null; err('Não foi possível redefinir por e-mail neste aparelho (' + e.message + '). Use o código de recuperação.'); }
  };
}
function showRecoveryReset() {
  authScreen(`<h2>Código de recuperação</h2><div class="sub">Digite o código de 20 caracteres que você anotou no primeiro acesso.</div>
    <div class="f"><label>Código de recuperação</label><input id="xRec" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" autocapitalize="characters" style="font-family:monospace"></div>
    <div class="f"><label>Novo PIN (4 números)</label><input id="xPw" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <div class="f"><label>Confirmar novo PIN</label><input id="xPw2" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <button class="pri" id="xGo">Redefinir PIN</button><div class="err" id="xErr"></div>
    <div class="links"><a id="xBack">Voltar</a></div>`);
  pwMeter('xPw', 'xBar');
  $('xBack').onclick = () => showLogin();
  $('xGo').onclick = async () => {
    const err = m => $('xErr').textContent = m;
    const pw = $('xPw').value, w = pwIssues(pw);
    if (w.length) return err(w[0]);
    if (pw !== $('xPw2').value) return err('Os PINs não conferem.');
    busy($('xGo'), true, 'Verificando…');
    let raw; try { raw = await openWith(normRec(val('xRec')), V.rec); } catch (e) { busy($('xGo'), false); return err('Código de recuperação incorreto.'); }
    await useDEK(raw); await setNewPassword(pw);
    toast('PIN redefinido'); enterApp();
  };
}

/* =====================================================================
   APP
   ===================================================================== */
const S = { view: 'home', cur: null, tab: 'ident', q: '', flt: 'ativo' };
const TABS = [
  ['ident', '1. Cadastro', 'id'], ['demanda', '2. Demanda e acolhimento', 'chat'], ['diagnostico', '3. Avaliação e diagnóstico', 'diag'],
  ['objetivos', '4. Plano terapêutico', 'target'], ['evolucao', '5. Sessões', 'trend'], ['encaminhamentos', '6. Encaminhamento e alta', 'share'],
  ['documentos', '7. Documentos', 'file'], ['linha', 'Linha do tempo', 'clock'], ['emitir', 'Atestado e recibo', 'printer'], ['acesso', 'Sigilo e acesso', 'shield'], ['privado', 'Anotações privadas', 'note']
];
const P = () => DB.patients.find(p => p.id === S.cur);

function enterApp() {
  hideAuth(); S.view = 'inicio'; S.cur = null;
  document.body.classList.toggle('mini', pref.get('mini', '0') === '1');
  render(); armIdle();
  if (typeof cloudLinked === 'function' && cloudLinked()) cloudStart();
}
function render() { checaTemaPlano(); renderSidebar(); renderMain(); }
function go(view, extra) {
  if (view !== 'patient') S.prefill = null;
  Object.assign(S, { view }, extra || {});
  document.body.classList.remove('drawer');
  render(); window.scrollTo(0, 0);
}
function toggleSidebar() {
  if (window.matchMedia('(max-width:600px)').matches) { document.body.classList.toggle('drawer'); return; }
  const m = !document.body.classList.contains('mini'); document.body.classList.toggle('mini', m); pref.set('mini', m ? '1' : '0'); renderSidebar();
}

function navBtn(icon, label, on, onclick, cls) { return `<button class="nav ${on ? 'on' : ''} ${cls || ''}" title="${esc(label)}" onclick="${onclick}">${IC[icon]}<span class="txt">${esc(label)}</span></button>`; }
function renderSidebar() {
  const p = S.cur ? P() : null, mini = document.body.classList.contains('mini');
  $('sidebar').innerHTML = `
    <div class="sb-head"><img src="logo.png" alt=""><span class="name">Appsico</span>
      <button class="sb-toggle" onclick="toggleSidebar()" title="${mini ? 'Expandir menu' : 'Recolher menu'}" aria-label="Menu">${IC.menu}</button></div>
    <div class="sb-scroll">
      <div class="sb-label">Geral</div>
      ${navBtn('homeic', 'Início', S.view === 'inicio', "go('inicio',{cur:null})")}
      ${navBtn('plus', 'Novo paciente', false, 'newPatient()')}
      ${navBtn('users', 'Pacientes', S.view === 'home' || S.view === 'patient', "go('home',{cur:null})")}
      ${navBtn('cal', 'Agenda', S.view === 'agenda', "go('agenda',{cur:null,agModo:'mes'})")}
      ${navBtn('bell', 'Lembretes', S.view === 'lembretes', "go('lembretes',{cur:null})")}
      ${navBtn('cert', 'Atestado', S.view === 'docs' && S.docKind === 'atestado', "go('docs',{cur:null,docQ:'',docKind:'atestado'})")}
      ${navBtn('receipt', 'Recibo', S.view === 'docs' && S.docKind === 'recibo', "go('docs',{cur:null,docQ:'',docKind:'recibo'})")}
      ${navBtn('docs', 'Modelos de documentos', S.view === 'docs' && S.docKind === 'modelos', "go('docs',{cur:null,docQ:'',docKind:'modelos'})")}
      <div class="sb-sep"></div><div class="sb-label">Financeiro</div>
      ${navBtn('receber', 'Contas a receber', S.view === 'fin' && S.finTab === 'receber', "go('fin',{cur:null,finTab:'receber'})", 'nav-rec' + (premium() ? '' : ' locked'))}
      ${navBtn('pagar', 'Contas a pagar', S.view === 'fin' && S.finTab === 'pagar', "go('fin',{cur:null,finTab:'pagar'})", 'nav-pag' + (premium() ? '' : ' locked'))}
      ${navBtn('calcash', 'Calendário financeiro', S.view === 'fin' && S.finTab === 'calendario', "go('fin',{cur:null,finTab:'calendario'})", premium() ? '' : 'locked')}
      ${navBtn('report', 'Relatório do contador', S.view === 'fin' && S.finTab === 'relatorio', "go('fin',{cur:null,finTab:'relatorio'})", premium() ? '' : 'locked')}
      <div class="sb-label">Mais</div>
      ${navBtn('crown', typeof cloudLinked === 'function' && cloudLinked() ? 'Assinatura' : premium() ? 'Premium' : 'Seja Premium', S.view === 'premium', "go('premium',{cur:null})", 'nav-prem')}
      ${navBtn('help', 'Ajuda e suporte', S.view === 'ajuda', "go('ajuda',{cur:null})")}
    </div>
    <div class="sb-foot">
      <div class="sb-prof">${esc(DB.prof.nome || '')}${DB.prof.crp ? ' · CRP ' + esc(DB.prof.crp) : ''}</div>
      ${typeof syncBadge === 'function' ? syncBadge() : ''}
      ${navBtn('gear', 'Configurações', S.view === 'settings', "go('settings')")}
      ${navBtn('backup', 'Backup', S.view === 'backup', "go('backup')")}
      ${navBtn('lock', 'Bloquear', false, "lockApp('App bloqueado')")}
    </div>`;
  const t = S.view === 'patient' && p ? (p.ident.nome || 'Novo paciente') : ({ inicio: 'Início', home: 'Pacientes', settings: 'Configurações', backup: 'Backup', fin: ({ relatorio: 'Relatório do contador', calendario: 'Calendário financeiro', pagar: 'Contas a pagar', receber: 'Contas a receber' })[S.finTab] || 'Financeiro', fincal: 'Calendário financeiro', agenda: 'Agenda', premium: typeof cloudLinked === 'function' && cloudLinked() ? 'Assinatura' : 'Appsico Premium', admin: 'Administrador', lembretes: 'Lembretes', ajuda: 'Ajuda e suporte', docs: S.docKind === 'recibo' ? 'Recibo' : S.docKind === 'modelos' ? 'Modelos de documentos' : 'Atestado' })[S.view] || 'Appsico';
  $('topTitle').textContent = t;
  $('fab').style.display = S.view === 'home' ? '' : 'none';
}

function renderMain() {
  const m = $('main');
  if (S.view === 'settings') return paneSettings(m);
  if (S.view === 'backup') return paneBackup(m);
  if (S.view === 'fincal') { S.view = 'fin'; S.finTab = 'calendario'; renderSidebar(); }
  if (S.view === 'premium') return typeof cloudLinked === 'function' && cloudLinked() ? panePremiumNuvem(m) : panePremium(m);
  if (S.view === 'admin') return paneAdmin(m);
  if (S.view === 'lembretes') return paneLembretes(m);
  if (S.view === 'ajuda') return paneAjuda(m);
  if (S.view === 'fin' && !premium() && !(typeof cloudLinked === 'function' && cloudLinked())) return paneBloqueado(m, 'fin');
  if (S.view === 'fin') { if (!S.finTab || S.finTab === 'caixa') S.finTab = 'calendario'; return ({ caixa: paneFin, calendario: paneFinCal, relatorio: paneRelatorio, pagar: m2 => paneContas(m2, 'pagar'), receber: m2 => paneContas(m2, 'receber') })[S.finTab](m); }
  if (S.view === 'docs') return paneDocsCentral(m);
  if (S.view === 'agenda') return paneAgenda(m);
  if (S.view === 'fincal') return paneFinCal(m);
  if (S.view === 'patient' && P()) return panePatient(m, P());
  if (S.view === 'inicio') return paneInicio(m);
  S.view = 'home'; paneHome(m);
}

/* ---------- Botão Sair ---------- */
const sairBtn = (home) => home === true
  ? `<button class="sair" onclick="confirmBox('Sair do Appsico?','Os prontuários serão bloqueados e será preciso entrar com e-mail e PIN.','Sair',()=>lockApp('Você saiu do Appsico'))">${IC.exit}<span>Sair</span></button>`
  : `<button class="sair" onclick="go('${home === 'lista' ? 'home' : 'inicio'}',{cur:null})">${IC.exit}<span>Sair</span></button>`;

/* ---------- Foto do paciente ---------- */
function avatarHTML(p, size, inert, editable) {
  const f = p.ident.foto, cls = 'avatar' + (size ? ' ' + size : '') + (f ? ' has-photo' : '') + (editable && !f ? ' add' : '');
  if (inert) return `<div class="${cls}">${f ? `<img src="${f}" alt="">` : esc(iniciais(p.ident.nome))}</div>`;
  const act = f ? `showPhoto('${p.id}')` : editable ? `fotoMenu('${p.id}')` : '';
  return `<div class="${cls}" ${act ? `role="button" title="${f ? 'Ampliar, trocar ou remover foto' : 'Carregar foto'}" onclick="event.stopPropagation();${act}"` : ''}>${f ? `<img src="${f}" alt="Foto de ${esc(p.ident.nome)}">` : esc(iniciais(p.ident.nome))}${editable ? `<i class="cam">${IC.camera}</i>` : ''}</div>`;
}
function pickPhoto(id) {
  const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
  inp.onchange = () => {
    const f = inp.files[0]; if (!f) return;
    const r = new FileReader();
    r.onload = () => {
      const img = new Image();
      img.onload = () => {
        const M = 480, k = Math.min(1, M / Math.max(img.width, img.height));
        const c = document.createElement('canvas'); c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        const p = DB.patients.find(x => x.id === id); if (!p) return;
        if (S.view === 'patient' && S.tab === 'ident' && S.cur === id && paneEl && paneEl.querySelector('[data-f]')) saveIdent(true);
        p.ident.foto = c.toDataURL('image/jpeg', .85); save(); toast('Foto salva'); render();
      };
      img.onerror = () => toast('Não foi possível ler a imagem');
      img.src = r.result;
    };
    r.readAsDataURL(f);
  };
  inp.click();
}
function fotoMenu(id) {
  const p = DB.patients.find(x => x.id === id); if (!p) return;
  if (p.ident.foto) return showPhoto(id);
  modal(`<h2>Foto de ${esc(primeiro(p.ident.nome) || 'paciente')}</h2><p>Escolha uma foto da galeria ou dos arquivos do aparelho. Ela fica guardada criptografada, só neste celular.</p>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" onclick="closeModal();pickPhoto('${id}')">${IC.camera}<span>Carregar foto</span></button></div>`);
}
function removePhoto(id) { confirmBox('Retirar foto?', 'A foto do paciente será apagada deste aparelho.', 'Retirar foto', () => { if (S.view === 'patient' && S.tab === 'ident' && paneEl && paneEl.querySelector('[data-f]')) saveIdent(true); const p = DB.patients.find(x => x.id === id); delete p.ident.foto; save(); render(); }); }
function showPhoto(id) {
  const p = DB.patients.find(x => x.id === id); if (!p || !p.ident.foto) return;
  const o = document.createElement('div'); o.className = 'lightbox';
  o.innerHTML = `<button class="lb-close" aria-label="Fechar">✕</button><img src="${p.ident.foto}" alt=""><div class="lb-name">${esc(p.ident.nome)}</div>
    <div class="lb-acts"><button id="lbTroca">${IC.camera}<span>Carregar outra foto</span></button><button id="lbRem" class="lb-rem">${IC.trash}<span>Retirar foto</span></button></div>`;
  const close = () => { o.classList.remove('show'); setTimeout(() => o.remove(), 250); document.removeEventListener('keydown', esc_); };
  const esc_ = e => { if (e.key === 'Escape') close(); };
  o.onclick = close; document.addEventListener('keydown', esc_);
  o.querySelector('#lbTroca').onclick = e => { e.stopPropagation(); close(); pickPhoto(id); };
  o.querySelector('#lbRem').onclick = e => { e.stopPropagation(); close(); removePhoto(id); };
  document.body.appendChild(o); requestAnimationFrame(() => o.classList.add('show'));
  window._closeLightbox = close;
}

/* ---------- Plano grátis e Premium ----------
 * Hoje funciona em MODO DE TESTE: o botão de assinar libera um Premium de teste de 30 dias.
 * Quando o app estiver na Google Play, a parte nativa (AppsicoNative.billing*) passa a
 * existir e as compras vão direto para a Google Play. Nenhum dado de paciente é enviado.
 */
const BILL = Object.assign({ limiteGratis: 5, diasTeste: 30, temasGratis: ['padrao', 'light', 'escuro'],
  produtos: { mensal: 'appsico_premium_mensal', anual: 'appsico_premium_anual', anualpix: 'appsico_premium_anual_pix' } }, CFG.billing || {});
const PLANOS = [
  { id: 'mensal', nome: 'Mensal', preco: 'R$ 24,90', per: 'por mês', obs: 'Cartão · cancele quando quiser' },
  { id: 'anual', nome: 'Anual', preco: 'R$ 199,00', per: 'por ano', obs: 'Cartão · renova sozinho · sai por R$ 16,58/mês', tag: 'Economize 33%' },
  { id: 'anualpix', nome: 'Anual no Pix', preco: 'R$ 199,00', per: 'pagamento único', obs: 'Pix ou cartão · vale 1 ano, sem renovação automática', tag: 'Aceita Pix' }
];
const BENEF = [
  ['users', 'Pacientes ilimitados', `No grátis, até ${BILL.limiteGratis} prontuários`],
  ['receber', 'Financeiro completo', 'Contas a receber, a pagar e calendário com saldo'],
  ['cash', 'Cobrança por Pix', 'QR Code e copia e cola enviados pelo WhatsApp'],
  ['report', 'Relatório do contador', 'Recebimentos com CPF e despesas do mês, em PDF ou planilha'],
  ['gear', 'Todos os temas de cores', 'Oceano, Floresta, Lavanda, Terracota e Rosa']
];
function billingReal() { return !!(window.AppsicoNative && typeof AppsicoNative.billingBuy === 'function'); }
function plano() { return (DB && DB.plano) || null; }
function premium() {
  if (typeof cloudLinked === 'function' && cloudLinked()) return true; // na nuvem, o controle é pela assinatura (modo consulta em cloud.js)
  const p = plano(); if (!p) return false;
  return !!p.ate && p.ate >= today();
}
function podeNovoPaciente() { if (typeof cloudLinked === 'function' && cloudLinked()) return !planoGratis(); return premium() || DB.patients.length < BILL.limiteGratis; }
function temaBloq(k) { return !premium() && !BILL.temasGratis.includes(k); }
function checaTemaPlano() { if (DB && temaBloq(pref.get('theme', 'padrao'))) { pref.set('theme', 'padrao'); applyTheme(); } }
function nomePlano(id) { return (PLANOS.find(x => x.id === id) || {}).nome || 'Premium'; }
function planoResumo() {
  const p = plano();
  if (premium()) return p.origem === 'teste' ? `Premium de teste até ${fmtD(p.ate)}` : `Premium ${nomePlano(p.tipo)}${p.tipo === 'anualpix' ? ' · válido até ' + fmtD(p.ate) : ' · renova em ' + fmtD(p.ate)}`;
  return `Plano grátis · ${Math.min(DB.patients.length, BILL.limiteGratis)} de ${BILL.limiteGratis} pacientes`;
}
function planoCard() {
  const p = plano(), on = premium();
  return `<div class="plano-st ${on ? 'on' : ''}"><span class="ps-ic">${IC.crown}</span><div><b>${on ? 'Você é Premium' : 'Plano grátis'}</b><small>${esc(planoResumo())}</small></div></div>
    ${on && p.origem === 'teste' ? `<div class="note">Este é um Premium de teste. A cobrança de verdade será ativada quando o app estiver na Google Play.</div>` : ''}
    <div class="row-actions" style="justify-content:flex-start">
      <button class="pri" onclick="go('premium',{cur:null})">${on ? 'Ver meu plano' : 'Conhecer o Premium'}</button>
      ${on && p.origem === 'teste' ? `<button onclick="encerrarTeste()">Voltar ao plano grátis</button>` : `<button onclick="restaurarCompra()">Restaurar compra</button>`}</div>`;
}
function avisoVencimento() {
  const p = plano(); if (!premium() || !(p.tipo === 'anualpix' || p.origem === 'teste')) return '';
  const dias = Math.round((new Date(p.ate + 'T12:00') - new Date(today() + 'T12:00')) / 864e5);
  if (dias > 15) return '';
  return `<button class="plano-banner vence" onclick="go('premium',{cur:null})"><span class="pb-ic">${IC.crown}</span>
    <span class="pb-txt"><b>${dias <= 0 ? 'Seu Premium vence hoje' : `Seu Premium vence em ${dias} dia${dias > 1 ? 's' : ''}`}</b><small>${p.origem === 'teste' ? 'Premium de teste' : 'Anual no Pix'} válido até ${fmtD(p.ate)}. Renove para continuar com pacientes ilimitados e financeiro.</small></span><span class="pb-go">Renovar</span></button>`;
}
function bannerPlano() {
  const n = DB.patients.length, L = BILL.limiteGratis, pct = Math.min(100, Math.round(n / L * 100));
  return `<button class="plano-banner" onclick="go('premium',{cur:null})"><span class="pb-ic">${IC.crown}</span>
    <span class="pb-txt"><b>Plano grátis · ${Math.min(n, L)} de ${L} pacientes</b><small>${n >= L ? 'Limite atingido. Libere pacientes ilimitados com o Premium.' : 'Conheça o Premium: pacientes ilimitados, financeiro e Pix.'}</small>
    <span class="pb-bar"><i style="width:${pct}%"></i></span></span><span class="pb-go">Ver planos</span></button>`;
}
const PAYWALL = {
  gratis: ['Modo consulta', 'Sem assinatura ativa, o Appsico só permite ver e exportar os prontuários. Para registrar sessões, cadastrar pacientes, agenda e financeiro, assine o Appsico. Nenhum dado foi apagado.'],
  conferir: ['Conecte à internet', 'Faz mais de 7 dias que o app não confere sua assinatura. Conecte o aparelho à internet para continuar registrando. Ver e exportar continua liberado.'],
  pacientes: ['Limite do plano grátis', `O plano grátis guarda até ${BILL.limiteGratis} prontuários. Seus pacientes atuais continuam disponíveis; para cadastrar mais, assine o Premium.`],
  fin: ['Financeiro é Premium', 'Contas a receber, contas a pagar, o calendário financeiro e o relatório do contador fazem parte do Premium.'],
  pix: ['Cobrança por Pix é Premium', 'Gerar o QR Code e o Pix copia e cola para o paciente faz parte do Premium.'],
  temas: ['Tema Premium', 'Os temas Appsico, Claro e Escuro são grátis. Os demais fazem parte do Premium.']
};
function paywall(k) {
  const [t, d] = PAYWALL[k] || PAYWALL.pacientes;
  modal(`<div class="pw-top">${IC.crown}</div><h2 style="text-align:center">${esc(t)}</h2><p style="text-align:center">${esc(d)}</p>
    <div class="row-actions" style="justify-content:center"><button onclick="closeModal()">Agora não</button><button class="pri" onclick="closeModal();go('premium',{cur:null})">Ver planos</button></div>`);
}
function paneBloqueado(m, k) {
  const [t, d] = PAYWALL[k];
  m.innerHTML = `<div class="head"><div><h1>${esc(t)}</h1><div class="meta">Disponível no Appsico Premium</div></div>${sairBtn()}</div>
    <div class="card bloq"><div class="pw-top">${IC.lock}</div><p>${esc(d)}</p>
    <ul class="benef">${BENEF.map(([ic, b, s]) => `<li><span>${IC[ic]}</span><div><b>${b}</b><small>${s}</small></div></li>`).join('')}</ul>
    <div class="row-actions" style="justify-content:center"><button class="pri" onclick="go('premium',{cur:null})">Ver planos</button></div></div>`;
}
function panePremium(m) {
  const on = premium(), p = plano(), sel = S.planoSel || 'anual';
  m.innerHTML = `<div class="head"><div><h1>Appsico Premium</h1><div class="meta">${esc(planoResumo())}</div></div>${sairBtn()}</div>
    <div class="prem-hero"><span class="ph-ic">${IC.crown}</span><div><b>${on ? 'Obrigado por ser Premium!' : 'Tudo o que seu consultório precisa'}</b>
      <small>Seus prontuários continuam só neste celular, criptografados. A assinatura não envia nenhum dado de paciente.</small></div></div>
    ${!billingReal() ? `<div class="note">Modo de teste: a cobrança pela Google Play será ativada quando o app for publicado. Por enquanto, o botão de assinar libera um Premium de teste de ${BILL.diasTeste} dias.</div>` : ''}
    <div class="card"><h3>O que você ganha</h3><table class="cmp"><thead><tr><th></th><th>Grátis</th><th>Premium</th></tr></thead><tbody>
      <tr><td>Prontuário completo (CFP)</td><td>${IC.check}</td><td>${IC.check}</td></tr>
      <tr><td>Agenda, atestado e recibo</td><td>${IC.check}</td><td>${IC.check}</td></tr>
      <tr><td>Backup criptografado</td><td>${IC.check}</td><td>${IC.check}</td></tr>
      <tr><td>Pacientes</td><td>até ${BILL.limiteGratis}</td><td><b>ilimitados</b></td></tr>
      <tr><td>Financeiro (receber, pagar e calendário)</td><td>—</td><td>${IC.check}</td></tr>
      <tr><td>Cobrança por Pix pelo WhatsApp</td><td>—</td><td>${IC.check}</td></tr>
      <tr><td>Relatório do contador (Carnê-Leão)</td><td>—</td><td>${IC.check}</td></tr>
      <tr><td>Lembretes por WhatsApp e modelos de documentos</td><td>${IC.check}</td><td>${IC.check}</td></tr>
      <tr><td>Temas de cores</td><td>3</td><td><b>8</b></td></tr></tbody></table></div>
    ${on && p.origem !== 'teste' && p.tipo !== 'anualpix' ? '' : `<div class="planos">${PLANOS.map(x => `<button class="plano ${sel === x.id ? 'on' : ''}" onclick="S.planoSel='${x.id}';panePremium($('main'))">
      ${x.tag ? `<span class="pl-tag">${x.tag}</span>` : ''}<span class="pl-radio"></span><b>${x.nome}</b><span class="pl-preco">${x.preco}</span><small>${x.per}</small><small class="pl-obs">${x.obs}</small></button>`).join('')}</div>
    <div class="row-actions prem-act"><button class="pri big" onclick="assinar('${sel}')">${IC.crown} ${on && p.tipo === 'anualpix' && sel === 'anualpix' ? 'Renovar ' : on ? 'Trocar para ' : sel === 'anualpix' ? 'Comprar ' : 'Assinar '}${nomePlano(sel)} · ${(PLANOS.find(x => x.id === sel) || {}).preco}</button></div>`}
    <div class="row-actions prem-act">${on && p.origem === 'teste' ? `<button onclick="encerrarTeste()">Voltar ao plano grátis</button>` : ''}<button onclick="restaurarCompra()">Restaurar compra</button>${billingReal() ? `<button onclick="gerenciarAssinatura()">Gerenciar na Google Play</button>` : ''}</div>
    <p class="meta" style="text-align:center;margin-top:10px">Os planos Mensal e Anual renovam automaticamente pela Google Play e podem ser cancelados a qualquer momento. O Anual no Pix é um pagamento único: vale por 1 ano e o app avisa antes de vencer. Se o Premium acabar, nenhum dado é perdido: você continua vendo todos os prontuários.</p>`;
}
function assinar(id) {
  if (billingReal()) { try { AppsicoNative.billingBuy(BILL.produtos[id]); } catch (e) { toast('Não foi possível abrir a Google Play'); } return; }
  modal(`<div class="pw-top">${IC.crown}</div><h2 style="text-align:center">Modo de teste</h2>
    <p>A cobrança pela Google Play só funciona depois que o app for publicado na loja. Para você ver tudo funcionando agora, posso liberar o <b>Premium ${esc(nomePlano(id))} de teste por ${BILL.diasTeste} dias</b>, sem nenhuma cobrança.</p>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" onclick="ativarTeste('${id}')">Ativar teste grátis</button></div>`);
}
function ativarTeste(id) {
  DB.plano = { tipo: id, origem: 'teste', desde: today(), ate: addDias(today(), BILL.diasTeste) };
  save(); closeModal(); toast('Premium de teste ativado'); render();
}
function encerrarTeste() { confirmBox('Voltar ao plano grátis?', 'O Premium de teste será encerrado. Nenhum dado é apagado.', 'Voltar ao grátis', () => { delete DB.plano; save(); render(); toast('Plano grátis'); }); }
function restaurarCompra() {
  if (billingReal()) { try { AppsicoNative.billingRestore(); toast('Consultando a Google Play…'); } catch (e) { toast('Não foi possível consultar a Google Play'); } return; }
  toast('Disponível quando o app estiver na Google Play');
}
function gerenciarAssinatura() { if (window.AppsicoNative && AppsicoNative.openExternal) AppsicoNative.openExternal('https://play.google.com/store/account/subscriptions?package=br.com.appsico.app'); }
// Chamado pela parte nativa quando a Google Play confirmar uma compra ou assinatura ativa.
window.appsicoBilling = function (r) {
  if (!DB) return;
  const id = Object.keys(BILL.produtos).find(k => BILL.produtos[k] === r.produto);
  if (r.ativo && id) DB.plano = { tipo: id, origem: 'play', desde: today(), ate: r.ate || addDias(r.compra || today(), id === 'mensal' ? 31 : 365) };
  else if (DB.plano && DB.plano.origem === 'play') delete DB.plano;
  save(); render(); if (r.ativo) toast('Premium ativado. Obrigado!');
};

/* ---------- Lembretes de consulta pelo WhatsApp (um toque) ---------- */
const LEMB_PADRAO = 'Olá, {paciente}! Passando para lembrar da sua consulta {quando}, às {hora}. Você confirma sua presença? Responda SIM para confirmar ou me avise se precisar remarcar.\n\n{profissional}';
function quandoLembrete(d) {
  const t = today();
  if (d === t) return 'hoje';
  if (d === addDias(t, 1)) return 'amanhã';
  const x = new Date(d + 'T12:00'), wd = x.toLocaleDateString('pt-BR', { weekday: 'long' });
  return `${x.getDay() === 0 || x.getDay() === 6 ? 'no' : 'na'} ${wd}, ${fmtD(d).slice(0, 5)}`;
}
function lembreteMsg(a) {
  const p = pacById(a.pid), ag = p ? age(p.ident.nascimento) : null, resp = p && ((ag !== null && ag < 18) || p.ident.interditado) ? p.ident.responsaveis.find(r => r.nome) : null;
  const quem = resp ? `${primeiro(resp.nome)}` : primeiro(p ? p.ident.nome : '');
  let t = (DB.prof.lembrete || LEMB_PADRAO)
    .replace(/\{paciente\}/g, quem)
    .replace(/\{quando\}/g, quandoLembrete(a.data))
    .replace(/\{data\}/g, fmtD(a.data))
    .replace(/\{hora\}/g, a.hora)
    .replace(/\{profissional\}/g, [DB.prof.nome, DB.prof.crp ? 'CRP ' + DB.prof.crp : ''].filter(Boolean).join(' — '));
  if (resp) t = t.replace('da sua consulta', `da consulta de ${primeiro(p.ident.nome)}`);
  return t;
}
function lembreteUrl(a) { const p = pacById(a.pid); return `https://wa.me/${p ? waPhone(p) : ''}?text=${encodeURIComponent(lembreteMsg(a))}`; }
function marcaLembrete(id) { const a = agList().find(x => x.id === id); if (!a) return; a.lembrete = nowISO(); save(); setTimeout(() => { if ($('modal').classList.contains('show') && document.querySelector('.ag-view')) closeModal(); renderMain(); }, 600); }
const lembAtivos = d => agDia(d).filter(a => ['agendado', 'confirmado'].includes(a.status));
function lembreteAviso() {
  const am = addDias(today(), 1), pend = lembAtivos(am).filter(a => a.status === 'agendado' && !a.lembrete);
  if (!pend.length) return '';
  return `<button class="lemb-aviso" onclick="go('lembretes',{cur:null,lmDia:'${am}'})"><span class="la-ic">${IC.bell}</span>
    <span><b>${pend.length} lembrete${pend.length > 1 ? 's' : ''} para enviar</b><small>Consultas de amanhã ainda sem confirmação</small></span><span class="pb-go">Enviar</span></button>`;
}
function paneLembretes(m) {
  const d = S.lmDia || addDias(today(), 1), lista = lembAtivos(d);
  const env = lista.filter(a => a.lembrete).length, conf = lista.filter(a => a.status === 'confirmado').length;
  m.innerHTML = `<div class="head"><div><h1>Lembretes</h1><div class="meta">Confirme as consultas pelo WhatsApp em um toque</div></div>${sairBtn()}</div>
    <div class="card">
      <div class="day-head"><button class="sm" onclick="S.lmDia=addDias('${d}',-1);paneLembretes($('main'))" aria-label="Dia anterior">‹</button>
        <div><h3 style="margin:0">${diaLongo(d)}${d === today() ? ' · hoje' : d === addDias(today(), 1) ? ' · amanhã' : ''}</h3>
        <div class="meta">${lista.length ? `${lista.length} consulta(s) · ${env} lembrete(s) enviado(s) · ${conf} confirmada(s)` : 'Nenhuma consulta para lembrar neste dia'}</div></div>
        <button class="sm" onclick="S.lmDia=addDias('${d}',1);paneLembretes($('main'))" aria-label="Próximo dia">›</button></div>
      <div class="chips"><button class="${d === today() ? 'on' : ''}" onclick="S.lmDia=today();paneLembretes($('main'))">Hoje</button><button class="${d === addDias(today(), 1) ? 'on' : ''}" onclick="S.lmDia=addDias(today(),1);paneLembretes($('main'))">Amanhã</button></div>
      <div class="lemb-list">${lista.map(a => {
        const p = pacById(a.pid), tel = p ? waPhone(p) : '';
        const st = a.status === 'confirmado' ? '<span class="tag st-confirmado">Confirmado</span>' : a.lembrete ? '<span class="tag warn">Aguardando resposta</span>' : '<span class="tag">Lembrete não enviado</span>';
        return `<div class="lemb">${p ? avatarHTML(p, '', true) : ''}<div class="lb-info"><b>${esc(pNome(a))}</b><span>${a.hora} · ${durTxt(a.dur || 50)}</span>${st}</div>
          <div class="lb-act">${tel ? `<a class="btn wa-btn" href="${lembreteUrl(a)}" target="_blank" rel="noopener" onclick="marcaLembrete('${a.id}')">${WA_ICON}<span>${a.lembrete ? 'Reenviar' : 'Enviar'}</span></a>`
            : `<button class="sm" onclick="go('patient',{cur:'${a.pid}',tab:'ident'})">Cadastrar telefone</button>`}
          ${a.status !== 'confirmado' ? `<button class="sm ok-btn" onclick="agStatus('${a.id}','confirmado')">${IC.check}<span>Confirmou</span></button>` : ''}
          <button class="sm" onclick="agForm({id:'${a.id}'})">Remarcar</button></div></div>`;
      }).join('') || `<div class="empty-s">Não há consultas agendadas para ${quandoLembrete(d)}.</div>`}</div>
    </div>
    <details class="card acc"><summary><span class="acc-ic">${IC.file}</span><span class="acc-t"><b>Mensagem do lembrete</b><small>Personalize o texto enviado aos pacientes</small></span></summary><div class="acc-body">
      <textarea id="lmTxt" style="min-height:130px">${esc(DB.prof.lembrete || LEMB_PADRAO)}</textarea>
      <div class="meta" style="margin:6px 0 0">Use: <b>{paciente}</b> (primeiro nome), <b>{quando}</b> (hoje, amanhã ou o dia), <b>{data}</b>, <b>{hora}</b> e <b>{profissional}</b>. Para menores, o lembrete vai para o responsável.</div>
      ${lista[0] ? `<label style="margin-top:10px">Como vai ficar</label><div class="lemb-prev" id="lmPrev"></div>` : ''}
      <div class="row-actions"><button onclick="DB.prof.lembrete='';save();paneLembretes($('main'));toast('Mensagem padrão restaurada')">Restaurar padrão</button><button class="pri" id="lmSave">Salvar mensagem</button></div></div></details>
    <div class="note">Ao tocar em <b>Enviar</b>, o WhatsApp abre com a mensagem pronta; é só tocar em enviar. Quando o paciente responder, toque em <b>Confirmou</b>.</div>`;
  const prev = () => { if ($('lmPrev')) { const o = DB.prof.lembrete; DB.prof.lembrete = $('lmTxt').value; $('lmPrev').textContent = lembreteMsg(lista[0]); DB.prof.lembrete = o; } };
  $('lmTxt').oninput = prev; prev();
  $('lmSave').onclick = () => { DB.prof.lembrete = $('lmTxt').value.trim() === LEMB_PADRAO.trim() ? '' : $('lmTxt').value; save(); toast('Mensagem salva'); };
}

/* ---------- Modelos de documentos (Resolução CFP nº 06/2019) ---------- */
const SEC_RE = /^\d\. [A-ZÁÉÍÓÚÂÊÔÃÕÇ ]{4,}$/;
const MODELOS = {
  relatorio: { titulo: 'RELATÓRIO PSICOLÓGICO', nome: 'Relatório psicológico', desc: 'Comunica a atuação profissional em um processo de trabalho, com identificação, demanda, procedimento, análise e conclusão.' },
  parecer: { titulo: 'PARECER PSICOLÓGICO', nome: 'Parecer psicológico', desc: 'Responde a uma questão específica, com análise técnica fundamentada.' },
  acomp: { titulo: 'DECLARAÇÃO', nome: 'Declaração de acompanhamento', desc: 'Informa que o paciente está em acompanhamento, desde quando e com que frequência. Não inclui diagnóstico.' },
  encaminhamento: { titulo: 'ENCAMINHAMENTO', nome: 'Encaminhamento', desc: 'Carta para encaminhar o paciente a outro profissional ou serviço.' }
};
function sessInfo(p) {
  const ss = p.evolucao.filter(e => !/Falta/.test(e.tipo || '')).map(e => e.data).sort();
  let freq = 'a combinar';
  if (ss.length > 2) { const med = (new Date(ss[ss.length - 1]) - new Date(ss[0])) / 864e5 / (ss.length - 1); freq = med <= 9 ? 'semanal' : med <= 18 ? 'quinzenal' : med <= 35 ? 'mensal' : 'variável'; }
  const di = [p.demanda.dataInicio, ss[0]].filter(Boolean).sort()[0] || '';
  return { n: ss.length, ini: ss[0] || di, fim: ss[ss.length - 1] || '', freq, inicio: di };
}
function paneModelo(p) {
  const tipo = EM.modelo || 'relatorio';
  pane(`${!DB.prof.cidade ? `<div class="note warn">Complete a cidade do profissional em <a href="#" onclick="go('settings');return false">Configurações</a> para que apareça nos documentos.</div>` : ''}
    <div class="mod-pick">${Object.entries(MODELOS).map(([k, x]) => `<button class="${tipo === k ? 'on' : ''}" onclick="EM={kind:'modelo',modelo:'${k}',edited:false};paneModelo(P())"><b>${x.nome}</b><small>${x.desc}</small></button>`).join('')}</div>
    <div class="card"><h3>${MODELOS[tipo].nome}</h3><input type="hidden" id="mTipo" value="${tipo}"><div class="grid">
      <div class="c3"><label>Data de emissão</label><input type="date" id="mEm" value="${today()}" onchange="emText()"></div>
      <div class="c3"><label>Cidade</label><input id="mCid" value="${esc(DB.prof.cidade || '')}" oninput="emText()"></div>
      ${tipo === 'encaminhamento' ? `<div class="c6"><label>Para quem (profissional ou serviço)</label><input id="mDest" placeholder="Ex.: Dr(a). Fulano, psiquiatra" oninput="emText()"></div>
        <div class="c12"><label>Motivo do encaminhamento</label><input id="mMot" placeholder="Ex.: avaliação psiquiátrica" oninput="emText()"></div>`
      : `<div class="c6"><label>Solicitante / interessado</label><input id="mSol" value="${esc(p.ident.nome)}" oninput="emText()"></div>
        <div class="c12"><label>Finalidade</label><input id="mFin" placeholder="Ex.: atender solicitação da escola" oninput="emText()"></div>`}
      <div class="c12"><label>Texto do documento <span style="font-weight:400">(preenchido com os dados do prontuário; revise e complete o que está entre colchetes)</span></label><textarea id="aTxt" style="min-height:280px" oninput="EM.edited=true"></textarea></div>
    </div><div class="row-actions"><button onclick="EM.edited=false;emText()">Refazer texto</button><button class="pri" onclick="emitirModelo()">Gerar documento</button></div></div>
    <div class="note">Os modelos seguem a estrutura da Resolução CFP nº 06/2019. As anotações privadas nunca entram nos documentos. O documento emitido fica salvo em <b>6. Documentos</b>.</div>`);
  emText(true);
}
function emitirModelo() { const t = val('aTxt'); if (/\[[^\]]+\]/.test(t)) return confirmBox('Ainda há campos entre colchetes', 'O texto tem trechos como [descreva…] que ainda não foram completados. Deseja gerar assim mesmo?', 'Gerar assim mesmo', emitir); emitir(); }
function modeloTexto(p) {
  const tipo = val('mTipo'), nome = p.ident.nome || '[nome do paciente]', s = sessInfo(p), pr = DB.prof, mod = (p.demanda.modalidade || 'presencial').toLowerCase();
  const ag = age(p.ident.nascimento), ident = `${nome}${p.ident.cpf ? ', CPF ' + p.ident.cpf : ''}${p.ident.nascimento ? ', nascido(a) em ' + fmtD(p.ident.nascimento) : ''}`;
  const objs = (p.objetivos || []).map(o => o.texto || o.titulo || o.desc || '').filter(Boolean);
  const sig = 'Este documento é sigiloso, destina-se exclusivamente à finalidade acima e não deve ser utilizado para outros fins.';
  let t;
  if (tipo === 'relatorio') t = [
    '1. IDENTIFICAÇÃO',
    `Autor(a): ${pr.nome || '[nome]'}, Psicólogo(a), CRP ${pr.crp || '[CRP]'}.`,
    `Interessado(a): ${val('mSol') || nome}.`,
    `Assunto / finalidade: ${val('mFin') || '[finalidade do documento]'}.`,
    `Pessoa atendida: ${ident}.`,
    '2. DESCRIÇÃO DA DEMANDA',
    p.demanda.queixa ? p.demanda.queixa : '[Descreva o motivo da busca pelo atendimento e quem fez a solicitação.]',
    '3. PROCEDIMENTO',
    s.n ? `${s.n === 1 ? `Foi realizada 1 sessão de atendimento psicológico individual, na modalidade ${mod}, em ${fmtD(s.ini)}.` : `Foram realizadas ${s.n} sessões de atendimento psicológico individual, na modalidade ${mod}, entre ${fmtD(s.ini)} e ${fmtD(s.fim)}, com frequência ${s.freq}.`} [Cite os recursos técnicos e instrumentos utilizados e o referencial teórico que os fundamenta.]`
      : '[Informe o número de sessões, o período, a frequência e os recursos técnicos utilizados.]',
    '4. ANÁLISE',
    (objs.length ? `Objetivos do acompanhamento: ${objs.join('; ')}. ` : '') + '[Exponha de forma descritiva e fundamentada os dados colhidos e sua interpretação, restringindo-se ao que for necessário para a finalidade do documento.]',
    '5. CONCLUSÃO',
    `[Apresente a conclusão a partir da análise e, se for o caso, recomendações e encaminhamentos.] ${sig}`
  ];
  else if (tipo === 'parecer') t = [
    '1. IDENTIFICAÇÃO',
    `Parecerista: ${pr.nome || '[nome]'}, Psicólogo(a), CRP ${pr.crp || '[CRP]'}.`,
    `Solicitante: ${val('mSol') || nome}.`,
    `Assunto: ${val('mFin') || '[questão a ser respondida]'}.`,
    '2. DESCRIÇÃO DA DEMANDA',
    '[Apresente a questão que motivou o parecer e as informações relevantes recebidas.]',
    '3. ANÁLISE',
    '[Faça a análise técnica da questão, fundamentada na literatura e nas normas da profissão.]',
    '4. CONCLUSÃO',
    `[Apresente seu posicionamento técnico sobre a questão.] ${sig}`
  ];
  else if (tipo === 'acomp') t = [`Declaro, para os devidos fins${val('mFin') ? ' de ' + val('mFin') : ''}, que ${nome}${p.ident.cpf ? ', CPF ' + p.ident.cpf + ',' : ''} está em acompanhamento psicológico sob meus cuidados desde ${s.inicio ? fmtD(s.inicio) : '[data de início]'}, com frequência ${s.freq}, na modalidade ${mod}.`];
  else t = [
    `Ao(À) ${val('mDest') || '[profissional ou serviço]'},`,
    `Encaminho ${nome}${ag !== null ? ', ' + ag + ' anos' : ''}, em acompanhamento psicológico sob meus cuidados desde ${s.inicio ? fmtD(s.inicio) : '[data de início]'}, para ${val('mMot') || '[motivo do encaminhamento]'}.`,
    'Coloco-me à disposição para troca de informações que possam contribuir com o cuidado, respeitados o sigilo profissional e o consentimento do(a) paciente.',
    'Atenciosamente,'
  ];
  $('aTxt').value = t.join('\n');
}

/* ---------- Relatório para o contador / Carnê-Leão ---------- */
function relDados(mes) {
  const rec = [], desp = [];
  const pagador = p => { const ag = age(p.ident.nascimento), r = ((ag !== null && ag < 18) || p.ident.interditado) ? p.ident.responsaveis.find(x => x.nome) : null; return r ? { nome: r.nome, cpf: r.cpf || '' } : { nome: p.ident.nome || '', cpf: p.ident.cpf || '' }; };
  DB.patients.forEach(p => p.evolucao.forEach(e => { const d = e.pagoEm || e.data; if (e.pago && e.valor > 0 && d.startsWith(mes)) { const pg = pagador(p); rec.push({ d, ben: p.ident.nome || '', benCpf: p.ident.cpf || '', pag: pg.nome, pagCpf: pg.cpf, forma: e.forma || '', v: e.valor, ref: 'Sessão de ' + fmtD(e.data) }); } }));
  contas().forEach(c => { const d = c.pagoEm || c.venc; if (!c.pago || !d.startsWith(mes)) return;
    if (c.tipo === 'receber') { const p = c.pid ? pacById(c.pid) : null, pg = p ? pagador(p) : { nome: '', cpf: '' }; rec.push({ d, ben: p ? p.ident.nome : c.desc, benCpf: p ? p.ident.cpf || '' : '', pag: pg.nome, pagCpf: pg.cpf, forma: c.forma || '', v: c.valor, ref: c.desc }); }
    else desp.push({ d, desc: c.desc, cat: c.cat || '', v: c.valor }); });
  (DB.lancamentos || []).forEach(l => { if (!l.data.startsWith(mes)) return; if (l.tipo === 'saida') desp.push({ d: l.data, desc: l.descricao, cat: l.categoria || '', v: l.valor }); else rec.push({ d: l.data, ben: l.descricao, benCpf: '', pag: '', pagCpf: '', forma: '', v: l.valor, ref: l.categoria || '' }); });
  rec.sort((a, b) => a.d.localeCompare(b.d)); desp.sort((a, b) => a.d.localeCompare(b.d));
  const tr = rec.reduce((s, x) => s + x.v, 0), td = desp.reduce((s, x) => s + x.v, 0), formas = {};
  rec.forEach(x => { const f = x.forma || 'Não informada'; formas[f] = (formas[f] || 0) + x.v; });
  return { rec, desp, tr, td, formas, semCpf: rec.filter(x => x.pag && !x.pagCpf).length };
}
function paneRelatorio(m) {
  S.rcMes = S.rcMes || today().slice(0, 7);
  const mes = S.rcMes, r = relDados(mes);
  m.innerHTML = `<div class="head"><div><h1>Relatório do contador</h1><div class="meta">Recebimentos e despesas do mês, prontos para o Carnê-Leão</div></div>${sairBtn()}</div>
    ${finTabs()}
    <div class="mes-nav plain"><button onclick="S.rcMes=mesShift(S.rcMes,-1);paneRelatorio($('main'))" aria-label="Mês anterior">‹</button><span class="mes-lbl">${mesLabel(mes)}</span><button onclick="S.rcMes=mesShift(S.rcMes,1);paneRelatorio($('main'))" aria-label="Próximo mês">›</button></div>
    <div class="kpis"><div class="kpi k-rec"><span>Recebido no mês</span><b>${brl(r.tr)}</b></div><div class="kpi k-pag"><span>Despesas pagas</span><b>${brl(r.td)}</b></div><div class="kpi"><span>Resultado</span><b>${brl(r.tr - r.td)}</b></div></div>
    ${r.semCpf ? `<div class="note warn">${r.semCpf} recebimento(s) sem CPF do pagador. Para o Carnê-Leão, cadastre o CPF do paciente ou do responsável no prontuário.</div>` : ''}
    <div class="card"><h3>Recebimentos (${r.rec.length})</h3>${r.rec.length ? `<div class="tbl-wrap"><table class="list rel"><thead><tr><th>Data</th><th>Paciente</th><th>Pagador · CPF</th><th>Forma</th><th class="num">Valor</th></tr></thead><tbody>
      ${r.rec.map(x => `<tr><td>${fmtD(x.d).slice(0, 5)}</td><td>${esc(x.ben)}<small>${esc(x.ref)}</small></td><td>${esc(x.pag || '—')}<small>${x.pagCpf ? 'CPF ' + esc(x.pagCpf) : x.pag ? '<span class="falta">sem CPF</span>' : ''}</small></td><td>${esc(x.forma || '—')}</td><td class="num">${brl(x.v)}</td></tr>`).join('')}
      </tbody></table></div>
      <div class="formas">${Object.entries(r.formas).map(([f, v]) => `<span>${esc(f)}: <b>${brl(v)}</b></span>`).join('')}</div>` : '<div class="empty-s">Nenhum recebimento neste mês.</div>'}</div>
    <div class="card"><h3>Despesas pagas (${r.desp.length})</h3>${r.desp.length ? `<div class="tbl-wrap"><table class="list rel"><thead><tr><th>Data</th><th>Descrição</th><th>Categoria</th><th class="num">Valor</th></tr></thead><tbody>
      ${r.desp.map(x => `<tr><td>${fmtD(x.d).slice(0, 5)}</td><td>${esc(x.desc)}</td><td>${esc(x.cat || '—')}</td><td class="num">${brl(x.v)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty-s">Nenhuma despesa paga neste mês.</div>'}</div>
    <div class="row-actions" style="justify-content:flex-start"><button class="pri" onclick="relPDF()">${IC.file}<span>PDF para o contador</span></button><button onclick="relCSV()">Planilha (CSV)</button></div>
    <div class="note">Este relatório organiza seus recebimentos e despesas, mas não substitui a nota fiscal nem a orientação do seu contador. Confirme com ele quais despesas podem ser deduzidas no livro-caixa.</div>`;
}
async function relCSV() {
  const mes = S.rcMes, r = relDados(mes), q = s => '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"', n = v => v.toFixed(2).replace('.', ',');
  const rows = [['RECEBIMENTOS'], ['Data', 'Paciente (beneficiário)', 'CPF do paciente', 'Pagador (titular)', 'CPF do pagador', 'Referente a', 'Forma', 'Valor']];
  r.rec.forEach(x => rows.push([fmtD(x.d), x.ben, x.benCpf, x.pag, x.pagCpf, x.ref, x.forma, n(x.v)]));
  rows.push(['', '', '', '', '', '', 'Total', n(r.tr)], [], ['DESPESAS PAGAS'], ['Data', 'Descrição', 'Categoria', 'Valor']);
  r.desp.forEach(x => rows.push([fmtD(x.d), x.desc, x.cat, n(x.v)]));
  rows.push(['', '', 'Total', n(r.td)], [], ['', '', 'Resultado', n(r.tr - r.td)]);
  await deliverPDF(new Blob(['﻿' + rows.map(x => x.map(q).join(';')).join('\r\n')], { type: 'text/csv' }), `Appsico-contador-${mes}.csv`);
}
async function relPDF() {
  const mes = S.rcMes, r = relDados(mes), { jsPDF } = window.jspdf, doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'landscape' }), pr = DB.prof;
  const L = 14, R = 283; let y = 18, pg = 1;
  const head = () => { doc.setTextColor(21, 26, 51); doc.setFont('helvetica', 'bold'); doc.setFontSize(14); doc.text(`Relatório de recebimentos e despesas — ${mesLabel(mes)}`, L, y);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5); doc.setTextColor(90, 96, 128);
    doc.text([pr.nome, pr.crp ? 'CRP ' + pr.crp : '', pr.cpf ? 'CPF ' + pr.cpf : ''].filter(Boolean).join(' · '), L, y + 6); doc.text(`Gerado pelo Appsico em ${fmtD(today())}`, R, y + 6, { align: 'right' }); y += 14; };
  const brk = () => { if (y > 192) { doc.text(`Página ${pg}`, R, 203, { align: 'right' }); doc.addPage(); pg++; y = 18; } };
  const table = (cols, rows) => {
    const th = () => { doc.setFillColor(238, 241, 250); doc.rect(L, y - 4.5, R - L, 7, 'F'); doc.setFont('helvetica', 'bold'); doc.setFontSize(8.8); doc.setTextColor(60, 66, 100);
      cols.forEach(c => doc.text(c[0], c[2] === 'r' ? c[1] + c[3] : c[1], y, c[2] === 'r' ? { align: 'right' } : undefined)); y += 6.5; doc.setFont('helvetica', 'normal'); doc.setTextColor(21, 26, 51); };
    th();
    rows.forEach(rw => { if (y > 192) { brk(); th(); } rw.forEach((v, i) => { const c = cols[i]; const t = doc.splitTextToSize(String(v || ''), c[3] - 2)[0] || ''; doc.text(t, c[2] === 'r' ? c[1] + c[3] : c[1], y, c[2] === 'r' ? { align: 'right' } : undefined); });
      doc.setDrawColor(230, 232, 240); doc.line(L, y + 2, R, y + 2); y += 6.2; });
  };
  head();
  doc.setFont('helvetica', 'bold'); doc.setFontSize(11); doc.setTextColor(21, 26, 51); doc.text(`Recebimentos (${r.rec.length}) — total ${brl(r.tr)}`, L, y); y += 7;
  table([['Data', L, 'l', 18], ['Paciente (beneficiário)', L + 19, 'l', 52], ['CPF paciente', L + 72, 'l', 30], ['Pagador (titular)', L + 103, 'l', 50], ['CPF pagador', L + 154, 'l', 30], ['Referente a', L + 185, 'l', 36], ['Forma', L + 222, 'l', 26], ['Valor', L + 249, 'r', 20]],
    r.rec.map(x => [fmtD(x.d), x.ben, x.benCpf, x.pag, x.pagCpf, x.ref, x.forma, brl(x.v)]));
  y += 4; brk(); doc.setFontSize(9.5); doc.text('Por forma de pagamento: ' + (Object.entries(r.formas).map(([f, v]) => `${f} ${brl(v)}`).join(' · ') || '—'), L, y); y += 10; brk();
  doc.setFont('helvetica', 'bold'); doc.setFontSize(11); doc.text(`Despesas pagas (${r.desp.length}) — total ${brl(r.td)}`, L, y); y += 7;
  table([['Data', L, 'l', 18], ['Descrição', L + 19, 'l', 150], ['Categoria', L + 170, 'l', 70], ['Valor', L + 249, 'r', 20]], r.desp.map(x => [fmtD(x.d), x.desc, x.cat, brl(x.v)]));
  y += 6; brk(); doc.setFont('helvetica', 'bold'); doc.setFontSize(11.5); doc.text(`Resultado do mês: ${brl(r.tr - r.td)}`, L, y);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(8.5); doc.setTextColor(90, 96, 128); doc.text(`Página ${pg}`, R, 203, { align: 'right' });
  await deliverPDF(doc.output('blob'), `Appsico-contador-${mes}.pdf`);
}

/* ---------- Ajuda e suporte ---------- */
const FAQ = [
  ['Onde ficam os dados dos meus pacientes?', 'Neste aparelho, criptografados (AES-256) e protegidos pelo seu PIN. Com a conta na nuvem, eles vão para a sua conta já criptografados, para sincronizar celular e computador: ninguém, nem a equipe do Appsico, consegue ler seus prontuários.'],
  ['Esqueci meu PIN. E agora?', 'Na tela do PIN, toque em "Esqueci o PIN" e use o código de recuperação que você guardou ao criar o acesso. Sem o PIN e sem esse código, os dados não podem ser abertos, porque nem o Appsico tem a chave.'],
  ['Como faço backup?', 'Vá em Backup e toque em fazer backup. O arquivo é salvo criptografado na pasta "appsico" do seu Google Drive ou onde você escolher. Faça pelo menos uma vez por semana.'],
  ['Vou trocar de celular. Como levo meus dados?', 'Com a conta na nuvem, basta instalar o Appsico no celular novo e entrar com seu e-mail e senha. Sem conta, faça um backup no celular antigo e restaure no novo com o código de recuperação.'],
  ['Como confirmo as consultas pelo WhatsApp?', 'Em Lembretes, escolha o dia e toque em Enviar em cada paciente: o WhatsApp abre com a mensagem pronta. Quando ele responder, toque em Confirmou.'],
  ['O app segue as orientações do CFP?', 'O prontuário é organizado nas seções de registro documental orientadas pelo Conselho Federal de Psicologia, com anotações privadas separadas, e os modelos de documentos seguem a estrutura da Resolução CFP nº 06/2019. O conteúdo e a guarda dos registros continuam sendo responsabilidade do profissional.'],
  ['Como funciona a assinatura e como cancelo?', 'Toda conta nova tem 15 dias grátis com tudo liberado. Depois, o app funciona enquanto a assinatura estiver ativa. Sem assinatura, ele fica em modo consulta: você vê e exporta todos os prontuários, mas não registra nada novo, e nenhum dado é apagado. O app confere a assinatura pela internet pelo menos a cada 7 dias. Os planos Mensal e Anual são cobrados no cartão pelo Mercado Pago e podem ser cancelados a qualquer momento. O Anual no Pix é um pagamento único que vale 1 ano.'],
  ['Por que não consigo tirar print da tela?', 'Por sigilo: o Appsico bloqueia capturas de tela para que informações de pacientes não fiquem salvas na galeria nem apareçam na lista de apps recentes.']
];
const POLITICA = [
  ['Quem somos', 'O Appsico é um aplicativo de prontuário eletrônico para psicólogos. Nesta política, "você" é o(a) psicólogo(a) que usa o app.'],
  ['Prontuários criptografados', 'Cadastro profissional, prontuários, agenda, documentos e dados financeiros são criptografados no seu aparelho. Com a conta na nuvem, são enviados à sua conta só dessa forma (provedor Supabase), para sincronizar seus aparelhos. O Appsico não consegue ler, não vende e não compartilha esses dados.'],
  ['Backup', 'Os backups são criptografados antes de sair do aparelho e vão apenas para o local que você escolher, como o seu Google Drive. Sem o seu código de recuperação, o arquivo não pode ser aberto.'],
  ['Compartilhamentos', 'PDFs, cobranças Pix e lembretes só são enviados quando você toca em compartilhar, e seguem pelo aplicativo que você escolher (por exemplo, WhatsApp ou e-mail).'],
  ['Conta e assinatura', 'Para a conta, guardamos nome, CRP, e-mail e a situação da assinatura. Os pagamentos são processados pelo Mercado Pago; o Appsico não recebe dados de cartão nem dados de pacientes.'],
  ['Responsabilidade pelos dados dos pacientes', 'Pela Lei Geral de Proteção de Dados (LGPD), você é o controlador dos dados dos seus pacientes e responsável pelo sigilo e pela guarda dos registros, conforme as normas do CFP.'],
  ['Seus direitos e exclusão', 'Você pode exportar seus dados por backup e apagá-los a qualquer momento, excluindo pacientes ou desinstalando o app (sem backup, os dados apagados não podem ser recuperados).']
];
function paneAjuda(m) {
  const sp = CFG.suporte || {}, wa = String(sp.whatsapp || '').replace(/\D/g, ''), em = sp.email || '', v = CFG.versao || '';
  const waN = wa.length === 10 || wa.length === 11 ? '55' + wa : wa;
  const txt = encodeURIComponent(`Olá! Preciso de ajuda com o Appsico${v ? ' (versão ' + v + ')' : ''}.`);
  m.innerHTML = `<div class="head"><div><h1>Ajuda e suporte</h1><div class="meta">Dúvidas frequentes, contato e privacidade</div></div>${sairBtn()}</div>
    <div class="card"><h3>Fale com o suporte</h3>
      ${wa || em ? `<p class="meta" style="margin-top:-4px">Nunca envie dados de pacientes ao suporte.</p><div class="sup-btns">
        ${wa ? `<a class="btn wa-btn" href="https://wa.me/${waN}?text=${txt}" target="_blank" rel="noopener">${WA_ICON}<span>WhatsApp</span></a>` : ''}
        ${em ? `<a class="btn" href="mailto:${esc(em)}?subject=${encodeURIComponent('Suporte Appsico')}&body=${txt}">${IC.file}<span>${esc(em)}</span></a>` : ''}</div>`
      : `<div class="note">O contato do suporte ainda não foi configurado.</div>`}</div>
    <div class="card"><h3>Gostou do Appsico?</h3><p class="meta" style="margin-top:-4px">Sua avaliação na Google Play ajuda outros psicólogos a conhecer o app.</p>
      <div class="row-actions" style="justify-content:flex-start"><a class="btn" href="https://play.google.com/store/apps/details?id=br.com.appsico.app" target="_blank" rel="noopener">★ Avaliar na Google Play</a></div></div>
    <div class="card"><h3>Dúvidas frequentes</h3><div class="faq">${FAQ.map(([q, a]) => `<details><summary>${esc(q)}</summary><p>${esc(a)}</p></details>`).join('')}</div></div>
    <details class="card acc"><summary><span class="acc-ic">${IC.shield}</span><span class="acc-t"><b>Política de privacidade</b><small>Como o Appsico trata os seus dados</small></span></summary><div class="acc-body politica">
      ${POLITICA.map(([t, d]) => `<h4>${esc(t)}</h4><p>${esc(d)}</p>`).join('')}${em ? `<h4>Contato</h4><p>${esc(em)}</p>` : ''}</div></details>
    <p class="meta" style="text-align:center">Appsico${v ? ' · versão ' + esc(v) : ''} · seus dados ficam só neste aparelho</p>`;
}

/* ---------- Tela inicial (menu em ícones) ---------- */
const TILES = [
  ['plus', 'Novo paciente', 'newPatient()'],
  ['users', 'Pacientes', "go('home',{cur:null})"],
  ['cal', 'Agenda', "go('agenda',{cur:null,agModo:'mes'})"],
  ['cert', 'Atestado', "go('docs',{cur:null,docQ:'',docKind:'atestado'})"],
  ['receipt', 'Recibo', "go('docs',{cur:null,docQ:'',docKind:'recibo'})"],
  ['docs', 'Modelos de documentos', "go('docs',{cur:null,docQ:'',docKind:'modelos'})"],
  ['receber', 'Contas a receber', "go('fin',{cur:null,finTab:'receber'})", 'rec'],
  ['pagar', 'Contas a pagar', "go('fin',{cur:null,finTab:'pagar'})", 'pag'],
  ['calcash', 'Financeiro', "go('fin',{cur:null,finTab:'calendario'})"],
  ['bell', 'Lembretes', "go('lembretes',{cur:null})"],
  ['report', 'Relatório do contador', "go('fin',{cur:null,finTab:'relatorio'})"],
  ['gear', 'Configurações', "go('settings')"]
];
function paneInicio(m) {
  const h = new Date().getHours(), saud = h < 12 ? 'Bom dia' : h < 18 ? 'Boa tarde' : 'Boa noite';
  const hoje = today(), agHoje = agList().filter(a => a.data === hoje && a.status !== 'cancelado').sort((a, b) => a.hora.localeCompare(b.hora));
  const restam = agHoje.filter(a => a.hora >= horaAgora() && !['realizado', 'faltou'].includes(a.status)).length;
  const pg = proxGeral();
  const nome = String(DB.prof.nome || '').replace(/^(dra?\.?|psic\.?)\s+/i, '');
  m.innerHTML = `<div class="ini-head"><div><div class="meta">${diaLongo(hoje)}</div><h1>${saud}${nome ? ', ' + esc(primeiro(nome)) : ''}!</h1></div><div class="ini-top"><button class="help-btn" onclick="go('ajuda',{cur:null})" title="Ajuda e suporte" aria-label="Ajuda e suporte">?</button>${sairBtn(true)}</div></div>
    <div class="ini-resumo">
      <button class="ir" onclick="abrirAgendaHoje()"><span>Consultas hoje</span><b>${agHoje.length}</b><small>${restam ? `${restam} ainda por atender` : agHoje.length ? 'todas atendidas' : 'agenda livre'}</small></button>
      ${pg ? `<button class="ir prox-c" onclick="agView('${pg.id}')"><span>Próxima consulta</span><span class="pc-nome">${(() => { const pp = pacById(pg.pid); return pp ? avatarHTML(pp, '', true) : ''; })()}<b>${esc(pNome(pg))}</b></span><small>${quandoTxt(pg)}</small></button>`
           : `<button class="ir prox-c" onclick="agForm()"><span>Próxima consulta</span><b class="nada">Nenhuma agendada</b><small>toque para agendar</small></button>`}
    </div>
    ${lembreteAviso()}
    ${typeof cloudLinked === 'function' && cloudLinked() ? bannerNuvem() : premium() ? avisoVencimento() : bannerPlano()}
    <div class="tiles">${TILES.map(([ic, l, fn, cl]) => `<button class="tile ${cl || ''} ${!premium() && /fin\(|'fin'/.test(fn) ? 'locked' : ''}" onclick="${fn}"><span class="ti">${IC[ic]}</span><span class="tlbl">${l}</span></button>`).join('')}</div>
    ${agHoje.length ? `<div class="card" style="margin-top:16px"><h3>Agenda de hoje</h3><div class="contas">${agHoje.map(a => `<div class="conta" onclick="agView('${a.id}')" style="cursor:pointer"><div class="cdata"><b>${a.hora}</b><small style="color:var(--muted)">${durTxt(a.dur || 50)}</small></div><div class="cinfo"><b>${esc(pNome(a))}</b><span>${AG_ST[a.status]}</span></div></div>`).join('')}</div></div>` : ''}`;
}
function proxGeral() { const t = today(), h = horaAgora(); return agList().filter(a => !['cancelado', 'realizado', 'faltou'].includes(a.status) && (a.data > t || (a.data === t && a.hora >= h))).sort((a, b) => (a.data + a.hora).localeCompare(b.data + b.hora))[0]; }
function quandoTxt(a) {
  const t = today(), am = addDias(t, 1);
  const dia = a.data === t ? 'Hoje' : a.data === am ? 'Amanhã' : (() => { const x = new Date(a.data + 'T12:00').toLocaleDateString('pt-BR', { weekday: 'short', day: '2-digit', month: '2-digit' }).replace('.', ''); return x.charAt(0).toUpperCase() + x.slice(1); })();
  return `${dia}, ${fmtD(a.data)} às ${a.hora}`.replace(/^(Hoje|Amanhã), /, '$1 · ');
}
function abrirAgendaHoje() { go('agenda', { cur: null }); abrirDia(today()); }

/* ---------- Lista de pacientes ---------- */
function paneHome(m) {
  const q = S.q.toLowerCase();
  const ps = DB.patients.filter(p => (S.flt === 'todos' || p.status === S.flt) && (p.ident.nome || '').toLowerCase().includes(q))
    .sort((a, b) => (a.ident.nome || '').localeCompare(b.ident.nome || ''));
  const ativos = DB.patients.filter(p => p.status === 'ativo').length;
  m.innerHTML = `<div class="head"><div><h1>Pacientes</h1><div class="meta">${ativos} em atendimento · ${DB.patients.length} prontuário(s)</div></div>
      <div class="head-act"><button class="pri" onclick="newPatient()">+ Novo paciente</button>${sairBtn()}</div></div>
    <div class="toolbar"><input id="q" placeholder="Buscar paciente…" value="${esc(S.q)}">
      <select id="flt"><option value="ativo" ${S.flt === 'ativo' ? 'selected' : ''}>Em atendimento</option><option value="encerrado" ${S.flt === 'encerrado' ? 'selected' : ''}>Encerrados</option><option value="todos" ${S.flt === 'todos' ? 'selected' : ''}>Todos</option></select></div>
    ${ps.length ? `<div class="pcards">${ps.map(p => {
      const a = age(p.ident.nascimento), last = p.evolucao.length ? p.evolucao[p.evolucao.length - 1].data : null;
      const needResp = ((a !== null && a < 18) || p.ident.interditado) && !p.ident.responsaveis.some(r => r.nome);
      const ini = (p.ident.nome || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(s => s[0]).join('').toUpperCase();
      return `<div class="pcard" onclick="openP('${p.id}')">${avatarHTML(p)}<div style="flex:1;min-width:0">
        <b>${esc(p.ident.nome || '(sem nome)')}</b><span>${a !== null ? a + ' anos · ' : ''}${last ? 'última sessão ' + fmtD(last) : 'sem sessões'}</span>${(() => { const n = proxAg(p.id); return n ? `<span class="prox">${IC.cal} ${fmtD(n.data)} às ${n.hora}</span>` : ''; })()}</div>
        ${typeof pacienteBloqueado === 'function' && pacienteBloqueado(p.id) ? '<span class="tag warn">consulta</span>' : p.status === 'encerrado' ? '<span class="tag off">encerrado</span>' : needResp ? '<span class="tag warn">responsável</span>' : ''}
        <button class="pdel" title="Excluir paciente" aria-label="Excluir paciente" onclick="event.stopPropagation();delPatient('${p.id}')">${IC.trash}</button></div>`;
    }).join('')}</div>`
    : `<div class="empty"><img src="logo.png" alt=""><h2>${DB.patients.length ? 'Nenhum paciente encontrado' : 'Nenhum prontuário ainda'}</h2><p>${DB.patients.length ? 'Ajuste a busca ou o filtro.' : 'Crie o primeiro prontuário para começar.'}</p></div>`}`;
  $('q').oninput = e => { S.q = e.target.value; const pos = e.target.selectionStart; paneHome(m); $('q').focus(); $('q').setSelectionRange(pos, pos); };
  $('flt').onchange = e => { S.flt = e.target.value; paneHome(m); };
}
function blankPatient() {
  return { id: uid(), criadoEm: nowISO(), status: 'ativo', tipo: 'pessoa',
    ident: { nome: '', nascimento: '', cpf: '', endereco: '', cidade: '', uf: '', cep: '', telefone: '', email: '', profissao: '',
      interditado: false, responsaveis: [], instituicao: '', cnpj: '', contatoInstituicao: '', psicologo: DB.prof.nome, crp: DB.prof.crp },
    demanda: { queixa: '', historico: '', dataInicio: today(), modalidade: 'Presencial' },
    objetivos: [], diagnosticos: [], evolucao: [], encaminhamentos: [], encerramento: { data: '', motivo: '', descricao: '' },
    documentos: [], acessos: [], privado: [] };
}
function newPatient() { if (!podeNovoPaciente()) return paywall(typeof cloudLinked === 'function' && cloudLinked() ? 'gratis' : 'pacientes'); const p = blankPatient(); DB.patients.push(p); save(); go('patient', { cur: p.id, tab: 'ident' }); }
function openP(id) { go('patient', { cur: id, tab: 'painel' }); }

/* ---------- Painel do prontuário (ícones) e menu sobreposto ---------- */
const SEC_DESC = {
  ident: 'Dados pessoais, responsáveis e foto', demanda: 'Queixa inicial e histórico', objetivos: 'Metas de curto, médio e longo prazo',
  diagnostico: 'Avaliação e hipóteses diagnósticas', evolucao: 'Relatos técnicos de cada sessão', encaminhamentos: 'Encaminhamentos e encerramento',
  documentos: 'Laudos, relatórios e anexos', emitir: 'Emitir atestado e recibo', acesso: 'Pedidos de acesso e guarda', privado: 'Fora do prontuário oficial'
};
function secResumo(p, k) {
  const n = (x, s, pl) => x + ' ' + (x === 1 ? s : pl);
  switch (k) {
    case 'ident': return p.ident.nascimento && (p.ident.telefone || p.ident.responsaveis.some(r => r.telefone)) ? 'Completo' : 'Faltam dados';
    case 'demanda': return p.demanda.queixa ? 'Preenchida' : 'Pendente';
    case 'objetivos': { const o = p.objetivos.length, al = p.objetivos.filter(x => x.status === 'Alcançado').length; return o ? n(o, 'meta', 'metas') + (al ? ` · ${al} alcançada${al > 1 ? 's' : ''}` : '') : 'Nenhuma meta'; }
    case 'diagnostico': { const d = (p.diagnosticos || []).length; return d ? n(d, 'registro', 'registros') : 'Nenhum registro'; }
    case 'evolucao': { const e = p.evolucao.length; return e ? `${n(e, 'sessão', 'sessões')} · última ${fmtD(p.evolucao[e - 1].data).slice(0, 5)}` : 'Nenhuma sessão'; }
    case 'encaminhamentos': return p.status === 'encerrado' ? 'Atendimento encerrado' : p.encaminhamentos.length ? n(p.encaminhamentos.length, 'encaminhamento', 'encaminhamentos') : 'Nenhum';
    case 'documentos': return p.documentos.length ? n(p.documentos.length, 'documento', 'documentos') : 'Nenhum';
    case 'emitir': return 'Gerar PDF, imprimir, WhatsApp';
    case 'acesso': return p.acessos.length ? n(p.acessos.length, 'pedido', 'pedidos') : 'Nenhum pedido';
    case 'linha': { const n2 = eventosPaciente(p).length; return n2 + ' registro' + (n2 === 1 ? '' : 's') + ' com data e hora'; }
    case 'privado': return p.privado.length ? n(p.privado.length, 'anotação', 'anotações') : 'Nenhuma';
  }
  return '';
}
function secTiles(p, onclickFn) {
  const tile = ([k, l, ic]) => {
    const r = secResumo(p, k), alerta = /Pendente|Faltam/.test(r);
    return `<button class="sec-tile ${k === 'privado' ? 'priv' : ''} ${S.view === 'patient' && S.tab === k ? 'on' : ''}" onclick="${onclickFn(k)}">
      <span class="sec-ic">${IC[ic]}${/^\d/.test(l) ? `<i class="sec-n">${l[0]}</i>` : ''}</span><span class="sec-t"><b>${l.replace(/^\d+\.\s*/, '')}</b><small class="${alerta ? 'alerta' : ''}">${r}</small></span></button>`;
  };
  return `<div class="sec-lbl">Fluxo do atendimento</div><div class="sec-grid">${TABS.filter(t => /^\d/.test(t[1])).map(tile).join('')}</div>
    <div class="sec-lbl">Outros registros</div><div class="sec-grid">${TABS.filter(t => !/^\d/.test(t[1])).map(tile).join('')}</div>`;
}
/* ---------- Fluxo do atendimento ---------- */
function etapas(p) {
  const fim = p.status === 'encerrado';
  return [
    ['ident', 'Cadastro', !!(p.ident.nome && p.ident.nascimento && (p.ident.telefone || p.ident.responsaveis.some(r => r.telefone)))],
    ['demanda', 'Demanda', !!p.demanda.queixa],
    ['diagnostico', 'Avaliação', (p.diagnosticos || []).length > 0],
    ['objetivos', 'Plano', p.objetivos.length > 0],
    ['evolucao', 'Sessões', p.evolucao.length > 0, fim ? 'feito' : p.evolucao.length ? 'andamento' : ''],
    ['encaminhamentos', 'Alta', fim]
  ];
}
const DICA_ETAPA = {
  ident: ['Complete o cadastro', 'Data de nascimento, telefone e, para menores, o responsável.'],
  demanda: ['Registre a demanda', 'Motivo da busca, histórico e como foi o acolhimento.'],
  diagnostico: ['Faça a avaliação', 'Registre instrumentos, hipótese diagnóstica ou avaliação psicológica.'],
  objetivos: ['Defina o plano terapêutico', 'Metas de curto, médio e longo prazo pactuadas com o paciente.'],
  evolucao: ['Registre as sessões', 'Cada sessão fica salva com data, horário de início e fim.'],
  encaminhamentos: ['Encaminhamento e alta', 'Registre encaminhamentos e, ao final, o encerramento.']
};
function fluxoHTML(p) {
  if (typeof pacienteBloqueado === 'function' && pacienteBloqueado(p.id)) return `<div class="note warn" style="cursor:pointer" onclick="go('premium',{cur:null})"><b>Modo consulta.</b> Sem assinatura ativa, você pode ver e exportar este prontuário, mas não registrar nada novo. Toque aqui para assinar.</div>` + fluxoHTMLBase(p);
  return fluxoHTMLBase(p);
}
function fluxoHTMLBase(p) {
  const et = etapas(p), atual = et.find(e => !e[2] && e[0] !== 'encaminhamentos') || (p.status === 'encerrado' ? null : et.find(e => e[0] === 'evolucao'));
  const dica = atual ? DICA_ETAPA[atual[0]] : null;
  return `<div class="card fluxo"><div class="fx-steps">${et.map(([k, l, ok, st], i) => {
      const cls = ok ? (st === 'andamento' ? 'and' : 'ok') : atual && atual[0] === k ? 'cur' : '';
      return `<button class="fx ${cls}" onclick="go('patient',{tab:'${k}'})"><span class="fx-n">${ok && cls === 'ok' ? IC.check : i + 1}</span><span class="fx-l">${l}</span></button>`;
    }).join('<span class="fx-line"></span>')}</div>
    ${dica ? `<div class="fx-next"><div><small>Próximo passo</small><b>${dica[0]}</b><span>${dica[1]}</span></div><button class="pri" onclick="go('patient',{tab:'${atual[0]}'})">${atual[0] === 'evolucao' && p.evolucao.length ? 'Registrar sessão' : 'Abrir'}</button></div>`
      : `<div class="fx-next done"><div><small>Atendimento encerrado</small><b>Todas as etapas concluídas</b><span>O prontuário segue guardado pelo prazo de guarda.</span></div></div>`}</div>`;
}
/* ---------- Linha do tempo do atendimento ---------- */
function eventosPaciente(p) {
  const ev = [], hr = iso => iso ? new Date(iso).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }) : '';
  if (p.criadoEm) ev.push({ d: p.criadoEm.slice(0, 10), h: hr(p.criadoEm), k: 'ident', t: 'Cadastro do paciente', x: '' });
  if (p.demanda.dataInicio) ev.push({ d: p.demanda.dataInicio, h: '', k: 'demanda', t: 'Início do atendimento · ' + (p.demanda.modalidade || ''), x: p.demanda.queixa || '' });
  (p.diagnosticos || []).forEach(d => ev.push({ d: d.data, h: hr(d.criadoEm), k: 'diagnostico', t: d.tipo + (d.cid ? ' · CID ' + d.cid : ''), x: d.texto }));
  p.objetivos.forEach(o => ev.push({ d: o.data, h: '', k: 'objetivos', t: 'Meta (' + o.prazo.toLowerCase() + ') · ' + o.status, x: o.texto }));
  p.evolucao.forEach((e, i) => ev.push({ d: e.data, h: e.hora ? e.hora + (e.horaFim ? '–' + e.horaFim : '') : '', k: 'evolucao', t: (e.tipo || 'Sessão') + (e.num ? ' nº ' + e.num : ''), x: e.texto }));
  p.encaminhamentos.forEach(e => ev.push({ d: e.data, h: '', k: 'encaminhamentos', t: 'Encaminhamento · ' + e.destinatario, x: e.finalidade }));
  p.documentos.forEach(d => ev.push({ d: d.data, h: '', k: 'documentos', t: d.tipo || 'Documento', x: d.titulo || '' }));
  if (p.status === 'encerrado' && p.encerramento.data) ev.push({ d: p.encerramento.data, h: '', k: 'encaminhamentos', t: 'Encerramento · ' + (p.encerramento.motivo || ''), x: p.encerramento.descricao || '' });
  return ev.filter(e => e.d).sort((a, b) => (b.d + (b.h || '')).localeCompare(a.d + (a.h || '')));
}
function linhaHTML(p, lim) {
  const ev = eventosPaciente(p), lst = lim ? ev.slice(0, lim) : ev, ICK = { ident: 'id', demanda: 'chat', diagnostico: 'diag', objetivos: 'target', evolucao: 'trend', encaminhamentos: 'share', documentos: 'file' };
  if (!ev.length) return '<div class="empty-s">Nenhum registro ainda.</div>';
  return `<div class="tline">${lst.map(e => `<button class="tl-it k-${e.k}" onclick="go('patient',{tab:'${e.k}'})"><span class="tl-dot">${IC[ICK[e.k]]}</span>
    <span class="tl-body"><span class="tl-when">${fmtD(e.d)}${e.h ? ' · ' + e.h : ''}</span><b>${esc(e.t)}</b>${e.x ? `<span class="tl-x">${esc(e.x.length > 160 ? e.x.slice(0, 160) + '…' : e.x)}</span>` : ''}</span></button>`).join('')}</div>
    ${lim && ev.length > lim ? `<div style="text-align:center;margin-top:8px"><button class="sm" onclick="go('patient',{tab:'linha'})">Ver linha do tempo completa (${ev.length})</button></div>` : ''}`;
}
function paneLinha(p) {
  pane(`<div class="card"><h3>Linha do tempo do atendimento</h3><div class="meta" style="margin:-6px 0 12px">Do cadastro às sessões, do mais recente ao mais antigo. Toque num item para abrir a seção.</div>${linhaHTML(p)}</div>
    <div class="note">As anotações privadas não aparecem aqui.</div>`);
}
function painelPaciente(p) {
  return `<div class="pp-acoes">
      <button class="pri" onclick="go('patient',{tab:'evolucao'})">${IC.trend}<span>Registrar sessão</span></button>
      <button onclick="agForm({pid:'${p.id}'})">${IC.cal}<span>Agendar</span></button>
      <button onclick="showRecord()">${IC.book}<span>Prontuário completo</span></button></div>
    ${fluxoHTML(p)}
    ${secTiles(p, k => `go('patient',{tab:'${k}'})`)}
    <div class="card" style="margin-top:14px"><h3>Últimos registros</h3>${linhaHTML(p, 4)}</div>`;
}
function menuSecoes() {
  const p = P(); if (!p) return;
  modal(`<div class="doc-head"><h2 style="margin:0">Seções do prontuário</h2><button class="ghost" onclick="closeModal()">Fechar</button></div>
    <button class="sheet-painel" onclick="closeModal();go('patient',{tab:'painel'})">${IC.grid}<span>Voltar ao painel de ${esc(primeiro(p.ident.nome) || 'paciente')}</span></button>
    ${secTiles(p, k => `closeModal();go('patient',{tab:'${k}'})`)}`, 'sheet');
}

/* ---------- Avaliação e diagnóstico ---------- */
const TIPOS_DIAG = ['Hipótese diagnóstica', 'Diagnóstico', 'Avaliação psicológica', 'Reavaliação', 'Devolutiva da avaliação'];
function paneDiag(p) {
  const ds = p.diagnosticos || (p.diagnosticos = []);
  pane(`<div class="card"><h3>Novo registro</h3>
    <div class="note">Registre de forma técnica e fundamentada: instrumentos utilizados, dados observados e conclusões. Hipóteses ainda em construção podem ficar nas <i>Anotações privadas</i> até serem confirmadas. O CID só deve ser incluído quando necessário e com critério.</div>
    <div class="grid">
      <div class="c4"><label>Data</label><input type="date" id="dgDt" value="${today()}"></div>
      <div class="c5"><label>Tipo</label><select id="dgTp">${TIPOS_DIAG.map(t => `<option>${t}</option>`).join('')}</select></div>
      <div class="c3"><label>CID (opcional)</label><input id="dgCid" placeholder="Ex.: F41.1"></div>
      <div class="c12"><label>Instrumentos e procedimentos utilizados</label><input id="dgIns" placeholder="Ex.: entrevista clínica, BAI, BDI-II, observação"></div>
      <div class="c12"><label>Descrição técnica / conclusões</label><textarea id="dgTx" style="min-height:120px"></textarea></div></div>
    <div class="row-actions"><button class="pri" onclick="addDiag()">Registrar</button></div></div>
  <div class="card"><h3>Histórico</h3>
    <div class="note">Registros salvos não são editados nem apagados. Para corrigir, adicione uma <b>retificação</b>.</div>
    ${ds.length ? [...ds].reverse().map(d => `<div class="entry">
      <div class="top"><span><b>${fmtD(d.data)}</b> · ${esc(d.tipo)}${d.cid ? ` · <span class="tag">CID ${esc(d.cid)}</span>` : ''}</span><span>registrado ${fmtDT(d.criadoEm)}</span></div>
      ${d.instrumentos ? `<p><b style="font-size:12.5px;color:var(--muted)">Instrumentos:</b> ${esc(d.instrumentos)}</p>` : ''}
      <p>${esc(d.texto)}</p>
      ${(d.retificacoes || []).map(r => `<div class="addendum"><b>Retificação</b> em ${fmtDT(r.em)}: ${esc(r.texto)}</div>`).join('')}
      <div style="text-align:right"><button class="ghost sm" onclick="addRetif('${d.id}','diagnosticos')">+ retificação</button></div></div>`).join('') : '<div style="color:var(--muted);font-size:13px">Nenhum registro.</div>'}</div>`);
}
function addDiag() {
  const t = val('dgTx'); if (!t) return toast('Descreva a avaliação');
  const p = P(); (p.diagnosticos = p.diagnosticos || []).push({ id: uid(), data: val('dgDt'), tipo: val('dgTp'), cid: val('dgCid'), instrumentos: val('dgIns'), texto: t, criadoEm: nowISO(), retificacoes: [] });
  p.diagnosticos.sort((a, b) => a.data.localeCompare(b.data)); save(); toast('Registro salvo'); renderMain();
}

/* ---------- Prontuário ---------- */
let paneEl = null;
const pane = h => { paneEl.innerHTML = h; };
function panePatient(m, p) {
  const a = age(p.ident.nascimento), guarda = p.encerramento.data ? addYears(p.encerramento.data, 20) : null;
  const painel = S.tab === 'painel' || !TABS.find(t => t[0] === S.tab);
  if (painel) S.tab = 'painel';
  const tb = TABS.find(t => t[0] === S.tab);
  const head = `<div class="head"><div class="head-pac">${avatarHTML(p, 'lg', false, true)}<div><h1>${esc(p.ident.nome || 'Novo prontuário')}</h1>
      <div class="meta">${a !== null ? a + ' anos · ' : ''}Início ${fmtD(p.demanda.dataInicio)} · ${p.evolucao.length} sessão(ões) ·
      ${p.status === 'encerrado' ? `Encerrado em ${fmtD(p.encerramento.data)} · guarda até <b>${fmtD(guarda)}</b>` : 'Em atendimento'}</div></div></div>
      ${sairBtn('lista')}</div>`;
  if (painel) { m.innerHTML = head + painelPaciente(p); return; }
  m.innerHTML = head + `<div class="sec-bar">
      <button class="sec-voltar" onclick="go('patient',{tab:'painel'})" title="Painel do paciente">${IC.grid}<span>Painel</span></button>
      <button class="sec-atual ${S.tab === 'privado' ? 'priv' : ''}" onclick="menuSecoes()"><span class="sec-ic sm">${IC[tb[2]]}</span><b>${tb[1].replace(/^\d+\.\s*/, '')}</b><span class="sec-mais">Seções ▾</span></button></div>
    <div id="pane"></div>`;
  paneEl = $('pane');
  ({ ident: paneIdent, demanda: paneDemanda, objetivos: paneObj, diagnostico: paneDiag, evolucao: paneEvo, linha: paneLinha, encaminhamentos: paneEnc, documentos: paneDocs, emitir: paneEmitir, acesso: paneAcesso, privado: panePriv })[S.tab](p);
}
function bind(obj) { paneEl.querySelectorAll('[data-f]').forEach(el => { obj[el.dataset.f] = el.type === 'checkbox' ? el.checked : el.value.trim(); }); }
function fld(lbl, k, v, cls, type, extra) { return `<div class="${cls || 'c6'}"><label>${lbl}</label><input type="${type || 'text'}" data-f="${k}" value="${esc(v)}" ${extra || ''}></div>`; }

/* 1. Identificação */
function paneIdent(p) {
  const i = p.ident, a = age(i.nascimento), inst = p.tipo === 'instituicao', need = (a !== null && a < 18) || i.interditado;
  pane(`<div class="card"><h3>Foto</h3><div class="foto-row">${avatarHTML(p, 'xl', false, true)}
      <div class="foto-btns"><button onclick="pickPhoto('${p.id}')">${i.foto ? 'Trocar foto' : 'Adicionar foto'}</button>${i.foto ? `<button class="danger" onclick="removePhoto('${p.id}')">Remover</button>` : ''}
      <small>Toque na foto para ampliar. A imagem fica criptografada junto com o prontuário.</small></div></div></div>
    <div class="card"><h3>Tipo de atendimento</h3><div class="grid"><div class="c6"><select onchange="saveIdent(true);P().tipo=this.value;save();renderMain()">
      <option value="pessoa" ${!inst ? 'selected' : ''}>Paciente (pessoa física)</option><option value="instituicao" ${inst ? 'selected' : ''}>Instituição</option></select></div></div></div>
    ${inst ? `<div class="card"><h3>Instituição</h3><div class="grid">${fld('Razão social / nome', 'instituicao', i.instituicao, 'c8')}${fld('CNPJ', 'cnpj', i.cnpj, 'c4')}
      ${fld('Responsável / contato na instituição', 'contatoInstituicao', i.contatoInstituicao, 'c12')}</div></div>` : ''}
    <div class="card"><h3>${inst ? 'Pessoa atendida' : 'Dados do paciente'}</h3><div class="grid">
      ${fld('Nome completo *', 'nome', i.nome, 'c8')}
      <div class="c4"><label>Data de nascimento *</label><input type="date" data-f="nascimento" value="${esc(i.nascimento)}" onchange="$('idade').value=(age(this.value)??'')+' anos'"></div>
      <div class="c3"><label>Idade</label><input id="idade" disabled value="${a !== null ? a + ' anos' : ''}"></div>
      ${fld('CPF', 'cpf', i.cpf, 'c4', 'text', 'inputmode="numeric"')}${fld('Profissão', 'profissao', i.profissao, 'c5')}
      ${fld('Endereço completo *', 'endereco', i.endereco, 'c12')}
      ${fld('Cidade', 'cidade', i.cidade, 'c6')}${fld('UF', 'uf', i.uf, 'c2', 'text', 'maxlength=2')}${fld('CEP', 'cep', i.cep, 'c4', 'text', 'inputmode="numeric"')}
      ${fld('Telefone *', 'telefone', i.telefone, 'c6', 'tel')}${fld('E-mail', 'email', i.email, 'c6', 'email')}
      <div class="c12"><label class="check"><input type="checkbox" data-f="interditado" ${i.interditado ? 'checked' : ''}> Pessoa interditada / sob curatela</label></div></div></div>
    <div class="card"><h3>Responsáveis legais</h3>
      ${need ? `<div class="note warn">Obrigatório: ${a !== null && a < 18 ? 'paciente menor de 18 anos' : 'pessoa interditada'}. Cadastre ao menos um responsável legal.</div>` : '<div class="note">Obrigatório para crianças, adolescentes ou pessoas interditadas.</div>'}
      <div id="resps">${i.responsaveis.map((r, ix) => respRow(r, ix)).join('')}</div>
      <button class="ghost" onclick="saveIdent(true);P().ident.responsaveis.push({nome:'',parentesco:'',cpf:'',telefone:'',email:''});save();renderMain()">+ Adicionar responsável</button></div>
    <div class="card"><h3>Financeiro</h3><div class="grid">
      <div class="c4"><label>Valor da consulta (R$)</label><input data-f="valorSessao" inputmode="decimal" placeholder="150,00" value="${esc(i.valorSessao || '')}"></div>
      <div class="c8"><label>Observações de pagamento</label><input data-f="obsPagamento" placeholder="Ex.: paga por mês, convênio, Pix até o dia 10" value="${esc(i.obsPagamento || '')}"></div></div></div>
    <div class="card"><h3>Psicólogo(a) responsável</h3><div class="grid">${fld('Nome', 'psicologo', i.psicologo, 'c8')}${fld('CRP', 'crp', i.crp, 'c4')}</div></div>
    <div class="row-actions"><button class="danger" onclick="delPatient()">Excluir prontuário</button><button class="pri" onclick="saveIdent()">Salvar identificação</button></div>`);
}
function respRow(r, ix) {
  return `<div class="grid" style="margin-bottom:10px;padding-bottom:10px;border-bottom:1px dashed var(--line)" data-resp="${ix}">
    <div class="c4"><label>Nome</label><input data-r="nome" value="${esc(r.nome)}"></div>
    <div class="c3"><label>Parentesco</label><input data-r="parentesco" value="${esc(r.parentesco)}"></div>
    <div class="c3"><label>CPF</label><input data-r="cpf" value="${esc(r.cpf)}" inputmode="numeric"></div>
    <div class="c2"><label>&nbsp;</label><button class="danger sm" onclick="saveIdent(true);P().ident.responsaveis.splice(${ix},1);save();renderMain()">Remover</button></div>
    <div class="c6"><label>Telefone</label><input data-r="telefone" value="${esc(r.telefone)}" type="tel"></div>
    <div class="c6"><label>E-mail</label><input data-r="email" value="${esc(r.email)}" type="email"></div></div>`;
}
function saveIdent(silent) {
  const p = P(); bind(p.ident);
  p.ident.responsaveis = [...paneEl.querySelectorAll('[data-resp]')].map(row => { const o = {}; row.querySelectorAll('[data-r]').forEach(el => o[el.dataset.r] = el.value.trim()); return o; });
  save();
  if (!silent) {
    const a = age(p.ident.nascimento);
    toast(((a !== null && a < 18) || p.ident.interditado) && !p.ident.responsaveis.some(r => r.nome) ? 'Salvo — falta cadastrar o responsável legal.' : 'Identificação salva');
    render();
  }
}
function delPatient(id) {
  id = id || S.cur; const p = DB.patients.find(x => x.id === id); if (!p) return;
  const guarda = p.status === 'encerrado' && p.encerramento.data ? addYears(p.encerramento.data, 20) : null;
  modal(`<h2>Excluir paciente?</h2>
    <p style="margin-top:0">Você vai apagar <b>todo o prontuário de ${esc(p.ident.nome || '(sem nome)')}</b>: identificação, evolução, documentos, financeiro e anotações. Não é possível desfazer.</p>
    <div class="note warn">O CFP exige guardar o prontuário por no mínimo 20 anos após o encerramento${guarda ? ` — neste caso, até <b>${fmtD(guarda)}</b>` : ''}. Se precisar, exporte um backup antes.</div>
    <label for="delConf">Para confirmar, escreva <b>EXCLUIR</b></label>
    <input id="delConf" autocomplete="off" autocapitalize="characters" placeholder="EXCLUIR">
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="btn-del" id="delGo" disabled>Excluir definitivamente</button></div>`);
  $('delConf').oninput = e => { $('delGo').disabled = e.target.value.trim() !== 'EXCLUIR'; };
  $('delConf').focus();
  $('delGo').onclick = () => {
    if (val('delConf') !== 'EXCLUIR') return;
    DB.patients = DB.patients.filter(x => x.id !== id); DB.agenda = agList().filter(a => a.pid !== id); save(); closeModal(); toast('Paciente excluído'); go('home', { cur: null });
  };
}

/* 2. Demanda */
function paneDemanda(p) {
  const d = p.demanda;
  pane(`<div class="card"><div class="grid">
    <div class="c4"><label>Início do atendimento</label><input type="date" data-f="dataInicio" value="${esc(d.dataInicio)}"></div>
    <div class="c4"><label>Modalidade</label><select data-f="modalidade">${['Presencial', 'On-line', 'Híbrido'].map(o => `<option ${d.modalidade === o ? 'selected' : ''}>${o}</option>`).join('')}</select></div>
    <div class="c12"><label>Motivo da busca / queixa inicial</label><textarea data-f="queixa" placeholder="Queixa relatada pelo paciente, de forma sintética.">${esc(d.queixa)}</textarea></div>
    <div class="c12"><label>Breve histórico e contexto</label><textarea data-f="historico" style="min-height:130px" placeholder="Contexto que levou ao início do processo terapêutico.">${esc(d.historico)}</textarea></div>
  </div><div class="row-actions"><button class="pri" onclick="bind(P().demanda);save();toast('Demanda salva');render()">Salvar</button></div></div>`);
}

/* 3. Objetivos */
const PRAZOS = ['Curto prazo', 'Médio prazo', 'Longo prazo'];
function paneObj(p) {
  pane(`<div class="note">As metas devem ser alinhadas entre psicólogo(a) e paciente. Atualize o status conforme o processo avança.</div>
    ${PRAZOS.map(pr => { const os = p.objetivos.filter(o => o.prazo === pr); return `<div class="card"><h3>${pr}</h3>
      ${os.length ? os.map(o => `<div class="entry"><div class="top"><span>Definida em ${fmtD(o.data)} ${o.pactuado ? '· <span class="tag">pactuada com paciente</span>' : ''}</span>
        <select style="width:auto;padding:4px 8px" onchange="setObj('${o.id}',this.value)">${['Em andamento', 'Alcançado', 'Revisado', 'Suspenso'].map(s => `<option ${o.status === s ? 'selected' : ''}>${s}</option>`).join('')}</select></div>
        <p>${esc(o.texto)}</p><div style="text-align:right"><button class="ghost sm danger" onclick="delItem('objetivos','${o.id}')">remover</button></div></div>`).join('') : '<div style="color:var(--muted);font-size:13px">Nenhuma meta.</div>'}</div>`; }).join('')}
    <div class="card"><h3>Nova meta</h3><div class="grid">
      <div class="c4"><label>Prazo</label><select id="oPr">${PRAZOS.map(x => `<option>${x}</option>`).join('')}</select></div>
      <div class="c4"><label>Data</label><input type="date" id="oDt" value="${today()}"></div>
      <div class="c4"><label>&nbsp;</label><label class="check"><input type="checkbox" id="oPac" checked> Pactuada com o paciente</label></div>
      <div class="c12"><label>Meta</label><textarea id="oTx" style="min-height:60px"></textarea></div></div>
      <div class="row-actions"><button class="pri" onclick="addObj()">Adicionar meta</button></div></div>`);
}
function addObj() { const t = val('oTx'); if (!t) return toast('Descreva a meta'); P().objetivos.push({ id: uid(), prazo: val('oPr'), data: val('oDt'), pactuado: $('oPac').checked, texto: t, status: 'Em andamento' }); save(); renderMain(); }
function setObj(id, v) { P().objetivos.find(o => o.id === id).status = v; save(); }
function delItem(col, id) { confirmBox('Remover item?', 'Esta ação não pode ser desfeita.', 'Remover', () => { const p = P(); p[col] = p[col].filter(x => x.id !== id); save(); renderMain(); }); }

/* 4. Evolução */
function lintEvo(t) {
  const w = [];
  if ((t.match(/["“”]/g) || []).length >= 4 || /"[^"]{80,}"/.test(t) || /“[^”]{80,}”/.test(t)) w.push('Parece haver transcrição extensa da fala do paciente. Prefira um registro sintético e técnico.');
  if (/\b(acho que|parece que|talvez seja|provavelmente|suspeito|desconfio|preguiços[oa]|mentiros[oa]|manipulador[a]?|imoral|vergonhoso)\b/i.test(t)) w.push('Há termos que podem indicar impressão pessoal, hipótese prematura ou juízo de valor. Considere mover para as anotações privadas.');
  return w;
}
function paneEvo(p) {
  const pf = S.prefill && S.prefill.pid === p.id ? S.prefill : null;
  pane(`${pf ? `<div class="note">Registrando a consulta agendada para <b>${fmtD(pf.data)} às ${pf.hora}</b>. <a href="#" onclick="S.prefill=null;renderMain();return false">Cancelar</a></div>` : ''}<div class="card"><h3>Novo registro de sessão</h3>
    <div class="note">Registre de forma <b>sintética e técnica</b>: progresso, eventos marcantes, intercorrências e respostas às intervenções. Não transcreva falas na íntegra nem inclua impressões íntimas ou hipóteses prematuras — use as <i>Anotações privadas</i>.</div>
    <div class="grid">
      <div class="c3"><label>Data</label><input type="date" id="eDt" value="${pf ? pf.data : today()}"></div>
      <div class="c3"><label>Início</label><input type="time" id="eHi" value="${pf ? pf.hora : horaAgora()}" onchange="$('eHf').value=somaMin(this.value,50)"></div>
      <div class="c3"><label>Término</label><input type="time" id="eHf" value="${pf ? pf.horaFim : somaMin(horaAgora(), 50)}"></div>
      <div class="c3"><label>Sessão nº</label><input type="number" id="eN" value="${p.evolucao.length + 1}"></div>
      <div class="c4"><label>Tipo</label><select id="eTp" onchange="if(/Falta justificada/.test(this.value))$('eVal').value='0,00'">${['Sessão individual', 'Sessão com responsável', 'Sessão familiar', 'Avaliação', 'Devolutiva', 'Falta justificada', 'Falta não justificada', 'Contato extra'].map(o => `<option>${o}</option>`).join('')}</select></div>
      <div class="c3"><label>Modalidade</label><select id="eMd">${['Presencial', 'On-line'].map(o => `<option ${p.demanda.modalidade === o ? 'selected' : ''}>${o}</option>`).join('')}</select></div>
      <div class="c12"><label>Registro técnico da sessão</label><textarea id="eTx" style="min-height:120px" oninput="liveLint()"></textarea><div class="counter" id="eCnt">0 caracteres</div><div class="lint" id="eLint"></div></div>
      <div class="c6"><label>Intervenções / técnicas utilizadas</label><textarea id="eIv" style="min-height:60px"></textarea></div>
      <div class="c6"><label>Intercorrências (se houver)</label><textarea id="eIc" style="min-height:60px"></textarea></div>
      <div class="c3"><label>Valor da consulta (R$)</label><input id="eVal" inputmode="decimal" value="${esc(p.ident.valorSessao || '')}" placeholder="0,00"></div>
      <div class="c3"><label>Pagamento</label><select id="ePg"><option value="0">Pendente</option><option value="1">Pago</option></select></div>
      <div class="c3"><label>Forma</label><select id="eFm">${FORMAS.map(o => `<option>${o}</option>`).join('')}</select></div></div>
    <div class="note" style="margin:10px 0 0">A data e a hora em que o registro foi salvo são gravadas automaticamente.</div>
    <div class="row-actions"><button class="pri" onclick="addEvo()">Registrar sessão</button></div></div>
  <div class="card"><h3>Histórico de evolução</h3>
    <div class="note">Registros salvos não são editados nem apagados. Para corrigir ou complementar, adicione uma <b>retificação</b> — o texto original é preservado.</div>
    ${p.evolucao.length ? [...p.evolucao].reverse().map(e => `<div class="entry">
      <div class="top"><span><b>${fmtD(e.data)}${e.hora ? ' · ' + esc(e.hora) + (e.horaFim ? '–' + esc(e.horaFim) : '') : ''}</b> · Sessão ${esc(e.num)} · ${esc(e.tipo)} · ${esc(e.modalidade)}</span><span>registrado em ${fmtDT(e.criadoEm)}</span></div>
      <p>${esc(e.texto)}</p>
      ${e.intervencoes ? `<p><b style="font-size:12.5px;color:var(--muted)">Intervenções:</b> ${esc(e.intervencoes)}</p>` : ''}
      ${e.intercorrencias ? `<p><b style="font-size:12.5px;color:var(--warn)">Intercorrências:</b> ${esc(e.intercorrencias)}</p>` : ''}
      ${(e.retificacoes || []).map(r => `<div class="addendum"><b>Retificação</b> em ${fmtDT(r.em)}: ${esc(r.texto)}</div>`).join('')}
      <div class="ent-foot">${e.valor !== undefined ? `<span class="tag ${e.pago ? 'ok' : 'warn'}">${brl(e.valor || 0)} · ${e.pago ? 'pago' + (e.forma ? ' (' + esc(e.forma) + ')' : '') : 'pendente'}</span>${e.pago ? '' : `<button class="ghost sm" onclick="marcarPago('${p.id}','${e.id}');renderMain()">marcar como pago</button>${e.valor > 0 ? `<button class="pix-btn sm" onclick="cobrarSessao('${p.id}','${e.id}')">${PIX_ICON}Cobrar via Pix</button>` : ''}`}` : ''}
        <span style="flex:1"></span><button class="ghost sm" onclick="addRetif('${e.id}')">+ retificação</button></div></div>`).join('') : '<div style="color:var(--muted);font-size:13px">Nenhuma sessão registrada.</div>'}</div>`);
}
function liveLint() { const t = $('eTx').value; $('eCnt').textContent = t.length + ' caracteres'; $('eLint').innerHTML = lintEvo(t).map(w => '⚠ ' + w).join('<br>'); }
function addEvo() {
  const t = val('eTx'); if (!t) return toast('Escreva o registro da sessão');
  const doIt = () => { const p = P(), pago = val('ePg') === '1';
    if (S.prefill && S.prefill.pid === p.id) { const ag = agList().find(x => x.id === S.prefill.agId); if (ag) ag.status = 'realizado'; S.prefill = null; }
    p.evolucao.push({ id: uid(), data: val('eDt'), hora: val('eHi'), horaFim: val('eHf'), num: val('eN'), tipo: val('eTp'), modalidade: val('eMd'), texto: t, intervencoes: val('eIv'), intercorrencias: val('eIc'), criadoEm: nowISO(), retificacoes: [],
      valor: parseValor(val('eVal')), pago, forma: val('eFm'), pagoEm: pago ? today() : '' });
    p.evolucao.sort((a, b) => (a.data + (a.hora || '')).localeCompare(b.data + (b.hora || ''))); save(); toast('Sessão registrada'); render(); };
  const w = lintEvo(t); if (w.length) confirmBox('Revisar antes de salvar?', w.join(' '), 'Salvar mesmo assim', doIt); else doIt();
}
function addRetif(id, col) {
  col = col || 'evolucao';
  modal(`<h2>Retificação</h2><div class="note">O registro original permanece. A retificação fica datada logo abaixo dele.</div>
    <textarea id="rTx" style="min-height:100px"></textarea>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" id="rSave">Salvar retificação</button></div>`);
  $('rSave').onclick = () => { const t = val('rTx'); if (!t) return; const e = P()[col].find(x => x.id === id); (e.retificacoes = e.retificacoes || []).push({ em: nowISO(), texto: t }); save(); closeModal(); renderMain(); };
}

/* 5. Encaminhamentos e encerramento */
function paneEnc(p) {
  const en = p.encerramento, fechado = p.status === 'encerrado';
  pane(`<div class="card"><h3>Encaminhamentos</h3>
    ${p.encaminhamentos.length ? `<div class="tbl-wrap"><table class="list"><tr><th>Data</th><th>Destinatário</th><th>Finalidade</th><th>Retorno</th><th></th></tr>
      ${p.encaminhamentos.map(e => `<tr><td>${fmtD(e.data)}</td><td>${esc(e.destinatario)}</td><td>${esc(e.finalidade)}</td><td>${esc(e.retorno || '—')}</td><td><button class="ghost sm danger" onclick="delItem('encaminhamentos','${e.id}')">remover</button></td></tr>`).join('')}</table></div>` : '<div style="color:var(--muted);font-size:13px;margin-bottom:8px">Nenhum encaminhamento.</div>'}
    <div class="grid" style="margin-top:12px">
      <div class="c3"><label>Data</label><input type="date" id="kDt" value="${today()}"></div>
      <div class="c9"><label>Destinatário (profissional ou serviço)</label><input id="kDs" placeholder="Ex.: Dra. Ana Lima – Psiquiatra / CAPS Centro"></div>
      <div class="c8"><label>Finalidade</label><input id="kFn"></div>
      <div class="c4"><label>Retorno / contrarreferência</label><input id="kRt"></div></div>
    <div class="row-actions"><button class="pri" onclick="addEnc()">Adicionar encaminhamento</button></div></div>
  <div class="card"><h3>Encerramento do atendimento</h3>
    ${fechado ? `<div class="note">Atendimento encerrado em <b>${fmtD(en.data)}</b> (${esc(en.motivo)}). Guarda obrigatória até <b>${fmtD(addYears(en.data, 20))}</b>.</div>` : ''}
    <div class="grid">
      <div class="c4"><label>Data</label><input type="date" id="xDt" value="${esc(en.data || today())}"></div>
      <div class="c8"><label>Condição do encerramento</label><select id="xMt">${['Alta', 'Desistência', 'Interrupção', 'Encaminhamento', 'Óbito', 'Outro'].map(o => `<option ${en.motivo === o ? 'selected' : ''}>${o}</option>`).join('')}</select></div>
      <div class="c12"><label>Descrição das condições do encerramento</label><textarea id="xDs">${esc(en.descricao)}</textarea></div></div>
    <div class="row-actions">${fechado ? '<button onclick="reabrir()">Reabrir atendimento</button>' : ''}<button class="pri" onclick="encerrar()">${fechado ? 'Atualizar encerramento' : 'Encerrar atendimento'}</button></div></div>`);
}
function addEnc() { const d = val('kDs'), f = val('kFn'); if (!d || !f) return toast('Informe destinatário e finalidade'); P().encaminhamentos.push({ id: uid(), data: val('kDt'), destinatario: d, finalidade: f, retorno: val('kRt') }); save(); renderMain(); }
function encerrar() { const p = P(); p.encerramento = { data: val('xDt'), motivo: val('xMt'), descricao: val('xDs') }; p.status = 'encerrado'; save(); toast('Encerrado — guarda até ' + fmtD(addYears(p.encerramento.data, 20))); render(); }
function reabrir() { P().status = 'ativo'; save(); render(); }

/* 6. Documentos */
const TDOC = ['Relatório psicológico', 'Laudo psicológico', 'Declaração', 'Atestado psicológico', 'Parecer psicológico', 'Instrumento de avaliação', 'Outro'];
function paneDocs(p) {
  pane(`<div class="card"><div class="note">Guarde cópia de relatórios, laudos, declarações e atestados emitidos, e dos documentos resultantes de instrumentos de avaliação psicológica. Os arquivos ficam criptografados junto com o prontuário.</div>
    ${p.documentos.length ? `<div class="tbl-wrap"><table class="list"><tr><th>Data</th><th>Tipo</th><th>Título</th><th>Arquivo</th><th></th></tr>
      ${p.documentos.map(d => `<tr><td>${fmtD(d.data)}</td><td>${esc(d.tipo)}</td><td><b>${esc(d.titulo)}</b>${d.desc ? `<br><span style="color:var(--muted)">${esc(d.desc)}</span>` : ''}${d.instrumento ? `<br><span class="tag">${esc(d.instrumento)}</span>` : ''}</td>
        <td>${d.arquivo ? `<button class="ghost sm" onclick="openAttachment('${d.id}')">${esc(d.arquivo.nome)}</button>` : d.emitido ? `<button class="ghost sm" onclick="reopenEmitido('${d.id}')">Ver / PDF</button>` : '—'}</td>
        <td><button class="ghost sm danger" onclick="delItem('documentos','${d.id}')">remover</button></td></tr>`).join('')}</table></div>` : '<div style="color:var(--muted);font-size:13px">Nenhum documento.</div>'}</div>
  <div class="card"><h3>Adicionar documento</h3><div class="grid">
    <div class="c3"><label>Data</label><input type="date" id="dDt" value="${today()}"></div>
    <div class="c4"><label>Tipo</label><select id="dTp" onchange="$('dInsW').style.display=this.value==='Instrumento de avaliação'?'':'none'">${TDOC.map(o => `<option>${o}</option>`).join('')}</select></div>
    <div class="c5"><label>Título</label><input id="dTi"></div>
    <div class="c6" id="dInsW" style="display:none"><label>Instrumento aplicado</label><input id="dIns" placeholder="Nome do teste / escala"></div>
    <div class="c12"><label>Descrição / finalidade / destinatário</label><textarea id="dDs" style="min-height:60px"></textarea></div>
    <div class="c12"><label>Arquivo (PDF ou imagem, até 5 MB)</label><input type="file" id="dFl" accept=".pdf,image/*"></div></div>
    <div class="row-actions"><button class="pri" onclick="addDoc()">Adicionar documento</button></div></div>`);
}
function addDoc() {
  const t = val('dTi'); if (!t) return toast('Informe o título');
  const f = $('dFl').files[0];
  const push = arq => { P().documentos.push({ id: uid(), data: val('dDt'), tipo: val('dTp'), titulo: t, desc: val('dDs'), instrumento: val('dTp') === 'Instrumento de avaliação' ? val('dIns') : '', arquivo: arq }); save(); toast('Documento adicionado'); renderMain(); };
  if (!f) return push(null);
  if (f.size > 5 * 1024 * 1024) return toast('Arquivo acima de 5 MB');
  const r = new FileReader(); r.onload = () => push({ nome: f.name, tipo: f.type, data: r.result }); r.readAsDataURL(f);
}
let tempFiles = [];
async function openAttachment(id) {
  const d = P().documentos.find(x => x.id === id); if (!d || !d.arquivo) return;
  const b64 = d.arquivo.data.split(',')[1];
  if (NATIVE) {
    try {
      const name = d.arquivo.nome.replace(/[^\w.\-]/g, '_');
      const r = await FS.writeFile({ path: name, data: b64, directory: 'CACHE' });
      tempFiles.push(name);
      await SHARE.share({ title: d.titulo, url: r.uri, dialogTitle: 'Abrir documento' });
    } catch (e) { if (!/cancel/i.test(e.message || '')) toast('Não foi possível abrir: ' + e.message); }
    return;
  }
  const blob = new Blob([b64d(b64)], { type: d.arquivo.tipo || 'application/octet-stream' });
  window.open(URL.createObjectURL(blob), '_blank');
}
async function cleanTemp() { if (!NATIVE) return; for (const n of tempFiles) { try { await FS.deleteFile({ path: n, directory: 'CACHE' }); } catch (e) {} } tempFiles = []; }

/* Sigilo e acesso */
function paneAcesso(p) {
  pane(`<div class="card"><div class="note">O prontuário é sigiloso. O paciente (ou responsável legal) pode solicitar acesso ou cópia — idealmente por meio de devolutiva mediada pelo(a) psicólogo(a). Registre aqui cada solicitação.</div>
    ${p.acessos.length ? `<div class="tbl-wrap"><table class="list"><tr><th>Data</th><th>Solicitante</th><th>Tipo</th><th>Forma de atendimento</th></tr>
      ${p.acessos.map(a => `<tr><td>${fmtD(a.data)}</td><td>${esc(a.solicitante)}</td><td>${esc(a.tipo)}</td><td>${esc(a.forma)}</td></tr>`).join('')}</table></div>` : '<div style="color:var(--muted);font-size:13px">Nenhuma solicitação registrada.</div>'}
    <div class="grid" style="margin-top:12px">
      <div class="c3"><label>Data</label><input type="date" id="aDt" value="${today()}"></div>
      <div class="c4"><label>Solicitante</label><input id="aSo" placeholder="Paciente / responsável / órgão"></div>
      <div class="c5"><label>Tipo</label><select id="aTp"><option>Acesso para leitura</option><option>Cópia integral</option><option>Cópia parcial</option><option>Requisição judicial</option></select></div>
      <div class="c12"><label>Forma de atendimento</label><input id="aFm" placeholder="Ex.: devolutiva presencial mediada"></div></div>
    <div class="row-actions"><button class="pri" onclick="addAcesso()">Registrar solicitação</button></div></div>
  <div class="card"><h3>Guarda</h3><p style="margin:0">${p.status === 'encerrado' ? `Guarda obrigatória até <b>${fmtD(addYears(p.encerramento.data, 20))}</b> (20 anos após o encerramento em ${fmtD(p.encerramento.data)}).` : 'O prazo de guarda (mínimo de 20 anos) começa a contar a partir do encerramento do atendimento.'}</p></div>`);
}
function addAcesso() { const s = val('aSo'); if (!s) return toast('Informe o solicitante'); P().acessos.push({ id: uid(), data: val('aDt'), solicitante: s, tipo: val('aTp'), forma: val('aFm') }); save(); renderMain(); }

/* Anotações privadas */
function panePriv(p) {
  pane(`<div class="note priv"><b>Arquivo privado do profissional — não faz parte do prontuário oficial.</b> Use para rascunhos, hipóteses em construção e notas de supervisão. Estas anotações não aparecem no prontuário completo nem em cópias ao paciente.</div>
    <div class="card"><h3>Nova anotação</h3><div class="grid">
      <div class="c4"><label>Categoria</label><select id="vCt"><option>Rascunho</option><option>Hipótese em construção</option><option>Supervisão</option><option>Lembrete</option></select></div>
      <div class="c12"><label>Anotação</label><textarea id="vTx"></textarea></div></div>
      <div class="row-actions"><button class="pri" style="background:linear-gradient(135deg,#14bfa5,#2dd4bf)" onclick="addPriv()">Salvar anotação privada</button></div></div>
    ${[...p.privado].reverse().map(v => `<div class="entry"><div class="top"><span><b>${esc(v.cat)}</b> · ${fmtDT(v.em)}</span><button class="ghost sm danger" onclick="delItem('privado','${v.id}')">apagar</button></div><p>${esc(v.texto)}</p></div>`).join('')}`);
}
function addPriv() { const t = val('vTx'); if (!t) return; P().privado.push({ id: uid(), em: nowISO(), cat: val('vCt'), texto: t }); save(); renderMain(); }

/* Prontuário completo */
function recordHTML(p) {
  const i = p.ident, a = age(i.nascimento), row = (k, v) => v ? `<tr><td>${k}</td><td>${esc(v)}</td></tr>` : '';
  return `<div class="doc"><h3>Prontuário psicológico</h3><div style="color:var(--muted)">Documento sigiloso · gerado em ${fmtDT(nowISO())}</div>
  <h4>1. Cadastro e identificação</h4><table>
   ${p.tipo === 'instituicao' ? row('Instituição', i.instituicao) + row('CNPJ', i.cnpj) + row('Contato', i.contatoInstituicao) : ''}
   ${row('Nome', i.nome)}${row('Nascimento', i.nascimento ? fmtD(i.nascimento) + (a !== null ? ` (${a} anos)` : '') : '')}${row('CPF', i.cpf)}${row('Profissão', i.profissao)}
   ${row('Endereço', [i.endereco, i.cidade, i.uf, i.cep].filter(Boolean).join(', '))}${row('Telefone', i.telefone)}${row('E-mail', i.email)}
   ${i.interditado ? row('Condição', 'Pessoa interditada / sob curatela') : ''}
   ${i.responsaveis.filter(r => r.nome).map(r => row('Responsável legal', `${r.nome} (${r.parentesco || '—'}) · CPF ${r.cpf || '—'} · ${r.telefone || ''} ${r.email || ''}`)).join('')}
   ${row('Psicólogo(a) responsável', `${i.psicologo} — CRP ${i.crp}`)}</table>
  <h4>2. Demanda e acolhimento</h4><table>${row('Início', fmtD(p.demanda.dataInicio))}${row('Modalidade', p.demanda.modalidade)}${row('Queixa inicial', p.demanda.queixa)}${row('Histórico / contexto', p.demanda.historico)}</table>
  ${(p.diagnosticos || []).length ? `<h4>3. Avaliação psicológica e diagnóstico</h4>${p.diagnosticos.map(d => `<p><b>${fmtD(d.data)} — ${esc(d.tipo)}${d.cid ? ' (CID ' + esc(d.cid) + ')' : ''}</b>${d.instrumentos ? '<br><i>Instrumentos:</i> ' + esc(d.instrumentos) : ''}<br>${esc(d.texto)}${(d.retificacoes || []).map(r => `<br><i>Retificação (${fmtDT(r.em)}):</i> ${esc(r.texto)}`).join('')}</p>`).join('')}` : '<h4>3. Avaliação psicológica e diagnóstico</h4><p>—</p>'}
  <h4>4. Plano terapêutico — objetivos</h4>${p.objetivos.length ? `<table>${p.objetivos.map(o => row(o.prazo + ' · ' + fmtD(o.data), o.texto + ' [' + o.status + ']')).join('')}</table>` : '<p>—</p>'}
  <h4>5. Evolução — sessões</h4>${p.evolucao.length ? p.evolucao.map(e => `<p><b>${fmtD(e.data)}${e.hora ? ' às ' + esc(e.hora) + (e.horaFim ? '–' + esc(e.horaFim) : '') : ''} — Sessão ${esc(e.num)} (${esc(e.tipo)}, ${esc(e.modalidade)})</b><br>${esc(e.texto)}${e.intervencoes ? '<br><i>Intervenções:</i> ' + esc(e.intervencoes) : ''}${e.intercorrencias ? '<br><i>Intercorrências:</i> ' + esc(e.intercorrencias) : ''}${(e.retificacoes || []).map(r => `<br><i>Retificação (${fmtDT(r.em)}):</i> ${esc(r.texto)}`).join('')}</p>`).join('') : '<p>—</p>'}
  <h4>6. Encaminhamentos e encerramento</h4>${p.encaminhamentos.length ? `<table>${p.encaminhamentos.map(e => row(fmtD(e.data), `${e.destinatario} — ${e.finalidade}${e.retorno ? ' · retorno: ' + e.retorno : ''}`)).join('')}</table>` : '<p>Sem encaminhamentos.</p>'}
   ${p.status === 'encerrado' ? `<table>${row('Encerramento', fmtD(p.encerramento.data) + ' — ' + p.encerramento.motivo)}${row('Condições', p.encerramento.descricao)}${row('Guarda até', fmtD(addYears(p.encerramento.data, 20)))}</table>` : '<p>Atendimento em curso.</p>'}
  <h4>7. Documentos complementares</h4>${p.documentos.length ? `<table>${p.documentos.map(d => row(fmtD(d.data) + ' · ' + d.tipo, d.titulo + (d.instrumento ? ' (' + d.instrumento + ')' : '') + (d.desc ? ' — ' + d.desc : ''))).join('')}</table>` : '<p>—</p>'}
  <p style="margin-top:26px">_______________________________<br>${esc(i.psicologo)} — CRP ${esc(i.crp)}</p></div>`;
}
function showRecord() {
  const p = P(); if (!p) return; document.body.classList.remove('drawer');
  modal(`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:8px;flex-wrap:wrap"><span class="tag">Sem anotações privadas</span>
    <div style="display:flex;gap:6px;flex-wrap:wrap"><button id="recCopy">Copiar texto</button>${NATIVE ? '<button id="recShare">Compartilhar</button>' : ''}<button onclick="closeModal()">Fechar</button></div></div>
    <div id="recDoc">${recordHTML(p)}</div>`);
  $('recCopy').onclick = () => navigator.clipboard.writeText($('recDoc').innerText).then(() => toast('Prontuário copiado'), () => toast('Não foi possível copiar'));
  if (NATIVE) $('recShare').onclick = () => confirmBox('Compartilhar prontuário?', 'O texto sairá do Appsico sem criptografia. Envie apenas por canal seguro e ao destinatário autorizado.', 'Compartilhar',
    () => SHARE.share({ title: 'Prontuário — ' + (p.ident.nome || ''), text: $('recDoc') ? $('recDoc').innerText : '' }).catch(() => {}));
}

/* ---------- Configurações ---------- */
function paneSettings(m) {
  m.innerHTML = `<div class="head"><div><h1>Configurações</h1></div>${sairBtn()}</div>
  ${typeof contaCard === 'function' ? contaCard() : ''}
  <div class="card"><h3>Tema e cores</h3><div class="temas">${TEMAS.map(([k, n, d, side, grad, bg]) => `<label class="tema ${pref.get('theme', 'padrao') === k ? 'on' : ''} ${temaBloq(k) ? 'locked' : ''}"><input type="radio" name="theme" value="${k}" ${pref.get('theme', 'padrao') === k ? 'checked' : ''}>
      <span class="tprev" style="background:${bg}"><i class="ts" style="background:${side}"></i><i class="tb" style="background:${grad}"></i><i class="tl1"></i><i class="tl2"></i></span><b>${n}</b><small>${d}</small></label>`).join('')}</div></div>
  ${typeof cloudLinked === 'function' && cloudLinked() ? '' : `<details class="card acc"><summary><span class="acc-ic">${IC.crown}</span><span class="acc-t"><b>Meu plano</b><small>${esc(planoResumo())}</small></span></summary><div class="acc-body">${planoCard()}</div></details>`}
  <details class="card acc"><summary><span class="acc-ic">${IC.users}</span><span class="acc-t"><b>Perfil</b><small>Nome, CRP e e-mail de login</small></span></summary><div class="acc-body"><div class="grid">
    <div class="c8"><label>Nome completo</label><input id="sNm" value="${esc(DB.prof.nome)}"></div>
    <div class="c4"><label>CRP</label><input id="sCrp" value="${esc(DB.prof.crp)}"></div>
    <div class="c12"><label>E-mail de login</label><input value="${esc(V.email)}" disabled></div></div>
    <div class="row-actions"><button class="pri" id="sSave">Salvar</button></div></div></details>
  <details class="card acc"><summary><span class="acc-ic">${IC.cert}</span><span class="acc-t"><b>Dados para atestados e recibos</b><small>CPF, telefone, cidade e endereço do consultório</small></span></summary><div class="acc-body"><div class="grid">
    <div class="c4"><label>CPF do profissional</label><input id="sCpf" inputmode="numeric" value="${esc(DB.prof.cpf || '')}"></div>
    <div class="c4"><label>Telefone</label><input id="sTel" type="tel" value="${esc(DB.prof.telefone || '')}"></div>
    <div class="c4"><label>Cidade / UF</label><input id="sCid" placeholder="São Paulo/SP" value="${esc(DB.prof.cidade || '')}"></div>
    <div class="c12"><label>Endereço do consultório</label><input id="sEnd" value="${esc(DB.prof.endereco || '')}"></div></div>
    <div class="row-actions"><button class="pri" id="sDoc">Salvar</button></div></div></details>
  <details class="card acc"><summary><span class="acc-ic">${IC.cash}</span><span class="acc-t"><b>Pix para cobrança</b><small>Chave Pix, nome do recebedor e cidade</small></span></summary><div class="acc-body"><div class="grid">
    <div class="c4"><label>Tipo de chave</label><select id="pxTipo">${[['cpf', 'CPF / CNPJ'], ['cel', 'Celular'], ['email', 'E-mail'], ['aleatoria', 'Chave aleatória']].map(([v, l]) => `<option value="${v}" ${(DB.prof.pix || {}).tipo === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
    <div class="c8"><label>Chave Pix</label><input id="pxChave" value="${esc((DB.prof.pix || {}).chave || '')}" autocomplete="off"></div>
    <div class="c8"><label>Nome do recebedor (como no banco)</label><input id="pxNome" maxlength="25" value="${esc((DB.prof.pix || {}).nome || DB.prof.nome || '')}"></div>
    <div class="c4"><label>Cidade</label><input id="pxCid" maxlength="15" value="${esc((DB.prof.pix || {}).cidade || String(DB.prof.cidade || '').split('/')[0])}"></div></div>
    <div class="row-actions"><button class="pri" id="pxSave">Salvar Pix</button></div></div></details>
  <details class="card acc"><summary><span class="acc-ic">${IC.lock}</span><span class="acc-t"><b>Alterar PIN</b><small>Troque o PIN de 4 números</small></span></summary><div class="acc-body"><div class="grid">
    <div class="c4"><label>PIN atual</label><input id="sOld" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="off" class="pin"></div>
    <div class="c4"><label>Novo PIN</label><input id="sNew" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div>
    <div class="c4"><label>Confirmar</label><input id="sNew2" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" class="pin"></div></div>
    <div class="row-actions"><button class="pri" id="sPw">Alterar PIN</button></div></div></details>
  <details class="card acc"><summary><span class="acc-ic">${IC.users}</span><span class="acc-t"><b>Dados de demonstração</b><small>10 pacientes fictícios para conhecer o app</small></span></summary><div class="acc-body">
    <p style="margin:0 0 10px">Carrega 10 pacientes <b>fictícios</b> com cadastro, demanda, avaliação e diagnóstico, plano terapêutico, sessões com data e horário, agenda e pagamentos. Seus pacientes reais não são alterados.</p>
    <div class="row-actions" style="justify-content:flex-start">${DB.patients.some(p => p.demo) ? `<button class="danger" onclick="removerDemo()">Remover dados de demonstração</button>` : `<button class="pri" onclick="carregarDemo()">Carregar demonstração</button>`}</div></div></details>
  <details class="card acc"><summary><span class="acc-ic">${IC.shield}</span><span class="acc-t"><b>Segurança</b><small>Como seus dados são protegidos</small></span></summary><div class="acc-body">
    <p style="margin:0 0 8px">• Dados criptografados com AES-256 e guardados somente neste aparelho.<br>
    • Bloqueio automático após ${CFG.autoLockMinutes} min sem uso ou ${CFG.backgroundLockSeconds} s em segundo plano.<br>
    • Capturas de tela bloqueadas e app excluído do backup automático do Android.<br>
    • Redefinição do PIN por e-mail: ${(CFG.emailjs && CFG.emailjs.serviceId) ? 'ativa' : '<b>não configurada</b> (use o código de recuperação)'}.</p></div></details>
`;
  pwMeter('sNew', 'sBar');
  $('pxSave').onclick = () => {
    const pix = { tipo: val('pxTipo'), chave: val('pxChave'), nome: val('pxNome'), cidade: val('pxCid') };
    if (!pix.chave || !pix.nome || !pix.cidade) return toast('Preencha chave, nome e cidade');
    const c = pixChave(pix.tipo, pix.chave);
    if (pix.tipo === 'cpf' && !(c.length === 11 || c.length === 14)) return toast('CPF deve ter 11 números ou CNPJ 14');
    if (pix.tipo === 'cel' && !/^\+55\d{10,11}$/.test(c)) return toast('Celular inválido: use DDD + número');
    if (pix.tipo === 'email' && !emailOk(c)) return toast('E-mail inválido');
    DB.prof.pix = pix; save(); toast('Pix salvo');
  };
  $('sDoc').onclick = () => { Object.assign(DB.prof, { cpf: val('sCpf'), telefone: val('sTel'), cidade: val('sCid'), endereco: val('sEnd') }); save(); toast('Dados salvos'); };
  document.querySelectorAll('input[name=theme]').forEach(r => r.onchange = () => { if (temaBloq(r.value)) { r.checked = false; const at = document.querySelector(`input[name=theme][value="${pref.get('theme', 'padrao')}"]`); if (at) at.checked = true; return paywall('temas'); } pref.set('theme', r.value); applyTheme(); document.querySelectorAll('.tema').forEach(l => l.classList.toggle('on', l.querySelector('input').checked)); });
  $('sSave').onclick = () => { DB.prof.nome = val('sNm'); DB.prof.crp = val('sCrp'); save(); toast('Dados salvos'); renderSidebar(); };
  $('sPw').onclick = async () => {
    const nw = $('sNew').value, w = pwIssues(nw);
    if (w.length) return toast(w[0]);
    if (nw !== $('sNew2').value) return toast('Os PINs não conferem');
    busy($('sPw'), true, 'Verificando…');
    try { await openPw($('sOld').value, V.pw); } catch (e) { busy($('sPw'), false); return toast('PIN atual incorreto'); }
    await setNewPassword(nw); busy($('sPw'), false); ['sOld', 'sNew', 'sNew2'].forEach(i => $(i).value = ''); toast('PIN alterado');
  };
}

/* ---------- Backup ---------- */
function paneBackup(m) {
  const diasBk = V.lastBackupAt ? Math.floor((Date.now() - new Date(V.lastBackupAt)) / 864e5) : null;
  const bkAviso = diasBk === null || diasBk >= 7 ? `<div class="bk-banner">${DRIVE_ICON}<div><b>${diasBk === null ? 'Você ainda não fez backup' : `Último backup há ${diasBk} dias`}</b><span>Faça um backup criptografado no Google Drive para não perder os prontuários.</span></div></div>` : '';
  m.innerHTML = `<div class="head"><div><h1>Backup</h1><div class="meta">Último salvamento: ${fmtDT(V.updatedAt)}</div></div>${sairBtn()}</div>${bkAviso}
  <div class="note warn">Os prontuários existem somente neste celular. Se o aparelho for perdido, formatado ou o app for desinstalado, os dados se perdem. Exporte backups com frequência e guarde em local seguro.</div>
  <div class="card"><h3>${G_ICON_SM}Google Drive</h3><div id="driveCard"><div class="meta">Carregando…</div></div></div>
  <div class="card"><h3>Exportar backup criptografado</h3>
    <p style="margin-top:0">Gera um arquivo <b>.txt</b> criptografado, para guardar onde quiser. Para restaurá-lo (inclusive em outro celular) é preciso o <b>código de recuperação</b> de 20 caracteres.</p>
    <div class="row-actions" style="justify-content:flex-start"><button id="bExp">Salvar em outro lugar</button></div>
    <div class="meta" style="margin-top:8px">Último backup: <b>${V.lastBackupAt ? fmtDT(V.lastBackupAt) : 'nunca'}</b></div>
    <textarea id="bTxt" class="hidden" style="margin-top:10px;font-family:monospace;font-size:11px;min-height:120px" readonly></textarea></div>
  <div class="card"><h3>Restaurar backup</h3>
    <p style="margin-top:0">Substitui todos os dados deste aparelho pelos do backup. Para usar um backup do Google Drive, toque em "Escolher arquivo" e selecione <b>Drive</b> no menu do celular.</p>
    <input type="file" id="bFile" accept=".txt,.appsico,.json,text/plain,application/json">
    <div class="grid" style="margin-top:10px"><div class="c8"><label>Código de recuperação</label><input id="bPw" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" autocapitalize="characters" autocomplete="off" style="font-family:monospace"></div></div>
    <div class="row-actions" style="justify-content:flex-start"><button class="danger" id="bImp">Restaurar</button></div></div>`;
  $('bExp').onclick = () => exportBackup('');
  renderDriveCard();
  $('bImp').onclick = importBackup;
}
async function marcaBackup() { V.lastBackupAt = nowISO(); try { await writeVault(); } catch (e) {} }
async function exportBackup(dest) {
  await flush();
  const s = JSON.stringify(backupObj()), d = today().replace(/-/g, '');
  if (NATIVE) {
    try {
      const name = `Appsico-backup-${d}.txt`;
      const r = await FS.writeFile({ path: name, data: backupTxt(), directory: 'CACHE', encoding: 'utf8' });
      tempFiles.push(name);
      await SHARE.share({ title: 'Backup Appsico ' + fmtD(today()), url: r.uri, dialogTitle: 'Salvar backup', package: dest === 'drive' ? 'com.google.android.apps.docs' : '' });
      await marcaBackup(); toast(dest === 'drive' ? 'Confirme a pasta e toque em Salvar no Google Drive' : 'Backup gerado'); if (S.view === 'backup') paneBackup($('main'));
    } catch (e) { if (!/cancel/i.test(e.message || '')) toast('Falha ao exportar: ' + e.message); }
    return;
  }
  await marcaBackup();
  try { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([backupTxt()], { type: 'text/plain' })); a.download = `Appsico-backup-${d}.txt`; document.body.appendChild(a); a.click(); a.remove(); } catch (e) {}
  $('bTxt').value = backupTxt(); $('bTxt').classList.remove('hidden');
  if (dest === 'drive') { $('bTxt').insertAdjacentHTML('beforebegin', '<div class="note" style="margin-top:10px">Arquivo baixado. Agora abra o <a href="https://drive.google.com/drive/my-drive" target="_blank" rel="noopener">Google Drive</a> e arraste o arquivo <b>.appsico</b> para lá.</div>'); }
  else toast('Se o download não começar, copie o conteúdo exibido.');
}
function importBackup() {
  const f = $('bFile').files[0], secret = $('bPw').value;
  if (!f) return toast('Escolha o arquivo de backup');
  if (!secret) return toast('Informe o código de recuperação');
  const r = new FileReader();
  r.onload = () => {
    let nv; try { nv = parseBackup(r.result); } catch (e) { return toast('Arquivo de backup inválido'); }
    confirmTyped('Restaurar backup?', 'Todos os dados atuais deste aparelho serão substituídos pelos do backup. Não é possível desfazer.', 'Restaurar', async () => {
      let raw = null;
      try { raw = await openWith(normRec(secret), nv.rec); } catch (e) { raw = null; }
      if (!raw && nv.pw && nv.pw.kind !== 'pin6') { try { raw = await openWith(secret, nv.pw); } catch (e) { raw = null; } }
      if (!raw) return toast('Código de recuperação incorreto para este backup');
      const old = V; V = nv;
      try { await useDEK(raw); } catch (e) { V = old; return toast('Backup danificado'); }
      V.guard = { fails: 0, until: 0 }; delete V.pw;
      await Secure.set('dek', b64e(DEKraw));
      pref.set('lastEmail', V.email);
      showCreatePin('Backup restaurado. Crie o PIN deste aparelho. O e-mail de login passa a ser ' + V.email + '.');
    });
  };
  r.readAsText(f);
}

/* ---------- Google Drive (login + backup automático) ---------- */
const GCFG = () => CFG.google || {};
const gConfigurado = () => !!GCFG().clientId;
const GF = 'appsico', GN = 'appsico-backup.txt';
let gAccess = null, gExp = 0, oauthWait = null;
window.__appsicoOAuth = line => { if (oauthWait) { const w = oauthWait; oauthWait = null; w(line); } };
const b64url = u8 => b64e(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const form = o => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
async function gGetStore() { try { const s = await Secure.get('google'); return s ? JSON.parse(s) : null; } catch (e) { return null; } }
async function gSetStore(o) { await Secure.set('google', o ? JSON.stringify(o) : ''); }
function nativePost(url, body) {
  const r = String(window.AppsicoNative.httpPost(url, body)), i = r.indexOf('\n'), st = +r.slice(0, i), txt = r.slice(i + 1);
  let j = {}; try { j = JSON.parse(txt); } catch (e) {}
  if (st === 0) throw new Error('Sem conexão com a internet');
  if (st !== 200) { const e = new Error(j.error_description || j.error || ('Erro ' + st)); e.code = j.error; throw e; }
  return j;
}
async function gLogin() {
  if (!NATIVE || !window.AppsicoNative || !window.AppsicoNative.oauthStart) throw new Error('O login com Google funciona no app Android.');
  if (!gConfigurado()) throw new Error('O login com Google ainda não foi configurado neste app.');
  const N = window.AppsicoNative, port = N.oauthStart();
  if (!port) throw new Error('Não foi possível iniciar o login.');
  const redirect = 'http://127.0.0.1:' + port, verifier = b64url(rnd(48)), state = b64url(rnd(16));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(verifier))));
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + form({ client_id: GCFG().clientId, redirect_uri: redirect, response_type: 'code',
    scope: 'openid email https://www.googleapis.com/auth/drive.file', code_challenge: challenge, code_challenge_method: 'S256', state, access_type: 'offline', prompt: 'consent select_account' });
  const line = await new Promise(res => { oauthWait = res; N.openExternal(url); });
  if (line === 'ERROR') throw new Error('Tempo esgotado. Tente entrar de novo.');
  const path = String(line).split(' ')[1] || '', q = new URLSearchParams(path.split('?')[1] || '');
  if (q.get('error')) throw new Error(q.get('error') === 'access_denied' ? 'Login cancelado.' : 'Google: ' + q.get('error'));
  if (q.get('state') !== state || !q.get('code')) throw new Error('Resposta do Google inválida.');
  const t = nativePost('https://oauth2.googleapis.com/token', form({ client_id: GCFG().clientId, client_secret: GCFG().clientSecret || '', code: q.get('code'), code_verifier: verifier, grant_type: 'authorization_code', redirect_uri: redirect }));
  if (!t.refresh_token) throw new Error('O Google não liberou o acesso permanente. Tente de novo.');
  let email = ''; try { email = JSON.parse(atob(t.id_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).email || ''; } catch (e) {}
  await gSetStore({ refresh: t.refresh_token, email });
  gAccess = t.access_token; gExp = Date.now() + ((t.expires_in || 3600) - 60) * 1000;
  return email;
}
async function gLogout() {
  const g = await gGetStore();
  if (g && g.refresh && NATIVE) { try { nativePost('https://oauth2.googleapis.com/revoke', form({ token: g.refresh })); } catch (e) {} }
  await gSetStore(null); gAccess = null; gExp = 0;
}
async function gToken() {
  if (gAccess && Date.now() < gExp) return gAccess;
  const g = await gGetStore(); if (!g || !g.refresh) throw new Error('Entre com sua conta Google.');
  try {
    const t = nativePost('https://oauth2.googleapis.com/token', form({ client_id: GCFG().clientId, client_secret: GCFG().clientSecret || '', refresh_token: g.refresh, grant_type: 'refresh_token' }));
    gAccess = t.access_token; gExp = Date.now() + ((t.expires_in || 3600) - 60) * 1000; return gAccess;
  } catch (e) {
    if (e.code === 'invalid_grant') { await gSetStore(null); throw new Error('A conexão com o Google expirou. Entre de novo com sua conta.'); }
    throw e;
  }
}
async function gApi(url, opts) {
  opts = opts || {}; const tk = await gToken();
  const r = await fetch(url, Object.assign({}, opts, { headers: Object.assign({}, opts.headers || {}, { Authorization: 'Bearer ' + tk }) }));
  if (!r.ok) { const t = await r.text(); throw new Error('Google Drive respondeu ' + r.status + (t ? ': ' + t.slice(0, 120) : '')); }
  return r;
}
async function gFolder(create) {
  const q = encodeURIComponent(`mimeType='application/vnd.google-apps.folder' and name='${GF}' and trashed=false`);
  const j = await (await gApi(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id)&spaces=drive`)).json();
  if (j.files && j.files[0]) return j.files[0].id;
  if (!create) return null;
  return (await (await gApi('https://www.googleapis.com/drive/v3/files?fields=id', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: GF, mimeType: 'application/vnd.google-apps.folder' }) })).json()).id;
}
async function gFile(folder) {
  const q = encodeURIComponent(`name='${GN}' and '${folder}' in parents and trashed=false`);
  const j = await (await gApi(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,modifiedTime,size)&orderBy=modifiedTime desc`)).json();
  return (j.files && j.files[0]) || null;
}
// Arquivo .txt: 1ª linha de identificação + dados criptografados em base64 (sem nada legível)
function backupTxt() { return 'APPSICO-BACKUP-CRIPTOGRAFADO v1 - nao edite este arquivo\n' + b64e(te.encode(JSON.stringify(backupObj()))).replace(/(.{76})/g, '$1\n') + '\n'; }
function parseBackup(t) {
  t = String(t || '').trim();
  const o = t.startsWith('{') ? JSON.parse(t) : JSON.parse(td.decode(b64d(t.split('\n').slice(1).join('').replace(/\s/g, ''))));
  if (o.app !== 'appsico' || !o.rec || !o.data) throw new Error('Arquivo de backup inválido');
  return o;
}
async function gBackup() {
  await flush();
  const folder = await gFolder(true), f = await gFile(folder), content = backupTxt();
  if (f) await gApi(`https://www.googleapis.com/upload/drive/v3/files/${f.id}?uploadType=media`, { method: 'PATCH', headers: { 'Content-Type': 'text/plain; charset=UTF-8' }, body: content });
  else {
    const bd = 'appsico' + b64url(rnd(9)), meta = { name: GN, parents: [folder], mimeType: 'text/plain', description: 'Backup criptografado do Appsico. Restaure pelo app.' };
    const body = `--${bd}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(meta)}\r\n--${bd}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n${content}\r\n--${bd}--`;
    await gApi('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', { method: 'POST', headers: { 'Content-Type': 'multipart/related; boundary=' + bd }, body });
  }
  V.lastDriveBackup = nowISO(); await marcaBackup();
}
async function gDownload() {
  const folder = await gFolder(false); if (!folder) return null;
  const f = await gFile(folder); if (!f) return null;
  const txt = await (await gApi(`https://www.googleapis.com/drive/v3/files/${f.id}?alt=media`)).text();
  return { meta: f, bk: parseBackup(txt) };
}
const tamanho = b => { b = Number(b || 0); return b > 1048576 ? (b / 1048576).toFixed(1).replace('.', ',') + ' MB' : Math.max(1, Math.round(b / 1024)) + ' KB'; };

// ---- Drive pelo seletor do Android (usa a conta Google do celular) ----
let safWait = null;
window.__appsicoSaf = u => { if (safWait) { const w = safWait; safWait = null; w(u); } };
const temSaf = () => NATIVE && window.AppsicoNative && !!window.AppsicoNative.safCreate;
function safPick(kind) { return new Promise(res => { safWait = res; if (kind === 'create') window.AppsicoNative.safCreate(GN); else window.AppsicoNative.safOpen(); }); }
const ehDrive = u => /com\.google\.android\.apps\.docs/.test(u || '');
function guiaDrive(acao, cb) {
  modal(`<h2>${G_ICON_SM}Fazer login no Google Drive</h2>
    <p style="margin-top:0">Vai abrir o Google Drive com a conta Google deste celular. Só na primeira vez:</p>
    <ol class="guia">
      <li>Se não abrir direto no Drive, toque em <b>☰</b> e escolha <b>Drive</b> (sua conta Google).</li>
      <li>Abra a pasta <b>appsico</b>. Se ela não existir, crie com <b>+ / Nova pasta</b> e o nome <b>appsico</b>.</li>
      <li>${acao === 'create' ? 'Mantenha o nome <b>appsico-backup.txt</b> e toque em <b>Salvar</b>.' : 'Toque no arquivo <b>appsico-backup.txt</b>.'}</li>
    </ol>
    <div class="note">${acao === 'create' ? 'Depois disso, cada "Fazer backup" grava sozinho nesse arquivo, sem perguntar nada.' : 'O backup é lido do seu Drive e restaurado neste aparelho.'}</div>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="g-btn" id="guiaGo">${G_ICON}<span>Continuar</span></button></div>`);
  $('guiaGo').onclick = async () => { closeModal(); const u = await safPick(acao); if (u === 'CANCEL') return toast('Cancelado'); if (u === 'NOAPP') return toast('O seletor de arquivos não está disponível neste celular'); cb(u); };
}
async function safBackup() {
  await flush();
  const r = window.AppsicoNative.safWrite(V.saf.uri, backupTxt());
  if (r !== '1') throw new Error('Não foi possível gravar no Drive. Toque em "Trocar local" e escolha o arquivo de novo.');
  V.lastDriveBackup = nowISO(); await marcaBackup();
}
function lerSaf(uri) {
  const t = window.AppsicoNative.safRead(uri); if (t == null) return null;
  const bk = parseBackup(t); return { meta: { modifiedTime: bk.updatedAt, size: t.length }, bk };
}

async function driveConnect() {
  if (gConfigurado()) {
    try { const em = await gLogin(); toast('Conectado: ' + em); await gBackup(); toast('Backup salvo na pasta appsico do Drive'); } catch (e) { toast(e.message); }
    return renderDriveCard();
  }
  if (!temSaf()) return toast('O backup no Google Drive funciona no app Android.');
  guiaDrive('create', async u => {
    V.saf = { uri: u };
    try { await safBackup(); toast(ehDrive(u) ? 'Backup salvo no Google Drive' : 'Backup salvo (o local escolhido não é o Google Drive)'); }
    catch (e) { toast(e.message); }
    if (S.view === 'backup') paneBackup($('main'));
  });
}
async function renderDriveCard() {
  const el = $('driveCard'); if (!el) return;
  if (!NATIVE) { el.innerHTML = `<div class="note">O backup no Google Drive funciona no <b>app Android</b>.</div><button class="g-btn" disabled>${G_ICON}<span>Fazer login com Google</span></button>`; return; }
  const g = gConfigurado() ? await gGetStore() : null;
  const ult = `Último backup: <b>${V.lastDriveBackup ? fmtDT(V.lastDriveBackup) : 'nunca'}</b>`;
  if (g && g.refresh) {
    el.innerHTML = `<div class="g-acc">${G_ICON}<div><b>${esc(g.email || 'Conta Google')}</b><span>Pasta appsico · ${GN}<br>${ult}</span></div></div>
      <div class="row-actions" style="justify-content:flex-start"><button class="pri drive-btn" id="gBk">${DRIVE_ICON}Fazer backup</button><button id="gRs">Restaurar</button><button class="ghost danger" id="gOut">Sair da conta</button></div>`;
    $('gBk').onclick = async () => { busy($('gBk'), true, 'Enviando…'); try { await gBackup(); toast('Backup salvo na pasta appsico do Drive'); } catch (e) { toast(e.message); } paneBackup($('main')); };
    $('gRs').onclick = async () => { toast('Buscando backup no Google Drive…'); let r; try { r = await gDownload(); } catch (e) { return toast(e.message); } if (!r) return toast('Nenhum backup do Appsico encontrado no seu Drive.'); restoreModal(r); };
    $('gOut').onclick = () => confirmBox('Sair da conta Google?', 'Os backups já salvos continuam no seu Drive.', 'Sair', async () => { await gLogout(); renderDriveCard(); });
    return;
  }
  if (V.saf && V.saf.uri) {
    el.innerHTML = `<div class="g-acc">${G_ICON}<div><b>${ehDrive(V.saf.uri) ? 'Google Drive conectado' : 'Local de backup conectado'}</b><span>Pasta appsico · ${GN}<br>${ult}</span></div></div>
      <div class="row-actions" style="justify-content:flex-start"><button class="pri drive-btn" id="sBk">${DRIVE_ICON}Fazer backup</button><button id="sRs">Restaurar</button><button class="ghost" id="sTroca">Trocar local</button><button class="ghost danger" id="sOut">Desconectar</button></div>`;
    $('sBk').onclick = async () => { busy($('sBk'), true, 'Enviando…'); try { await safBackup(); toast('Backup salvo no Google Drive'); } catch (e) { toast(e.message); } paneBackup($('main')); };
    $('sRs').onclick = () => {
      let r = null; try { r = lerSaf(V.saf.uri); } catch (e) { r = null; }
      if (r) return restoreModal(r);
      guiaDrive('open', u => { let x; try { x = lerSaf(u); } catch (e) { x = null; } if (!x) return toast('Não foi possível ler esse arquivo de backup'); restoreModal(x); });
    };
    $('sTroca').onclick = () => driveConnect();
    $('sOut').onclick = () => confirmBox('Desconectar o Google Drive?', 'O arquivo de backup continua no seu Drive. Você pode conectar de novo quando quiser.', 'Desconectar', async () => { V.saf = null; await writeVault().catch(() => {}); renderDriveCard(); });
    return;
  }
  el.innerHTML = `<p style="margin-top:0">Entre com sua conta Google para salvar o backup criptografado na pasta <b>appsico</b> do seu Google Drive.</p>
    <button class="g-btn" id="gIn">${G_ICON}<span>Fazer login com Google</span></button>`;
  $('gIn').onclick = driveConnect;
}
function restoreModal(r) {
  let mesmo = false; try { if (DEK) { const k = r.bk.rec && V.rec && r.bk.rec.ct === V.rec.ct; mesmo = !!k; } } catch (e) {}
  modal(`<h2>Restaurar backup</h2>
    <p style="margin-top:0">Backup de <b>${r.meta.modifiedTime ? fmtDT(r.meta.modifiedTime) : 'data desconhecida'}</b> (${tamanho(r.meta.size)}).</p>
    <div class="note warn">Todos os dados atuais deste aparelho serão <b>substituídos</b> pelos do backup. Não é possível desfazer.</div>
    ${mesmo ? '' : `<label>Código de recuperação do backup</label><input id="rsRec" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" autocapitalize="characters" autocomplete="off" style="font-family:monospace;margin-bottom:10px">`}
    <label for="rsConf">Para confirmar, escreva <b>Restaurar</b></label>
    <input id="rsConf" autocomplete="off" placeholder="Restaurar">
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="btn-del" id="rsGo" disabled>Restaurar agora</button></div>`);
  $('rsConf').oninput = e => { $('rsGo').disabled = e.target.value.trim().toLowerCase() !== 'restaurar'; };
  $('rsGo').onclick = async () => {
    if (val('rsConf').toLowerCase() !== 'restaurar') return;
    busy($('rsGo'), true, 'Restaurando…');
    try {
      if (mesmo) {
        const novo = JSON.parse(td.decode(await unseal(DEK, r.bk.data)));
        V.data = r.bk.data; DB = novo; await persist();
        closeModal(); toast('Backup restaurado'); go('home', { cur: null });
      } else {
        let raw; try { raw = await openWith(normRec(val('rsRec')), r.bk.rec); } catch (e) { busy($('rsGo'), false); return toast('Código de recuperação incorreto'); }
        const saf = V && V.saf; V = r.bk; await useDEK(raw); delete V.pw; V.guard = { fails: 0, until: 0 }; V.saf = saf; V.lastDriveBackup = r.meta.modifiedTime;
        await Secure.set('dek', b64e(DEKraw)); pref.set('lastEmail', V.email); closeModal();
        showCreatePin('Backup restaurado. Crie o PIN deste aparelho. O e-mail de login passa a ser ' + V.email + '.');
      }
    } catch (e) { busy($('rsGo'), false); toast('Falha ao restaurar: ' + e.message); }
  };
}
// Celular novo: restaurar a partir da tela de primeiro acesso
function showSetupRestore() {
  authScreen(`<h2>Restaurar do Google Drive</h2><div class="sub">Entre com a conta Google onde está o backup do Appsico (pasta <b>appsico</b>).</div>
    <div id="srBody"><button class="g-btn" id="srIn" style="width:100%">${G_ICON}<span>Fazer login com Google</span></button></div>
    <div class="err" id="srErr"></div><div class="links"><a id="srBack">Voltar</a></div>`);
  $('srBack').onclick = showSetup;
  const err = m => $('srErr').textContent = m;
  const pedir = (r, uri) => {
    $('srBody').innerHTML = `<div class="note">Backup de <b>${r.meta.modifiedTime ? fmtDT(r.meta.modifiedTime) : '—'}</b> (${tamanho(r.meta.size)}) — conta ${esc(r.bk.email)}.</div>
      <div class="f"><label>Código de recuperação</label><input id="srRec" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" autocapitalize="characters" autocomplete="off" style="font-family:monospace"></div>
      <div class="f"><label>Para confirmar, escreva <b>Restaurar</b></label><input id="srConf" autocomplete="off" placeholder="Restaurar"></div>
      <button class="pri" id="srGo" disabled>Restaurar</button>`;
    $('srConf').oninput = e => { $('srGo').disabled = e.target.value.trim().toLowerCase() !== 'restaurar'; };
    $('srGo').onclick = async () => {
      busy($('srGo'), true, 'Restaurando…');
      let raw; try { raw = await openWith(normRec(val('srRec')), r.bk.rec); } catch (e) { busy($('srGo'), false); return err('Código de recuperação incorreto.'); }
      V = r.bk; await useDEK(raw); delete V.pw; V.guard = { fails: 0, until: 0 }; V.lastDriveBackup = r.meta.modifiedTime; if (uri) V.saf = { uri };
      await Secure.set('dek', b64e(DEKraw)); pref.set('lastEmail', V.email);
      showCreatePin('Backup restaurado. Crie o PIN deste aparelho. O e-mail de login é ' + V.email + '.');
    };
  };
  $('srIn').onclick = async () => {
    if (gConfigurado()) {
      busy($('srIn'), true, 'Abrindo o Google…');
      let r; try { await gLogin(); r = await gDownload(); } catch (e) { busy($('srIn'), false); return err(e.message); }
      if (!r) { busy($('srIn'), false); return err('Nenhum backup do Appsico encontrado nesta conta.'); }
      return pedir(r);
    }
    if (!temSaf()) return err('Disponível no app Android.');
    guiaDrive('open', u => { let r; try { r = lerSaf(u); } catch (e) { r = null; } if (!r) return err('Não foi possível ler esse arquivo de backup.'); pedir(r, u); });
  };
}

const G_ICON = '<svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.6 12.3c0-.8-.1-1.5-.2-2.3H12v4.3h6c-.3 1.4-1.1 2.5-2.2 3.3v2.8h3.6c2-1.9 3.2-4.7 3.2-8.1z"/><path fill="#34A853" d="M12 23c3 0 5.5-1 7.4-2.7l-3.6-2.8c-1 .7-2.3 1.1-3.8 1.1-2.9 0-5.4-2-6.3-4.6H2v2.9C3.9 20.6 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.7 14c-.2-.7-.4-1.4-.4-2s.1-1.4.4-2V7.1H2C1.4 8.6 1 10.2 1 12s.4 3.4 1 4.9L5.7 14z"/><path fill="#EA4335" d="M12 5.4c1.6 0 3.1.6 4.3 1.7l3.2-3.2C17.5 2.1 15 1 12 1 7.7 1 3.9 3.4 2 7.1L5.7 10c.9-2.7 3.4-4.6 6.3-4.6z"/></svg>';

/* ---------- Agenda ---------- */
const AG_ST = { agendado: 'Agendado', confirmado: 'Confirmado', realizado: 'Realizado', faltou: 'Faltou', cancelado: 'Cancelado' };
const DIAS = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
const agList = () => DB.agenda || (DB.agenda = []);
const toMin = h => { const [a, b] = String(h || '0:0').split(':').map(Number); return a * 60 + (b || 0); };
const minToH = m => pad2(Math.floor(m / 60) % 24) + ':' + pad2(m % 60);
const pacById = id => DB.patients.find(p => p.id === id);
const pNome = a => { const p = pacById(a.pid); return p ? (p.ident.nome || '(sem nome)') : '(paciente excluído)'; };
const primeiro = n => String(n || '').split(' ')[0];
const agDia = d => agList().filter(a => a.data === d).sort((a, b) => a.hora.localeCompare(b.hora));
const addDias = (d, k) => { const x = new Date(d + 'T12:00'); x.setDate(x.getDate() + k); return x.toISOString().slice(0, 10); };
const diaLongo = d => { const t = new Date(d + 'T12:00').toLocaleDateString('pt-BR', { weekday: 'long', day: 'numeric', month: 'long' }); return t.charAt(0).toUpperCase() + t.slice(1); };
const durTxt = m => (m >= 60 ? Math.floor(m / 60) + 'h' + (m % 60 ? pad2(m % 60) : '') : m + ' min');

function abrirDia(d) { S.agDia = d; S.agMes = d.slice(0, 7); S.agModo = 'dia'; renderSidebar(); paneAgenda($('main')); window.scrollTo(0, 0); }
function paneAgendaDia(m) {
  const d = S.agDia, doDia = agDia(d).filter(a => a.status !== 'cancelado'), ocup = doDia.reduce((s, a) => s + (a.dur || 50), 0);
  m.innerHTML = `<div class="head"><div><button class="voltar" onclick="S.agModo='mes';paneAgenda($('main'))">‹ ${mesLabel(S.agMes)}</button><h1>Agenda do dia</h1></div>
      <div class="head-act"><button class="pri" onclick="agForm({data:S.agDia})">+ Agendar</button>${sairBtn()}</div></div>
    <div class="card">
      <div class="day-head"><button class="sm" onclick="abrirDia(addDias(S.agDia,-1))" aria-label="Dia anterior">‹</button>
        <div><h3 style="margin:0">${diaLongo(d)}${d === today() ? ' · hoje' : ''}</h3><div class="meta">${doDia.length ? `${doDia.length} consulta(s) · ${durTxt(ocup)} ocupadas · ${durTxt(Math.max(0, (20 - 8) * 60 - ocup))} livres no expediente` : 'Dia livre — toque num horário para agendar'}</div></div>
        <button class="sm" onclick="abrirDia(addDias(S.agDia,1))" aria-label="Próximo dia">›</button></div>
      ${d !== today() ? `<div style="text-align:center;margin:-4px 0 10px"><button class="sm" onclick="abrirDia(today())">Ir para hoje</button></div>` : ''}
      ${timelineHTML(d, true)}
      <div class="tl-legend">${Object.keys(AG_ST).map(k => `<span><i class="st-${k}"></i>${AG_ST[k]}</span>`).join('')}</div>
    </div>`;
  const tl = $('tl'); if (tl) { const n = tl.querySelector('.tl-now') || tl.querySelector('.tl-ev') || tl.querySelector('.tl-row[data-h="8"]'); if (n) tl.scrollTop = Math.max(0, n.offsetTop - 60); }
}
function paneAgenda(m) {
  S.agDia = S.agDia || today(); S.agMes = S.agMes || S.agDia.slice(0, 7);
  if (S.agModo === 'dia') return paneAgendaDia(m);
  const [y, mm] = S.agMes.split('-').map(Number);
  const first = new Date(y, mm - 1, 1), start = first.getDay(), nDias = new Date(y, mm, 0).getDate();
  const cells = [];
  for (let i = 0; i < start; i++) cells.push(null);
  for (let d = 1; d <= nDias; d++) cells.push(`${S.agMes}-${pad2(d)}`);
  while (cells.length % 7) cells.push(null);
  const hoje = today(), doDia = agDia(S.agDia).filter(a => a.status !== 'cancelado');
  const ocup = doDia.reduce((s, a) => s + (a.dur || 50), 0);
  m.innerHTML = `<div class="head"><div><h1>Agenda</h1><div class="meta">Agendamentos de todos os pacientes</div></div>
      <div class="head-act"><button onclick="go('lembretes',{cur:null,lmDia:addDias(today(),1)})">${IC.bell}<span>Lembretes</span></button><button class="pri" onclick="agForm({data:S.agDia})">+ Agendar</button>${sairBtn()}</div></div>
    <div class="card cal-card">
      <div class="mes-nav"><button onclick="S.agMes=mesShift(S.agMes,-1);paneAgenda($('main'))" aria-label="Mês anterior">‹</button>
        <span class="mes-lbl">${mesLabel(S.agMes)}</span>
        <button onclick="S.agMes=mesShift(S.agMes,1);paneAgenda($('main'))" aria-label="Próximo mês">›</button>
        ${S.agMes !== hoje.slice(0, 7) || S.agDia !== hoje ? `<button class="sm hoje" onclick="S.agMes=today().slice(0,7);S.agDia=today();paneAgenda($('main'))">Hoje</button>` : ''}</div>
      <div class="cal">${DIAS.map(d => `<div class="cal-h">${d}</div>`).join('')}
        ${cells.map(d => {
          if (!d) return '<div class="cal-c vazio"></div>';
          const ags = agDia(d).filter(a => a.status !== 'cancelado');
          return `<div class="cal-c ${d === S.agDia ? 'sel' : ''} ${d === hoje ? 'hoje' : ''}" onclick="abrirDia('${d}')">
            <span class="cal-n">${Number(d.slice(8))}</span>
            ${ags.slice(0, 3).map(a => `<span class="cal-ev st-${a.status}"><b>${a.hora}</b> ${esc(primeiro(pNome(a)))}</span>`).join('')}
            ${ags.length > 3 ? `<span class="cal-more">+${ags.length - 3}</span>` : ''}</div>`;
        }).join('')}</div></div>
    <div class="cal-hint">Toque em um dia para ver a agenda hora a hora.</div>`;
}
function timelineHTML(d, full) {
  const ags = agDia(d), H = 64;
  let h0 = full ? 6 : 7, h1 = full ? 23 : 21;
  ags.forEach(a => { h0 = Math.min(h0, Math.floor(toMin(a.hora) / 60)); h1 = Math.max(h1, Math.ceil((toMin(a.hora) + (a.dur || 50)) / 60)); });
  h1 = Math.min(24, h1);
  // distribui sobreposições em colunas
  // distribui sobreposições em colunas, só dentro de cada grupo que se sobrepõe
  const pos = []; let grp = [], lanes = [], gEnd = -1;
  const fecha = () => { grp.forEach(x => x.n = lanes.length); grp = []; lanes = []; };
  ags.forEach(a => {
    const s = toMin(a.hora), e = s + (a.dur || 50);
    if (s >= gEnd) { fecha(); gEnd = e; } else gEnd = Math.max(gEnd, e);
    let l = lanes.findIndex(end => end <= s); if (l < 0) { l = lanes.length; lanes.push(e); } else lanes[l] = e;
    const o = { a, s, e, l, n: 1 }; grp.push(o); pos.push(o);
  });
  fecha();
  const hrs = []; for (let h = h0; h < h1; h++) hrs.push(h);
  const nowM = (() => { const x = new Date(); return x.getHours() * 60 + x.getMinutes(); })();
  return `<div class="tl" id="tl"><div class="tl-in" style="height:${(h1 - h0) * H}px">
    ${hrs.map(h => `<div class="tl-row${h < 8 || h >= 20 ? ' fora' : ''}" data-h="${h}" style="top:${(h - h0) * H}px;height:${H}px" onclick="agForm({data:'${d}',hora:'${pad2(h)}:00'})"><span>${pad2(h)}:00</span>${livre(ags, h) ? '<em>+ Livre — agendar</em>' : ''}</div>`).join('')}
    ${d === today() && nowM >= h0 * 60 && nowM <= h1 * 60 ? `<div class="tl-now" style="top:${(nowM - h0 * 60) / 60 * H}px"></div>` : ''}
    ${pos.map(({ a, s, e, l, n }) => `<div class="tl-ev st-${a.status}" style="top:${(s - h0 * 60) / 60 * H}px;height:${Math.max(26, (e - s) / 60 * H - 3)}px;left:calc(56px + (100% - 62px) * ${l} / ${n});width:calc((100% - 62px) / ${n} - 4px)" onclick="event.stopPropagation();agView('${a.id}')">
      <b>${esc(pNome(a))}</b><span>${a.hora}–${minToH(e)} · ${durTxt(a.dur || 50)}${a.status !== 'agendado' ? ' · ' + AG_ST[a.status] : a.lembrete ? ' · aguardando resposta' : ''}</span></div>`).join('')}
  </div></div>`;
}
function livre(ags, h) { const s = h * 60, e = s + 60; return !ags.some(a => a.status !== 'cancelado' && toMin(a.hora) < e && toMin(a.hora) + (a.dur || 50) > s); }
function conflitos(data, hora, dur, ignoreId, serie) {
  const s = toMin(hora), e = s + dur;
  return agList().filter(a => a.data === data && a.id !== ignoreId && (!serie || a.serie !== serie) && a.status !== 'cancelado' && toMin(a.hora) < e && toMin(a.hora) + (a.dur || 50) > s);
}
function agForm(pre) {
  pre = pre || {}; const ed = pre.id ? agList().find(a => a.id === pre.id) : null;
  const a = ed || { pid: pre.pid || (S.view === 'patient' ? S.cur : ''), data: pre.data || today(), hora: pre.hora || '14:00', dur: 50, status: 'agendado', obs: '' };
  let pid = a.pid;
  modal(`<h2>${ed ? 'Editar agendamento' : 'Novo agendamento'}</h2>
    <label>Paciente</label>
    <div id="agPac"></div>
    <div class="grid" style="margin-top:12px">
      <div class="c4"><label>Data</label><input type="date" id="agDt" value="${a.data}"></div>
      <div class="c4"><label>Horário</label><input type="time" id="agHr" value="${a.hora}"></div>
      <div class="c4"><label>Duração</label><select id="agDur">${[30, 40, 45, 50, 60, 90, 120].map(v => `<option value="${v}" ${v === (a.dur || 50) ? 'selected' : ''}>${durTxt(v)}</option>`).join('')}</select></div>
      ${ed ? `<div class="c6"><label>Situação</label><select id="agSt">${Object.keys(AG_ST).map(k => `<option value="${k}" ${a.status === k ? 'selected' : ''}>${AG_ST[k]}</option>`).join('')}</select></div>`
           : `<div class="c6"><label>Repetir toda semana</label><select id="agRep"><option value="1">Não repetir</option><option value="4">Por 4 semanas</option><option value="8">Por 8 semanas</option><option value="12">Por 12 semanas</option><option value="26">Por 6 meses</option></select></div>`}
      <div class="c12"><label>Observação</label><input id="agObs" value="${esc(a.obs || '')}" placeholder="Ex.: primeira consulta, on-line"></div></div>
    <div id="agWarn"></div>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" id="agSave">${ed ? 'Salvar' : 'Agendar'}</button></div>`);
  const pacUI = () => {
    const p = pid && pacById(pid);
    if (p) { $('agPac').innerHTML = `<div class="pick-sel" style="margin:0">${avatarHTML(p, '', true)}<div style="flex:1;min-width:0"><b>${esc(p.ident.nome)}</b><span>${pacInfo(p)}</span></div><button class="sm" id="agTroca">Trocar</button></div>`; $('agTroca').onclick = () => { pid = ''; pacUI(); }; return; }
    $('agPac').innerHTML = `<input id="agQ" placeholder="Digite o nome do paciente…" autocomplete="off"><div id="agRes" class="pick-list" style="max-height:220px"></div>`;
    const list = () => {
      const q = val('agQ').toLowerCase();
      const ps = DB.patients.filter(x => x.status === 'ativo' && (!q || (x.ident.nome || '').toLowerCase().includes(q))).sort((x, y) => (x.ident.nome || '').localeCompare(y.ident.nome || '')).slice(0, 20);
      $('agRes').innerHTML = ps.length ? ps.map(x => `<button class="pick" data-id="${x.id}">${avatarHTML(x, '', true)}<div style="flex:1;min-width:0;text-align:left"><b>${esc(x.ident.nome || '(sem nome)')}</b><span>${pacInfo(x)}</span></div></button>`).join('')
        : `<div style="color:var(--muted);font-size:13px;padding:8px 2px">${DB.patients.length ? 'Nenhum paciente em atendimento encontrado.' : 'Cadastre um paciente primeiro.'}</div>`;
      $('agRes').querySelectorAll('.pick').forEach(b => b.onclick = () => { pid = b.dataset.id; pacUI(); check(); });
    };
    $('agQ').oninput = list; list(); setTimeout(() => $('agQ') && $('agQ').focus(), 50);
  };
  const check = () => {
    const c = conflitos(val('agDt'), val('agHr'), Number(val('agDur')), ed && ed.id);
    $('agWarn').innerHTML = c.length ? `<div class="note warn" style="margin:10px 0 0">Conflito de horário com ${c.map(x => `<b>${esc(pNome(x))}</b> (${x.hora})`).join(', ')}.</div>` : '';
  };
  ['agDt', 'agHr', 'agDur'].forEach(i => $(i).onchange = check);
  pacUI(); check();
  $('agSave').onclick = () => {
    if (!pid) return toast('Escolha o paciente');
    const data = val('agDt'), hora = val('agHr'), dur = Number(val('agDur'));
    if (!data || !hora) return toast('Informe data e horário');
    if (ed) { Object.assign(ed, { pid, data, hora, dur, status: val('agSt'), obs: val('agObs') }); }
    else {
      const n = Number(val('agRep')), serie = n > 1 ? uid() : null;
      for (let k = 0; k < n; k++) agList().push({ id: uid(), pid, data: addDias(data, 7 * k), hora, dur, status: 'agendado', obs: val('agObs'), serie, criadoEm: nowISO() });
    }
    save(); closeModal(); toast(ed ? 'Agendamento atualizado' : 'Agendado'); S.agDia = data; S.agMes = data.slice(0, 7); if (S.view === 'agenda') S.agModo = 'dia'; renderMain();
  };
}
function agView(id) {
  const a = agList().find(x => x.id === id); if (!a) return; const p = pacById(a.pid), fim = minToH(toMin(a.hora) + (a.dur || 50));
  modal(`<div class="ag-view">${p ? avatarHTML(p, 'lg') : ''}<div><h2 style="margin:0">${esc(pNome(a))}</h2>
      <div class="meta">${diaLongo(a.data)} · ${a.hora}–${fim} (${durTxt(a.dur || 50)})</div>
      <span class="tag st-${a.status}">${AG_ST[a.status]}</span>${a.serie ? ' <span class="tag">semanal</span>' : ''}${a.lembrete ? ` <span class="tag">lembrete enviado ${fmtD(a.lembrete.slice(0, 10))}</span>` : ''}</div></div>
    ${a.obs ? `<p style="margin:12px 0 0">${esc(a.obs)}</p>` : ''}
    <label style="margin-top:14px">Alterar situação</label>
    <div class="st-pick">${Object.keys(AG_ST).map(k => `<button class="${a.status === k ? 'on' : ''} st-${k}" onclick="agStatus('${a.id}','${k}')">${AG_ST[k]}</button>`).join('')}</div>
    <div class="row-actions" style="justify-content:space-between">
      <button class="danger" onclick="agDel('${a.id}')">Excluir</button>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${p ? `<button onclick="closeModal();go('patient',{cur:'${a.pid}',tab:'painel'})">Abrir prontuário</button>` : ''}
        ${p && ['agendado', 'confirmado'].includes(a.status) ? `<a class="btn wa-btn" href="${lembreteUrl(a)}" target="_blank" rel="noopener" onclick="marcaLembrete('${a.id}')">${WA_ICON}<span>Lembrete</span></a>` : ''}
        <button onclick="agForm({id:'${a.id}'})">Editar</button>
        ${p && a.status !== 'realizado' && a.status !== 'cancelado' ? `<button class="pri" onclick="agSessao('${a.id}')">Registrar sessão</button>` : ''}</div></div>`);
}
function agStatus(id, st) { const a = agList().find(x => x.id === id); if (!a) return; a.status = st; save(); closeModal(); toast('Situação: ' + AG_ST[st]); renderMain(); }
function agDel(id) {
  const a = agList().find(x => x.id === id); if (!a) return;
  if (!a.serie) return confirmBox('Excluir agendamento?', `${pNome(a)} — ${fmtD(a.data)} às ${a.hora}.`, 'Excluir', () => { DB.agenda = agList().filter(x => x.id !== id); save(); renderMain(); });
  modal(`<h2>Excluir agendamento semanal</h2><p>${esc(pNome(a))} — ${fmtD(a.data)} às ${a.hora}.</p>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button>
    <button class="danger" id="agD1">Só este</button><button class="btn-del" id="agDn">Este e os próximos</button></div>`);
  $('agD1').onclick = () => { DB.agenda = agList().filter(x => x.id !== id); save(); closeModal(); renderMain(); };
  $('agDn').onclick = () => { DB.agenda = agList().filter(x => !(x.serie === a.serie && x.data >= a.data)); save(); closeModal(); toast('Agendamentos excluídos'); renderMain(); };
}
function agSessao(id) {
  const a = agList().find(x => x.id === id); if (!a) return;
  S.prefill = { pid: a.pid, agId: a.id, data: a.data, hora: a.hora, horaFim: minToH(toMin(a.hora) + (a.dur || 50)) };
  closeModal(); go('patient', { cur: a.pid, tab: 'evolucao' });
}
function proxAg(pid) { const t = today(), h = horaAgora(); return agList().filter(a => a.pid === pid && a.status !== 'cancelado' && a.status !== 'realizado' && (a.data > t || (a.data === t && a.hora >= h))).sort((a, b) => (a.data + a.hora).localeCompare(b.data + b.hora))[0]; }

/* ---------- Pix (BR Code estático, padrão do Banco Central) ---------- */
const semAcento = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '');
function crc16(str) {
  let crc = 0xFFFF;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xFFFF : (crc << 1) & 0xFFFF;
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}
const emv = (id, v) => id + String(v.length).padStart(2, '0') + v;
function pixChave(tipo, chave) {
  const c = String(chave || '').trim();
  if (tipo === 'cpf') return c.replace(/\D/g, '');
  if (tipo === 'cel') { let d = c.replace(/\D/g, ''); if (d.startsWith('55') && d.length > 11) d = d.slice(2); return '+55' + d; }
  if (tipo === 'email') return c.toLowerCase();
  return c;
}
function pixPayload({ chave, nome, cidade, valor, txid, descricao }) {
  const nm = semAcento(nome).toUpperCase().replace(/[^A-Z0-9 ]/g, '').trim().slice(0, 25) || 'RECEBEDOR';
  const cd = semAcento(cidade).toUpperCase().replace(/[^A-Z0-9 ]/g, '').trim().slice(0, 15) || 'BRASIL';
  let ma = emv('00', 'br.gov.bcb.pix') + emv('01', chave);
  const desc = semAcento(descricao || '').replace(/[^A-Za-z0-9 .,\/-]/g, '').trim();
  if (desc && (ma.length + 4 + desc.length) <= 99) ma += emv('02', desc.slice(0, 99 - ma.length - 4));
  const tx = (String(txid || '***').replace(/[^A-Za-z0-9]/g, '') || '***').slice(0, 25);
  let p = emv('00', '01') + emv('26', ma) + emv('52', '0000') + emv('53', '986');
  if (valor > 0) p += emv('54', valor.toFixed(2));
  p += emv('58', 'BR') + emv('59', nm) + emv('60', cd) + emv('62', emv('05', tx)) + '6304';
  return p + crc16(p);
}
function pixPronto() { const x = DB.prof.pix || {}; return x.chave && x.nome && x.cidade; }
function qrCanvas(text, scale) {
  const q = qrcode(0, 'M'); q.addData(text); q.make();
  const n = q.getModuleCount(), m = 4, s = scale || 8, c = document.createElement('canvas');
  c.width = c.height = (n + m * 2) * s;
  const g = c.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, c.width, c.height); g.fillStyle = '#000';
  for (let r = 0; r < n; r++) for (let k = 0; k < n; k++) if (q.isDark(r, k)) g.fillRect((k + m) * s, (r + m) * s, s, s);
  return c;
}
function cobrarPix(pid, valor, ref, sessIds) {
  if (!premium()) return paywall('pix');
  const p = pacById(pid);
  if (!pixPronto()) return confirmBox('Configure sua chave Pix', 'Cadastre a chave Pix, o nome do recebedor e a cidade em Configurações para gerar cobranças.', 'Abrir Configurações', () => go('settings'));
  const x = DB.prof.pix, chave = pixChave(x.tipo, x.chave);
  const txid = 'APPSICO' + today().replace(/-/g, '').slice(2) + uid().replace(/[^A-Za-z0-9]/g, '').slice(0, 6);
  const code = pixPayload({ chave, nome: x.nome, cidade: x.cidade, valor, txid, descricao: ref ? 'Psicologia ' + ref : '' });
  const nomeP = p ? (p.ident.nome || '') : '', tel = p ? waPhone(p) : '';
  const msg = `Olá${nomeP ? ', ' + primeiro(nomeP) : ''}! Segue o Pix para pagamento${ref ? ' referente a ' + ref : ''}, no valor de ${brl(valor)}.\n\nPix copia e cola:\n${code}\n\n${DB.prof.nome || ''}${DB.prof.crp ? ' — CRP ' + DB.prof.crp : ''}`;
  const canvas = qrCanvas(code, 8), img = canvas.toDataURL('image/png');
  modal(`<div class="doc-head"><h2 style="margin:0">Cobrança via Pix</h2><button class="ghost" onclick="closeModal()">Fechar</button></div>
    <div class="pix-box">
      <div class="pix-val"><span>${esc(nomeP || 'Paciente')}</span><b>${brl(valor)}</b>${ref ? `<small>${esc(ref)}</small>` : ''}</div>
      <img class="pix-qr" src="${img}" alt="QR Code Pix">
      <label>Pix copia e cola</label>
      <textarea class="pix-code" readonly onclick="this.select()">${esc(code)}</textarea>
      <div class="pix-to">Recebedor: <b>${esc(x.nome)}</b> · Chave: ${esc(x.chave)}</div>
    </div>
    <div class="doc-actions">
      <button class="act" id="pxCopy">${IC.file}<span>Copiar código</span></button>
      <button class="act" id="pxImg">${IC.share}<span>Enviar QR Code</span></button>
      <a class="act wa" id="pxWa" href="https://wa.me/${tel}?text=${encodeURIComponent(msg)}" target="_blank" rel="noopener">${WA_ICON}<span>Enviar pelo WhatsApp</span></a>
    </div>
    ${tel ? '' : '<div class="note warn" style="margin:0 0 10px">Paciente sem telefone cadastrado: o WhatsApp vai abrir para você escolher o contato.</div>'}
    ${sessIds && sessIds.length ? `<div class="row-actions" style="margin-top:0"><button class="pri" id="pxPago">Marcar como pago</button></div>` : ''}`);
  $('pxCopy').onclick = () => navigator.clipboard.writeText(code).then(() => toast('Código Pix copiado'), () => { document.querySelector('.pix-code').select(); toast('Selecione e copie o código'); });
  $('pxImg').onclick = async () => {
    const fname = `Pix-${semAcento(primeiro(nomeP) || 'paciente').replace(/\W+/g, '')}-${today()}.png`, b64 = img.split(',')[1];
    if (NATIVE) {
      try { await FS.writeFile({ path: fname, data: b64, directory: 'CACHE' }); tempFiles.push(fname); await SHARE.share({ title: 'Pix', text: msg, files: ['content://x/' + fname], dialogTitle: 'Enviar QR Code', package: 'com.whatsapp' }); }
      catch (e) { if (!/cancel/i.test(e.message || '')) toast('Falha ao compartilhar: ' + e.message); }
      return;
    }
    await deliverPDF(await (await fetch(img)).blob(), fname);
  };
  if ($('pxPago')) $('pxPago').onclick = () => {
    sessIds.forEach(([ppid, eid]) => { const e = findSess(ppid, eid); if (e) { e.pago = true; e.pagoEm = today(); e.forma = 'Pix'; } });
    save(); closeModal(); toast('Pagamento registrado'); renderMain();
  };
}
function cobrarSessao(pid, eid) { const e = findSess(pid, eid); if (!e) return; cobrarPix(pid, e.valor || 0, 'consulta de ' + fmtD(e.data), [[pid, eid]]); }
function cobrarPendentes(pid, mes) {
  const p = pacById(pid); if (!p) return;
  const ss = p.evolucao.filter(e => !e.pago && e.valor > 0 && (!mes || e.data.startsWith(mes)));
  if (!ss.length) return toast('Nenhuma consulta pendente');
  const tot = ss.reduce((s, e) => s + e.valor, 0);
  cobrarPix(pid, tot, ss.length === 1 ? 'consulta de ' + fmtD(ss[0].data) : `${ss.length} consultas (${ss.map(e => fmtD(e.data).slice(0, 5)).join(', ')})`, ss.map(e => [pid, e.id]));
}

/* ---------- Calendário financeiro + contas a pagar e receber ---------- */
function finTabs() {
  const t = S.finTab || 'calendario';
  return `<div class="ptabs fin-tabs">${[['receber', 'Contas a receber', 'receber', 't-rec'], ['pagar', 'Contas a pagar', 'pagar', 't-pag'], ['calendario', 'Calendário', 'calcash', ''], ['relatorio', 'Contador', 'report', '']]
    .map(([k, l, ic, cl]) => `<button class="${cl} ${t === k ? 'on' : ''}" onclick="go('fin',{cur:null,finTab:'${k}'})">${IC[ic]}<span>${l}</span></button>`).join('')}</div>`;
}
function paneContas(m, tipo) {
  const hoje = today(), mes = hoje.slice(0, 7), pd = pendencias().filter(x => x.tipo === tipo);
  const tot = pd.reduce((s, x) => s + x.v, 0), venc = pd.filter(x => x.d < hoje), sete = pd.filter(x => x.d >= hoje && x.d <= addDias(hoje, 7));
  const pagas = contas().filter(c => c.tipo === tipo && c.pago).sort((a, b) => (b.pagoEm || '').localeCompare(a.pagoEm || ''));
  const pagasMes = pagas.filter(c => (c.pagoEm || '').startsWith(mes)).reduce((s, c) => s + c.valor, 0)
    + (tipo === 'receber' ? DB.patients.reduce((s, p) => s + p.evolucao.filter(e => e.pago && e.valor > 0 && (e.pagoEm || e.data).startsWith(mes)).reduce((t, e) => t + e.valor, 0), 0) : 0);
  const P_ = tipo === 'pagar';
  m.innerHTML = `<div class="head"><div><h1 class="${P_ ? 'h-pag' : 'h-rec'}">${P_ ? 'Contas a pagar' : 'Contas a receber'}</h1><div class="meta">${P_ ? 'Despesas do consultório e vencimentos' : 'Consultas não pagas e outros valores a receber'}</div></div>
      <div class="head-act"><button class="pri ${P_ ? 'b-pag' : 'b-rec'}" onclick="contaForm({tipo:'${tipo}'})">+ Nova conta</button>${sairBtn()}</div></div>
    ${finTabs()}
    <div class="kpis k4">
      <div class="kpi ${P_ ? 'k-pag' : 'k-rec'}"><span>${P_ ? 'Total a pagar' : 'Total a receber'}</span><b>${brl(tot)}</b></div>
      <div class="kpi ${venc.length ? 'bad' : ''}"><span>Vencidas</span><b>${venc.length}${venc.length ? ' · ' + brl(venc.reduce((s, x) => s + x.v, 0)) : ''}</b></div>
      <div class="kpi"><span>Próximos 7 dias</span><b>${brl(sete.reduce((s, x) => s + x.v, 0))}</b></div>
      <div class="kpi ok"><span>${P_ ? 'Pago' : 'Recebido'} no mês</span><b>${brl(pagasMes)}</b></div></div>
    <div class="card ${P_ ? 'c-pag' : 'c-rec'}"><h3>Em aberto</h3>
      ${pd.length ? `<div class="contas">${pd.map(x => contaRow(x, hoje)).join('')}</div>` : `<div style="color:var(--muted);font-size:13px">Nada ${P_ ? 'a pagar' : 'a receber'} em aberto.</div>`}</div>
    ${pagas.length ? `<div class="card"><h3>${P_ ? 'Pagas' : 'Recebidas'} recentemente</h3><div class="contas">${pagas.slice(0, 10).map(c => `<div class="conta quit"><div class="cdata"><b>${(c.pagoEm || c.venc).slice(8)}/${(c.pagoEm || c.venc).slice(5, 7)}</b><small style="color:var(--ok)">${P_ ? 'paga' : 'recebida'}</small></div><div class="cinfo"><b>${esc(c.desc)}</b><span>${esc(c.cat || '')} · venc. ${fmtD(c.venc)}</span></div><div class="cval">${brl(c.valor)}</div><div class="cact"><button class="ghost sm" onclick="contaReabrir('${c.id}')">desfazer</button></div></div>`).join('')}</div></div>` : ''}`;
}
function contaReabrir(id) { const c = contas().find(x => x.id === id); if (!c) return; c.pago = false; c.pagoEm = ''; save(); renderMain(); }
const contas = () => DB.contas || (DB.contas = []);
const CAT_PAGAR = ['Aluguel / sala', 'Condomínio', 'Energia / internet', 'Supervisão', 'Conselho (CRP)', 'Impostos', 'Contador', 'Materiais e testes', 'Software', 'Cartão de crédito', 'Outros'];
const CAT_RECEBER = ['Consultas', 'Pacote de sessões', 'Avaliação', 'Convênio', 'Palestra / curso', 'Outros'];
const brlC = v => (v < 0 ? '−' : '') + 'R$ ' + Math.abs(v).toLocaleString('pt-BR', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
// Movimentos de caixa (o que efetivamente entrou ou saiu, na data do pagamento)
function movimentos() {
  const mv = [];
  DB.patients.forEach(p => p.evolucao.forEach(e => { if (e.pago && e.valor > 0) mv.push({ d: e.pagoEm || e.data, v: e.valor, t: 'in', txt: `Consulta — ${p.ident.nome || 'paciente'}`, sub: e.forma || '' }); }));
  (DB.lancamentos || []).forEach(l => mv.push({ d: l.data, v: l.valor, t: l.tipo === 'saida' ? 'out' : 'in', txt: l.descricao, sub: l.categoria || '' }));
  contas().forEach(c => { if (c.pago) mv.push({ d: c.pagoEm || c.venc, v: c.valor, t: c.tipo === 'pagar' ? 'out' : 'in', txt: c.desc, sub: (c.tipo === 'pagar' ? 'Conta paga' : 'Conta recebida') + (c.cat ? ' · ' + c.cat : '') }); });
  return mv;
}
// Pendências: contas em aberto + consultas não pagas (a receber)
function pendencias() {
  const pd = contas().filter(c => !c.pago).map(c => ({ kind: 'conta', id: c.id, tipo: c.tipo, d: c.venc, v: c.valor, txt: c.desc, sub: c.cat || '', pid: c.pid }));
  DB.patients.forEach(p => p.evolucao.forEach(e => { if (!e.pago && e.valor > 0) pd.push({ kind: 'sessao', id: e.id, pid: p.id, tipo: 'receber', d: e.data, v: e.valor, txt: `Consulta — ${p.ident.nome || 'paciente'}`, sub: 'Sessão de ' + fmtD(e.data) }); }));
  return pd.sort((a, b) => a.d.localeCompare(b.d));
}
function paneFinCal(m) {
  S.fcMes = S.fcMes || today().slice(0, 7);
  const mes = S.fcMes, hoje = today(), mv = movimentos(), pd = pendencias();
  const [y, mm] = mes.split('-').map(Number), nDias = new Date(y, mm, 0).getDate(), start = new Date(y, mm - 1, 1).getDay();
  const ini = mes + '-01';
  let saldo = mv.filter(x => x.d < ini).reduce((s, x) => s + (x.t === 'in' ? x.v : -x.v), 0);
  const saldoIni = saldo, dias = {};
  for (let d = 1; d <= nDias; d++) {
    const k = `${mes}-${pad2(d)}`, dm = mv.filter(x => x.d === k);
    const ent = dm.filter(x => x.t === 'in').reduce((s, x) => s + x.v, 0), sai = dm.filter(x => x.t === 'out').reduce((s, x) => s + x.v, 0);
    saldo += ent - sai;
    dias[k] = { ent, sai, saldo, venc: pd.filter(x => x.d === k) };
  }
  const recMes = Object.values(dias).reduce((s, x) => s + x.ent, 0), pagMes = Object.values(dias).reduce((s, x) => s + x.sai, 0);
  const aRec = pd.filter(x => x.tipo === 'receber'), aPag = pd.filter(x => x.tipo === 'pagar');
  const venc = pd.filter(x => x.d < hoje);
  const cells = []; for (let i = 0; i < start; i++) cells.push(null); for (let d = 1; d <= nDias; d++) cells.push(`${mes}-${pad2(d)}`); while (cells.length % 7) cells.push(null);
  const aba = S.fcAba || 'pagar', lista = aba === 'pagar' ? aPag : aRec;
  S.mes = mes;
  m.innerHTML = `<div class="head"><div><h1>Financeiro</h1><div class="meta">Entradas, saídas e saldo de cada dia</div></div>
      <div class="head-act"><button class="pri" onclick="contaForm()">+ Conta</button>${sairBtn()}</div></div>
    ${finTabs()}
    <div class="mes-nav"><button onclick="S.fcMes=mesShift(S.fcMes,-1);paneFinCal($('main'))" aria-label="Mês anterior">‹</button>
      <span class="mes-lbl">${mesLabel(mes)}</span><button onclick="S.fcMes=mesShift(S.fcMes,1);paneFinCal($('main'))" aria-label="Próximo mês">›</button>
      ${mes !== hoje.slice(0, 7) ? `<button class="sm hoje" onclick="S.fcMes=today().slice(0,7);paneFinCal($('main'))">Mês atual</button>` : ''}</div>
    <div class="kpis">
      <div class="kpi ok"><span>Recebido no mês</span><b>${brl(recMes)}</b></div>
      <div class="kpi bad"><span>Pago no mês</span><b>${brl(pagMes)}</b></div>
      <div class="kpi main"><span>Saldo acumulado</span><b>${brl(saldo)}</b></div>
      <div class="kpi k-rec" onclick="go('fin',{cur:null,finTab:'receber'})" style="cursor:pointer"><span>A receber</span><b>${brl(aRec.reduce((s, x) => s + x.v, 0))}</b></div>
      <div class="kpi k-pag" onclick="go('fin',{cur:null,finTab:'pagar'})" style="cursor:pointer"><span>A pagar</span><b>${brl(aPag.reduce((s, x) => s + x.v, 0))}</b></div>
      <div class="kpi ${venc.length ? 'bad' : ''}"><span>Vencidas</span><b>${venc.length}</b></div></div>
    <div class="card cal-card">
      <div class="cal fcal">${DIAS.map(d => `<div class="cal-h">${d}</div>`).join('')}
      ${cells.map(k => {
        if (!k) return '<div class="cal-c vazio"></div>';
        const x = dias[k], vp = x.venc.filter(v => v.tipo === 'pagar').length, vr = x.venc.filter(v => v.tipo === 'receber').length;
        return `<div class="cal-c ${k === hoje ? 'hoje' : ''} ${k > hoje ? 'fut' : ''}" onclick="fcDia('${k}')">
          <span class="cal-n">${Number(k.slice(8))}</span>
          ${x.ent ? `<span class="fc-in">+${brlC(x.ent).replace('R$ ', '')}</span>` : ''}
          ${x.sai ? `<span class="fc-out">−${brlC(x.sai).replace('R$ ', '')}</span>` : ''}
          ${k <= hoje ? `<span class="fc-sal ${x.saldo < 0 ? 'neg' : ''}">${brlC(x.saldo)}</span>` : ''}
          ${vp || vr ? `<span class="fc-dots">${vp ? `<i class="dp" title="${vp} a pagar"></i>` : ''}${vr ? `<i class="dr" title="${vr} a receber"></i>` : ''}</span>` : ''}</div>`;
      }).join('')}</div>
      <div class="tl-legend"><span><i style="background:var(--ok)"></i>Entrou no dia</span><span><i style="background:var(--danger)"></i>Saiu no dia</span><span><i style="background:var(--blue)"></i>Saldo acumulado</span><span><i class="dot dp"></i>Conta a pagar</span><span><i class="dot dr"></i>A receber</span></div>
      <div class="meta" style="margin-top:6px">Saldo no início do mês: <b>${brl(saldoIni)}</b> · Valores pelo dia em que o dinheiro entrou ou saiu.</div></div>
    <div class="row-actions" style="justify-content:flex-start"><button onclick="exportFinCSV()">Exportar mês (planilha CSV)</button></div>`;
}
function contaRow(x, hoje) {
  const atras = x.d < hoje, hojeV = x.d === hoje;
  return `<div class="conta ${atras ? 'atras' : ''}">
    <div class="cdata"><b>${x.d.slice(8)}/${x.d.slice(5, 7)}</b><small>${atras ? 'vencida' : hojeV ? 'hoje' : ''}</small></div>
    <div class="cinfo"><b>${esc(x.txt)}</b><span>${esc(x.sub)}</span></div>
    <div class="cval ${x.tipo}">${brl(x.v)}</div>
    <div class="cact">${x.kind === 'sessao'
      ? `<button class="pix-btn sm" onclick="cobrarSessao('${x.pid}','${x.id}')">${PIX_ICON}Pix</button><button class="sm" onclick="marcarPago('${x.pid}','${x.id}');paneFinCal($('main'))">Recebido</button>`
      : `${x.tipo === 'receber' && x.pid ? `<button class="pix-btn sm" onclick="cobrarPix('${x.pid}',${x.v},'${esc(x.txt).replace(/'/g, '')}')">${PIX_ICON}Pix</button>` : ''}<button class="sm ok-btn" onclick="contaPagar('${x.id}')">${x.tipo === 'pagar' ? 'Paguei' : 'Recebi'}</button><button class="ghost sm" onclick="contaForm({id:'${x.id}'})">editar</button>`}</div></div>`;
}
function contaPagar(id) { const c = contas().find(x => x.id === id); if (!c) return; c.pago = true; c.pagoEm = today(); save(); toast(c.tipo === 'pagar' ? 'Conta paga' : 'Valor recebido'); closeModal(); renderMain(); }
function contaForm(pre) {
  pre = pre || {}; const ed = pre.id ? contas().find(x => x.id === pre.id) : null;
  const c = ed || { tipo: pre.tipo || 'pagar', desc: '', cat: '', valor: 0, venc: pre.venc || today(), pid: '' };
  const cats = t => (t === 'pagar' ? CAT_PAGAR : CAT_RECEBER).map(o => `<option ${c.cat === o ? 'selected' : ''}>${o}</option>`).join('');
  modal(`<h2>${ed ? 'Editar conta' : 'Nova conta'}</h2><div class="grid">
    <div class="c6"><label>Tipo</label><select id="ctTipo"><option value="pagar" ${c.tipo === 'pagar' ? 'selected' : ''}>A pagar</option><option value="receber" ${c.tipo === 'receber' ? 'selected' : ''}>A receber</option></select></div>
    <div class="c6"><label>Categoria</label><select id="ctCat">${cats(c.tipo)}</select></div>
    <div class="c12"><label>Descrição</label><input id="ctDesc" value="${esc(c.desc)}" placeholder="Ex.: aluguel da sala, anuidade CRP"></div>
    <div class="c6"><label>Valor (R$)</label><input id="ctVal" inputmode="decimal" value="${c.valor ? c.valor.toFixed(2).replace('.', ',') : ''}" placeholder="0,00"></div>
    <div class="c6"><label>Vencimento</label><input type="date" id="ctVenc" value="${c.venc}"></div>
    <div class="c12" id="ctPacW" style="${c.tipo === 'receber' ? '' : 'display:none'}"><label>Paciente (opcional, para cobrar via Pix)</label><select id="ctPac"><option value="">—</option>${DB.patients.filter(p => p.status === 'ativo' || p.id === c.pid).sort((a, b) => (a.ident.nome || '').localeCompare(b.ident.nome || '')).map(p => `<option value="${p.id}" ${c.pid === p.id ? 'selected' : ''}>${esc(p.ident.nome || '(sem nome)')}</option>`).join('')}</select></div>
    ${ed ? '' : `<div class="c12"><label>Repetir todo mês</label><select id="ctRep"><option value="1">Não repetir</option><option value="3">Por 3 meses</option><option value="6">Por 6 meses</option><option value="12">Por 12 meses</option></select></div>`}
  </div>
  <div class="row-actions" style="justify-content:space-between">${ed ? `<button class="danger" onclick="contaDel('${ed.id}')">Excluir</button>` : '<span></span>'}
    <div style="display:flex;gap:8px"><button onclick="closeModal()">Cancelar</button><button class="pri" id="ctSave">${ed ? 'Salvar' : 'Adicionar'}</button></div></div>`);
  $('ctTipo').onchange = e => { c.tipo = e.target.value; $('ctCat').innerHTML = cats(c.tipo); $('ctPacW').style.display = c.tipo === 'receber' ? '' : 'none'; };
  $('ctSave').onclick = () => {
    const valor = parseValor(val('ctVal')), desc = val('ctDesc'), venc = val('ctVenc');
    if (!desc) return toast('Informe a descrição'); if (!valor) return toast('Informe o valor'); if (!venc) return toast('Informe o vencimento');
    const base = { tipo: val('ctTipo'), cat: val('ctCat'), desc, valor, venc, pid: val('ctTipo') === 'receber' ? val('ctPac') : '' };
    if (ed) Object.assign(ed, base);
    else {
      const n = Number(val('ctRep')), serie = n > 1 ? uid() : null, [yy, mo, dd] = venc.split('-').map(Number);
      for (let k = 0; k < n; k++) {
        const dt = new Date(yy, mo - 1 + k, 1), ult = new Date(dt.getFullYear(), dt.getMonth() + 1, 0).getDate();
        const v = `${dt.getFullYear()}-${pad2(dt.getMonth() + 1)}-${pad2(Math.min(dd, ult))}`;
        contas().push(Object.assign({ id: uid(), pago: false, pagoEm: '', serie, criadoEm: nowISO() }, base, { venc: v, desc: n > 1 ? `${desc} (${k + 1}/${n})` : desc }));
      }
    }
    save(); closeModal(); toast(ed ? 'Conta atualizada' : 'Conta adicionada'); renderMain();
  };
}
function contaDel(id) {
  const c = contas().find(x => x.id === id); if (!c) return;
  confirmBox('Excluir conta?', `${c.desc} — ${brl(c.valor)} (vence ${fmtD(c.venc)}).`, 'Excluir', () => { DB.contas = contas().filter(x => x.id !== id); save(); renderMain(); });
}
function fcDia(k) {
  const mv = movimentos().filter(x => x.d === k), pd = pendencias().filter(x => x.d === k);
  const ent = mv.filter(x => x.t === 'in').reduce((s, x) => s + x.v, 0), sai = mv.filter(x => x.t === 'out').reduce((s, x) => s + x.v, 0);
  const acum = movimentos().filter(x => x.d <= k).reduce((s, x) => s + (x.t === 'in' ? x.v : -x.v), 0);
  modal(`<div class="doc-head"><h2 style="margin:0">${diaLongo(k)}</h2><button class="ghost" onclick="closeModal()">Fechar</button></div>
    <div class="kpis" style="grid-template-columns:repeat(3,1fr)"><div class="kpi ok"><span>Entrou</span><b>${brl(ent)}</b></div><div class="kpi bad"><span>Saiu</span><b>${brl(sai)}</b></div><div class="kpi main"><span>Saldo acumulado</span><b>${brl(acum)}</b></div></div>
    ${mv.length ? `<h3 style="font-size:15px;margin:4px 0 8px">Movimentos do dia</h3><div class="contas">${mv.map(x => `<div class="conta"><div class="cinfo"><b>${esc(x.txt)}</b><span>${esc(x.sub)}</span></div><div class="cval ${x.t === 'in' ? 'receber' : 'pagar'}">${x.t === 'in' ? '+' : '−'} ${brl(x.v)}</div></div>`).join('')}</div>` : '<div style="color:var(--muted);font-size:13px;margin-bottom:8px">Nenhum valor entrou ou saiu neste dia.</div>'}
    ${pd.length ? `<h3 style="font-size:15px;margin:14px 0 8px">Vencendo neste dia</h3><div class="contas">${pd.map(x => contaRow(x, today())).join('')}</div>` : ''}
    <div class="row-actions"><button onclick="closeModal();contaForm({venc:'${k}',tipo:'pagar'})">+ Conta a pagar</button><button onclick="closeModal();contaForm({venc:'${k}',tipo:'receber'})">+ Conta a receber</button></div>`);
}

/* ---------- Financeiro ---------- */
const FORMAS = ['Pix', 'Dinheiro', 'Cartão de débito', 'Cartão de crédito', 'Transferência bancária', 'Convênio'];
const pad2 = n => String(n).padStart(2, '0');
function horaAgora() { const d = new Date(); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()); }
function somaMin(h, m) { if (!h) return ''; const [a, b] = h.split(':').map(Number); const t = (a * 60 + b + m + 1440) % 1440; return pad2(Math.floor(t / 60)) + ':' + pad2(t % 60); }
function findSess(pid, eid) { const p = DB.patients.find(x => x.id === pid); return p ? p.evolucao.find(x => x.id === eid) : null; }
function marcarPago(pid, eid) { const e = findSess(pid, eid); if (!e) return; e.pago = true; e.pagoEm = today(); save(); toast('Pagamento registrado'); }
function setPg(pid, eid, field, v) {
  const e = findSess(pid, eid); if (!e) return;
  if (field === 'pago') { e.pago = v === '1'; e.pagoEm = e.pago ? today() : ''; }
  else if (field === 'forma') e.forma = v;
  else if (field === 'valor') e.valor = parseValor(v);
  save(); paneFin($('main'));
}
const mesLabel = m => { const [y, mm] = m.split('-').map(Number); const t = new Date(y, mm - 1, 1).toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }); return t.charAt(0).toUpperCase() + t.slice(1); };
const mesShift = (m, k) => { const [y, mm] = m.split('-').map(Number); const d = new Date(y, mm - 1 + k, 1); return d.getFullYear() + '-' + pad2(d.getMonth() + 1); };
function finMes(mes) {
  const sess = [];
  DB.patients.forEach(p => p.evolucao.forEach(e => { if (e.data && e.data.startsWith(mes) && e.valor !== undefined && (e.valor > 0 || e.pago)) sess.push({ p, e }); }));
  sess.sort((a, b) => (a.e.data + (a.e.hora || '')).localeCompare(b.e.data + (b.e.hora || '')));
  const lanc = (DB.lancamentos || []).filter(l => l.data.startsWith(mes)).sort((a, b) => a.data.localeCompare(b.data));
  const ent = lanc.filter(l => l.tipo === 'entrada'), sai = lanc.filter(l => l.tipo === 'saida');
  const sum = (a, f) => a.reduce((s, x) => s + f(x), 0);
  const fatSess = sum(sess, x => x.e.valor || 0), recSess = sum(sess.filter(x => x.e.pago), x => x.e.valor || 0);
  const avulso = sum(ent, l => l.valor), desp = sum(sai, l => l.valor);
  return { sess, lanc, ent, sai, faturado: fatSess + avulso, recebido: recSess + avulso, pendente: fatSess - recSess, despesas: desp, saldo: recSess + avulso - desp };
}
function paneFin(m) {
  if (!DB.lancamentos) DB.lancamentos = [];
  const mes = S.mes || (S.mes = today().slice(0, 7));
  const f = finMes(mes);
  const hist = [-5, -4, -3, -2, -1, 0].map(k => { const mm = mesShift(mes, k), r = finMes(mm); return { mm, fat: r.faturado, rec: r.recebido, desp: r.despesas }; });
  const max = Math.max(1, ...hist.map(h => Math.max(h.fat, h.desp)));
  const porPac = {};
  f.sess.forEach(({ p, e }) => { const o = porPac[p.id] || (porPac[p.id] = { pid: p.id, nome: p.ident.nome || '(sem nome)', n: 0, fat: 0, rec: 0 }); o.n++; o.fat += e.valor || 0; if (e.pago) o.rec += e.valor || 0; });
  const pacs = Object.values(porPac).sort((a, b) => b.fat - a.fat);
  m.innerHTML = `<div class="head"><div><h1>Fluxo de caixa</h1><div class="meta">Faturamento mensal de todos os pacientes</div></div>${sairBtn()}</div>
  ${finTabs()}
  <div class="mes-nav"><button onclick="S.mes=mesShift(S.mes,-1);paneFin($('main'))" aria-label="Mês anterior">‹</button>
    <span class="mes-lbl">${mesLabel(mes)}</span>${mes !== today().slice(0, 7) ? `<button class="sm hoje" onclick="S.mes=today().slice(0,7);paneFin($('main'))">Mês atual</button>` : ''}
    <button onclick="S.mes=mesShift(S.mes,1);paneFin($('main'))" aria-label="Próximo mês">›</button></div>
  <div class="kpis">
    <div class="kpi"><span>Atendimentos</span><b>${f.sess.length}</b></div>
    <div class="kpi"><span>Faturado</span><b>${brl(f.faturado)}</b></div>
    <div class="kpi ok"><span>Recebido</span><b>${brl(f.recebido)}</b></div>
    <div class="kpi warn"><span>A receber</span><b>${brl(f.pendente)}</b></div>
    <div class="kpi bad"><span>Despesas</span><b>${brl(f.despesas)}</b></div>
    <div class="kpi main"><span>Saldo do mês</span><b>${brl(f.saldo)}</b></div></div>
  <div class="card"><h3>Últimos 6 meses</h3>
    <div class="bars">${hist.map(h => `<div class="bcol ${h.mm === mes ? 'cur' : ''}" title="${mesLabel(h.mm)}: faturado ${brl(h.fat)}, recebido ${brl(h.rec)}, despesas ${brl(h.desp)}" onclick="S.mes='${h.mm}';paneFin($('main'))">
      <div class="bstack"><i class="bf" style="height:${h.fat / max * 100}%"></i><i class="br" style="height:${h.rec / max * 100}%"></i><i class="bd" style="height:${h.desp / max * 100}%"></i></div>
      <small>${mesLabel(h.mm).slice(0, 3)}</small></div>`).join('')}</div>
    <div class="legend"><span><i class="bf"></i>Faturado</span><span><i class="br"></i>Recebido</span><span><i class="bd"></i>Despesas</span></div></div>
  <div class="card"><h3>Consultas do mês</h3>
    ${f.sess.length ? `<div class="tbl-wrap"><table class="list fin"><tr><th>Data / hora</th><th>Paciente</th><th>Valor</th><th>Situação</th><th>Forma</th><th>Cobrar</th></tr>
    ${f.sess.map(({ p, e }) => `<tr><td>${fmtD(e.data)}${e.hora ? '<br><small>' + esc(e.hora) + '</small>' : ''}</td>
      <td><a href="#" onclick="go('patient',{cur:'${p.id}',tab:'evolucao'});return false">${esc(p.ident.nome || '(sem nome)')}</a><br><small>${esc(e.tipo)}</small></td>
      <td><input class="vin" inputmode="decimal" value="${(e.valor || 0).toFixed(2).replace('.', ',')}" onchange="setPg('${p.id}','${e.id}','valor',this.value)"></td>
      <td><select class="pg ${e.pago ? 'ok' : 'warn'}" onchange="setPg('${p.id}','${e.id}','pago',this.value)"><option value="0" ${!e.pago ? 'selected' : ''}>Pendente</option><option value="1" ${e.pago ? 'selected' : ''}>Pago</option></select></td>
      <td><select onchange="setPg('${p.id}','${e.id}','forma',this.value)">${FORMAS.map(o => `<option ${e.forma === o ? 'selected' : ''}>${o}</option>`).join('')}</select></td>
      <td>${!e.pago && e.valor > 0 ? `<button class="pix-btn sm" onclick="cobrarSessao('${p.id}','${e.id}')">${PIX_ICON}Pix</button>` : ''}</td></tr>`).join('')}</table></div>`
    : '<div style="color:var(--muted);font-size:13px">Nenhuma consulta com valor neste mês. O valor é informado ao registrar a sessão em <b>4. Evolução</b>.</div>'}</div>
  ${pacs.length ? `<div class="card"><h3>Por paciente</h3><div class="tbl-wrap"><table class="list"><tr><th>Paciente</th><th>Consultas</th><th>Faturado</th><th>Recebido</th><th>A receber</th><th></th></tr>
    ${pacs.map(o => `<tr><td>${esc(o.nome)}</td><td>${o.n}</td><td>${brl(o.fat)}</td><td>${brl(o.rec)}</td><td>${o.fat - o.rec > 0 ? `<b style="color:var(--warn)">${brl(o.fat - o.rec)}</b>` : brl(0)}</td><td>${o.fat - o.rec > 0 ? `<button class="pix-btn sm" onclick="cobrarPendentes('${o.pid}','${mes}')">${PIX_ICON}Cobrar</button>` : ''}</td></tr>`).join('')}</table></div></div>` : ''}
  <div class="card"><h3>Outros lançamentos</h3>
    ${f.lanc.length ? `<div class="tbl-wrap"><table class="list"><tr><th>Data</th><th>Descrição</th><th>Categoria</th><th>Valor</th><th></th></tr>
      ${f.lanc.map(l => `<tr><td>${fmtD(l.data)}</td><td>${esc(l.descricao)}</td><td>${esc(l.categoria || '—')}</td><td style="color:${l.tipo === 'saida' ? 'var(--danger)' : 'var(--ok)'};font-weight:600">${l.tipo === 'saida' ? '− ' : '+ '}${brl(l.valor)}</td><td><button class="ghost sm danger" onclick="delLanc('${l.id}')">remover</button></td></tr>`).join('')}</table></div>` : '<div style="color:var(--muted);font-size:13px;margin-bottom:6px">Nenhum lançamento avulso neste mês.</div>'}
    <div class="grid" style="margin-top:12px">
      <div class="c3"><label>Tipo</label><select id="lTp" onchange="$('lCat').innerHTML=catOpts(this.value)"><option value="saida">Despesa (saída)</option><option value="entrada">Receita avulsa (entrada)</option></select></div>
      <div class="c3"><label>Data</label><input type="date" id="lDt" value="${mes === today().slice(0, 7) ? today() : mes + '-01'}"></div>
      <div class="c3"><label>Categoria</label><select id="lCat">${catOpts('saida')}</select></div>
      <div class="c3"><label>Valor (R$)</label><input id="lVal" inputmode="decimal" placeholder="0,00"></div>
      <div class="c12"><label>Descrição</label><input id="lDs" placeholder="Ex.: aluguel da sala, supervisão, anuidade CRP"></div></div>
    <div class="row-actions"><button class="pri" onclick="addLanc()">Adicionar lançamento</button></div></div>
  <div class="row-actions" style="justify-content:flex-start"><button onclick="exportFinCSV()">Exportar mês (planilha CSV)</button><button onclick="go('fin',{cur:null,finTab:'calendario',fcMes:S.mes})">${IC.calcash}<span>Ver calendário financeiro</span></button></div>`;
}
function catOpts(t) { return (t === 'entrada' ? ['Pacote de sessões', 'Avaliação', 'Supervisão prestada', 'Palestra / curso', 'Outros'] : ['Aluguel / sala', 'Supervisão', 'Conselho (CRP)', 'Impostos', 'Materiais e testes', 'Software / internet', 'Formação', 'Outros']).map(o => `<option>${o}</option>`).join(''); }
function addLanc() {
  const v = parseValor(val('lVal')), d = val('lDs');
  if (!v) return toast('Informe o valor'); if (!d) return toast('Informe a descrição');
  (DB.lancamentos = DB.lancamentos || []).push({ id: uid(), tipo: val('lTp'), data: val('lDt'), categoria: val('lCat'), descricao: d, valor: v });
  save(); toast('Lançamento adicionado'); paneFin($('main'));
}
function delLanc(id) { confirmBox('Remover lançamento?', 'Esta ação não pode ser desfeita.', 'Remover', () => { DB.lancamentos = DB.lancamentos.filter(l => l.id !== id); save(); paneFin($('main')); }); }
async function exportFinCSV() {
  const mes = S.mes, f = finMes(mes), q = s => '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"', n = v => v.toFixed(2).replace('.', ',');
  const rows = [['Data', 'Hora', 'Tipo', 'Paciente / descrição', 'Categoria', 'Valor', 'Situação', 'Forma']];
  f.sess.forEach(({ p, e }) => rows.push([fmtD(e.data), e.hora || '', 'Consulta', p.ident.nome, e.tipo, n(e.valor || 0), e.pago ? 'Pago' : 'Pendente', e.forma || '']));
  f.lanc.forEach(l => rows.push([fmtD(l.data), '', l.tipo === 'saida' ? 'Despesa' : 'Receita avulsa', l.descricao, l.categoria, (l.tipo === 'saida' ? '-' : '') + n(l.valor), l.tipo === 'saida' ? 'Pago' : 'Recebido', '']));
  rows.push([]); rows.push(['', '', '', 'Faturado', '', n(f.faturado)]); rows.push(['', '', '', 'Recebido', '', n(f.recebido)]); rows.push(['', '', '', 'A receber', '', n(f.pendente)]); rows.push(['', '', '', 'Despesas', '', n(f.despesas)]); rows.push(['', '', '', 'Saldo', '', n(f.saldo)]);
  const csv = '﻿' + rows.map(r => r.map(q).join(';')).join('\r\n');
  await deliverPDF(new Blob([csv], { type: 'text/csv' }), `Appsico-financeiro-${mes}.csv`);
}

/* ---------- Atestado e recibo (menu) ---------- */
function paneDocsCentral(m) {
  const p = S.cur ? P() : null;
  const rec = S.docKind === 'recibo', mod = S.docKind === 'modelos';
  m.innerHTML = `<div class="head"><div><h1>${rec ? 'Recibo' : mod ? 'Modelos de documentos' : 'Atestado / declaração'}</h1><div class="meta">Busque o paciente: os dados dele são preenchidos automaticamente.</div></div>${sairBtn()}</div>
    ${p ? `<div class="pick-sel">${avatarHTML(p)}<div style="flex:1;min-width:0"><b>${esc(p.ident.nome || '(sem nome)')}</b>
        <span>${pacInfo(p)}</span></div><button class="sm" onclick="S.cur=null;S.docQ='';renderMain()">Trocar paciente</button></div>
      <div id="pane"></div>`
    : `<div class="card"><label for="docQ">Paciente</label><input id="docQ" placeholder="Digite o nome ou CPF do paciente…" autocomplete="off" value="${esc(S.docQ || '')}">
      <div id="docRes" class="pick-list"></div></div>`}`;
  if (p) { paneEl = $('pane'); const kk = rec ? 'recibo' : mod ? 'modelo' : 'atestado'; if (EM.kind !== kk) EM = { kind: kk, edited: false }; if (mod) return paneModelo(p); paneEmitir(p, true); return; }
  const list = () => {
    const q = (S.docQ || '').toLowerCase().trim(), qd = q.replace(/\D/g, '');
    const ps = DB.patients.filter(x => !q || (x.ident.nome || '').toLowerCase().includes(q) || (qd && (x.ident.cpf || '').replace(/\D/g, '').includes(qd)))
      .sort((a, b) => (a.status === b.status ? 0 : a.status === 'ativo' ? -1 : 1) || (a.ident.nome || '').localeCompare(b.ident.nome || '')).slice(0, 30);
    $('docRes').innerHTML = ps.length ? ps.map(x => `<button class="pick" onclick="S.cur='${x.id}';EM.edited=false;renderMain()">${avatarHTML(x, '', true)}
      <div style="flex:1;min-width:0;text-align:left"><b>${esc(x.ident.nome || '(sem nome)')}</b><span>${pacInfo(x)}</span></div>${x.status === 'encerrado' ? '<span class="tag off">encerrado</span>' : ''}</button>`).join('')
      : `<div style="color:var(--muted);font-size:13px;padding:10px 2px">${DB.patients.length ? 'Nenhum paciente encontrado.' : 'Nenhum paciente cadastrado ainda.'}</div>`;
  };
  $('docQ').oninput = e => { S.docQ = e.target.value; list(); };
  list(); setTimeout(() => $('docQ') && $('docQ').focus(), 50);
}
const iniciais = n => (n || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(s => s[0]).join('').toUpperCase();
function pacInfo(p) {
  const a = age(p.ident.nascimento), ult = p.evolucao.length ? p.evolucao[p.evolucao.length - 1] : null;
  return [a !== null ? a + ' anos' : '', p.ident.cpf ? 'CPF ' + esc(p.ident.cpf) : '', ult ? 'última sessão ' + fmtD(ult.data) : 'sem sessões'].filter(Boolean).join(' · ');
}

/* ---------- Atestado e recibo ---------- */
function extenso(valor) {
  const U = ['', 'um', 'dois', 'três', 'quatro', 'cinco', 'seis', 'sete', 'oito', 'nove', 'dez', 'onze', 'doze', 'treze', 'quatorze', 'quinze', 'dezesseis', 'dezessete', 'dezoito', 'dezenove'];
  const D = ['', '', 'vinte', 'trinta', 'quarenta', 'cinquenta', 'sessenta', 'setenta', 'oitenta', 'noventa'];
  const C = ['', 'cento', 'duzentos', 'trezentos', 'quatrocentos', 'quinhentos', 'seiscentos', 'setecentos', 'oitocentos', 'novecentos'];
  const ate999 = n => { if (!n) return ''; if (n === 100) return 'cem'; const ps = [], ce = Math.floor(n / 100), r = n % 100; if (ce) ps.push(C[ce]); if (r) ps.push(r < 20 ? U[r] : D[Math.floor(r / 10)] + (r % 10 ? ' e ' + U[r % 10] : '')); return ps.join(' e '); };
  const inteiro = n => {
    if (!n) return 'zero';
    const g = [[Math.floor(n / 1e6), 'mi'], [Math.floor((n % 1e6) / 1000), 'mil'], [n % 1000, '']].filter(x => x[0]);
    return g.map(([v, k], i) => {
      const t = k === 'mi' ? (v === 1 ? 'um milhão' : ate999(v) + ' milhões') : k === 'mil' ? (v === 1 ? 'mil' : ate999(v) + ' mil') : ate999(v);
      const sep = i === 0 ? '' : (v < 100 || v % 100 === 0) ? ' e ' : ' ';
      return sep + t;
    }).join('');
  };
  const cents = Math.round(valor * 100), r = Math.floor(cents / 100), c = cents % 100;
  const parts = [];
  if (r) parts.push(inteiro(r) + (r === 1 ? ' real' : (r % 1e6 === 0 ? ' de reais' : ' reais')));
  if (c) parts.push(inteiro(c) + (c === 1 ? ' centavo' : ' centavos'));
  return parts.join(' e ') || 'zero real';
}
const parseValor = s => { const n = parseFloat(String(s).replace(/[^\d,.-]/g, '').replace(/\.(?=\d{3}(\D|$))/g, '').replace(',', '.')); return isNaN(n) ? 0 : n; };
const brl = n => n.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
const dataExtenso = d => { if (!d) return ''; const x = new Date(d + 'T12:00'); return x.toLocaleDateString('pt-BR', { day: 'numeric', month: 'long', year: 'numeric' }); };

let EM = { kind: 'atestado', edited: false };
function paneEmitir(p, single) {
  const k = EM.kind;
  const resp = p.ident.responsaveis.find(r => r.nome);
  const ag = age(p.ident.nascimento), menor = (ag !== null && ag < 18) || p.ident.interditado;
  const ult = [...p.evolucao].reverse().find(e => !/Falta/.test(e.tipo));
  const falta = !DB.prof.cpf || !DB.prof.cidade;
  pane(`${single ? '' : `<div class="seg"><button class="${k === 'atestado' ? 'on' : ''}" onclick="EM={kind:'atestado',edited:false};renderMain()">Atestado / declaração</button><button class="${k === 'recibo' ? 'on' : ''}" onclick="EM={kind:'recibo',edited:false};renderMain()">Recibo</button></div>`}
  ${falta ? `<div class="note warn">Complete CPF e cidade do profissional em <a href="#" onclick="go('settings');return false">Configurações</a> para que apareçam nos documentos.</div>` : ''}
  ${k === 'atestado' ? `<div class="card"><h3>Atestado psicológico ou declaração</h3><div class="grid">
      <div class="c6"><label>Tipo de documento</label><select id="aTipo" onchange="emText(true)">
        <option value="atestado">Atestado psicológico</option><option value="declaracao">Declaração de comparecimento</option></select></div>
      <div class="c3"><label>Data de emissão</label><input type="date" id="aEm" value="${today()}" onchange="emText()"></div>
      <div class="c3"><label>Cidade</label><input id="aCid" value="${esc(DB.prof.cidade || '')}" onchange="emText()"></div>
      <div class="c6"><label>Solicitante</label><input id="aSol" value="${esc(p.ident.nome)}" oninput="emText()"></div>
      <div class="c6"><label>Finalidade</label><input id="aFin" placeholder="Ex.: apresentação ao empregador" oninput="emText()"></div>
      <div class="c12 at-only"><label>Condições psicológicas observadas (descrição técnica)</label><textarea id="aCond" style="min-height:70px" oninput="emText()"></textarea></div>
      <div class="c3 at-only"><label>Afastamento (dias)</label><input type="number" id="aDias" min="0" oninput="emText()"></div>
      <div class="c3 at-only"><label>A partir de</label><input type="date" id="aIni" value="${today()}" onchange="emText()"></div>
      <div class="c3 at-only"><label>CID (opcional)</label><input id="aCid10" oninput="emText()"></div>
      <div class="c3 at-only"><label>&nbsp;</label><label class="check"><input type="checkbox" id="aAut" onchange="emText()"> Paciente autorizou o CID</label></div>
      <div class="c4 dc-only"><label>Data do atendimento</label><input type="date" id="dData" value="${ult ? ult.data : today()}" onchange="emText()"></div>
      <div class="c4 dc-only"><label>Das</label><input type="time" id="dIni" value="${ult && ult.hora ? ult.hora : horaAgora()}" onchange="emText()"></div>
      <div class="c4 dc-only"><label>Às</label><input type="time" id="dFim" value="${ult && ult.horaFim ? ult.horaFim : somaMin(ult && ult.hora ? ult.hora : horaAgora(), 50)}" onchange="emText()"></div>
      <div class="c12"><label>Texto do documento <span style="font-weight:400">(gerado automaticamente; pode editar)</span></label><textarea id="aTxt" style="min-height:140px" oninput="EM.edited=true"></textarea></div>
    </div><div class="row-actions"><button onclick="EM.edited=false;emText()">Refazer texto</button><button class="pri" onclick="emitir()">Gerar documento</button></div></div>`
  : `<div class="card"><h3>Recibo</h3><div class="grid">
      <div class="c3"><label>Nº do recibo</label><input id="rNum" value="${(DB.prof.reciboSeq || 0) + 1}"></div>
      <div class="c3"><label>Valor (R$)</label><input id="rVal" inputmode="decimal" placeholder="150,00" value="${valorMes(p)}" oninput="emText()"></div>
      <div class="c3"><label>Data de emissão</label><input type="date" id="rEm" value="${today()}" onchange="emText()"></div>
      <div class="c3"><label>Cidade</label><input id="rCid" value="${esc(DB.prof.cidade || '')}" oninput="emText()"></div>
      <div class="c8"><label>Pagador (nome)</label><input id="rPag" value="${esc(menor && resp ? resp.nome : p.ident.nome)}" oninput="emText()"></div>
      <div class="c4"><label>CPF do pagador</label><input id="rCpf" inputmode="numeric" value="${esc(menor && resp ? resp.cpf : p.ident.cpf)}" oninput="emText()"></div>
      <div class="c8"><label>Referente a</label><input id="rRef" value="atendimento psicológico" oninput="emText()"></div>
      <div class="c4"><label>Forma de pagamento</label><select id="rForma" onchange="emText()">${FORMAS.map(o => `<option>${o}</option>`).join('')}</select></div>
      <div class="c12"><label>Datas das sessões</label><input id="rDatas" value="${esc(sessoesMes(p))}" placeholder="Ex.: 04, 11, 18 e 25/11/2026" oninput="emText()"></div>
      <div class="c12"><label>Texto do recibo <span style="font-weight:400">(gerado automaticamente; pode editar)</span></label><textarea id="aTxt" style="min-height:120px" oninput="EM.edited=true"></textarea></div>
    </div><div class="row-actions"><button onclick="EM.edited=false;emText()">Refazer texto</button><button class="pri" onclick="emitir()">Gerar recibo</button></div></div>`}
  <div class="note">Os documentos emitidos ficam salvos automaticamente em <b>6. Documentos</b>, como exige a guarda do prontuário.</div>`);
  emText(true);
}
function valorMes(p) { const m = today().slice(0, 7), t = p.evolucao.filter(e => e.data.startsWith(m) && e.valor > 0).reduce((s, e) => s + e.valor, 0); return t ? t.toFixed(2).replace('.', ',') : (p.ident.valorSessao || ''); }
function sessoesMes(p) {
  const m = today().slice(0, 7);
  const ds = p.evolucao.filter(e => e.data.startsWith(m) && !/Falta/.test(e.tipo)).map(e => fmtD(e.data));
  return ds.length ? ds.join(', ') : '';
}
function emText(force) {
  const p = P(); if (!p || !$('aTxt')) return;
  if (EM.kind === 'atestado') {
    const decl = val('aTipo') === 'declaracao';
    paneEl.querySelectorAll('.at-only').forEach(e => e.style.display = decl ? 'none' : '');
    paneEl.querySelectorAll('.dc-only').forEach(e => e.style.display = decl ? '' : 'none');
  }
  if (EM.edited && !force) return;
  if (force) EM.edited = false;
  if (EM.kind === 'modelo') return modeloTexto(p);
  const nome = p.ident.nome || '[nome do paciente]', cpf = p.ident.cpf ? `, CPF ${p.ident.cpf},` : '';
  let t;
  if (EM.kind === 'atestado') {
    if (val('aTipo') === 'declaracao') {
      t = `Declaro, para os devidos fins${val('aFin') ? ' de ' + val('aFin') : ''}, que ${nome}${cpf} compareceu a atendimento psicológico no dia ${fmtD(val('dData'))}, no horário das ${val('dIni')} às ${val('dFim')}.`;
    } else {
      const dias = parseInt(val('aDias'), 10);
      t = `Atesto, a pedido de ${val('aSol') || nome}${val('aFin') ? ', para fins de ' + val('aFin') : ''}, que ${nome}${cpf} encontra-se em acompanhamento psicológico sob meus cuidados.`;
      if (val('aCond')) t += ` ${val('aCond')}`;
      if (dias > 0) t += ` Por essa razão, necessita de afastamento de suas atividades por ${dias} (${extenso(dias).replace(/ rea(l|is)$/, '')}) dia${dias > 1 ? 's' : ''}, a partir de ${fmtD(val('aIni'))}.`;
      if (val('aCid10') && $('aAut').checked) t += ` CID: ${val('aCid10')}, informado com autorização expressa do(a) paciente.`;
    }
  } else {
    const v = parseValor(val('rVal'));
    t = `Recebi de ${val('rPag') || '[pagador]'}${val('rCpf') ? ', CPF ' + val('rCpf') : ''}, a importância de ${v ? brl(v) + ' (' + extenso(v) + ')' : 'R$ [valor]'}, referente a ${val('rRef') || 'atendimento psicológico'}${val('rPag') && val('rPag') !== p.ident.nome ? ' prestado a ' + nome : ''}${val('rDatas') ? ', nas sessões de ' + val('rDatas') : ''}. Forma de pagamento: ${val('rForma')}.\n\nPara clareza, firmo o presente recibo, dando plena quitação do valor recebido.`;
  }
  $('aTxt').value = t;
}
function emitir() {
  const p = P(), texto = val('aTxt');
  if (!texto) return toast('O texto está vazio');
  let d;
  if (EM.kind === 'modelo') {
    const mo = MODELOS[val('mTipo')];
    d = { kind: val('mTipo'), titulo: mo.titulo, texto, data: val('mEm'), cidade: val('mCid') };
  } else if (EM.kind === 'atestado') {
    const decl = val('aTipo') === 'declaracao';
    if (!decl && $('aCid10').value.trim() && !$('aAut').checked) return toast('Marque a autorização do paciente para incluir o CID, ou apague o CID.');
    d = { kind: decl ? 'declaracao' : 'atestado', titulo: decl ? 'DECLARAÇÃO' : 'ATESTADO PSICOLÓGICO', texto, data: val('aEm'), cidade: val('aCid') };
  } else {
    const v = parseValor(val('rVal')); if (!v) return toast('Informe o valor');
    d = { kind: 'recibo', titulo: 'RECIBO', numero: val('rNum'), valor: v, texto, data: val('rEm'), cidade: val('rCid') };
    const n = parseInt(d.numero, 10); if (n > (DB.prof.reciboSeq || 0)) DB.prof.reciboSeq = n;
  }
  d.prof = { nome: p.ident.psicologo || DB.prof.nome, crp: p.ident.crp || DB.prof.crp, cpf: DB.prof.cpf || '', endereco: DB.prof.endereco || '', telefone: DB.prof.telefone || '', email: DB.prof.email || V.email };
  const tipoDoc = DOC_NOME[d.kind] || 'Documento';
  const item = { id: uid(), data: d.data, tipo: tipoDoc, titulo: d.kind === 'recibo' ? `Recibo nº ${d.numero} — ${brl(d.valor)}` : tipoDoc + ' emitido', desc: texto.slice(0, 140) + (texto.length > 140 ? '…' : ''), instrumento: '', arquivo: null, emitido: d };
  p.documentos.push(item); save();
  showEmitido(d, p);
}
function reopenEmitido(id) { const p = P(), d = p.documentos.find(x => x.id === id); if (d && d.emitido) showEmitido(d.emitido, p); }
function paperHTML(d) {
  const pr = d.prof;
  return `<div class="paper">
    <div class="ph"><div><b>${esc(pr.nome)}</b><br>Psicólogo(a) · CRP ${esc(pr.crp)}${d.kind === 'recibo' && pr.cpf ? ' · CPF ' + esc(pr.cpf) : ''}</div>
      <div style="text-align:right">${esc([pr.telefone, pr.email].filter(Boolean).join(' · '))}<br>${esc(pr.endereco)}</div></div>
    <div class="pbar"></div>
    ${d.kind === 'recibo' ? `<div class="pval"><span>Nº ${esc(d.numero)}</span><b>${brl(d.valor)}</b></div>` : ''}
    <h2 class="pt">${esc(d.titulo)}</h2>
    ${d.texto.split(/\n+/).map(t => SEC_RE.test(t) ? `<p class="psec">${esc(t)}</p>` : `<p>${esc(t)}</p>`).join('')}
    <p class="pdate">${esc(d.cidade ? d.cidade + ', ' : '')}${dataExtenso(d.data)}.</p>
    <div class="psig"><i></i>${esc(pr.nome)}<br>Psicólogo(a) · CRP ${esc(pr.crp)}${d.kind === 'recibo' && pr.cpf ? '<br>CPF ' + esc(pr.cpf) : ''}</div>
  </div>`;
}
const hostClaude = () => { try { return window.claude || (window.parent !== window && window.parent.claude) || null; } catch (e) { return null; } };
function waPhone(p) {
  const ag = age(p.ident.nascimento), menor = (ag !== null && ag < 18) || p.ident.interditado;
  const r = p.ident.responsaveis.find(x => x.telefone);
  let t = ((menor && r ? r.telefone : p.ident.telefone) || (r ? r.telefone : '') || '').replace(/\D/g, '');
  if (t.length === 10 || t.length === 11) t = '55' + t;
  return t;
}
const DOC_NOME = { atestado: 'Atestado psicológico', declaracao: 'Declaração', recibo: 'Recibo', relatorio: 'Relatório psicológico', parecer: 'Parecer psicológico', acomp: 'Declaração de acompanhamento', encaminhamento: 'Encaminhamento' };
function docNome(d) { return (DOC_NOME[d.kind] || 'documento').toLowerCase(); }
function showEmitido(d, p) {
  const inHost = !!hostClaude();
  const fname = `${d.kind === 'recibo' ? 'Recibo-' + d.numero : (DOC_NOME[d.kind] || 'Documento').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/\s+/g, '-')}-${(p.ident.nome || 'paciente').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^\w]+/g, '-')}-${d.data}.pdf`;
  modal(`<div class="doc-head"><h2 style="margin:0">${esc(DOC_NOME[d.kind] || 'Documento')}</h2>
      <button class="ghost" onclick="closeModal()">Fechar</button></div>
    <div class="doc-actions">
      <button class="act" id="actPdf">${IC.file}<span>Gerar PDF</span></button>
      <button class="act" id="actPrt">${IC.printer}<span>Imprimir</span></button>
      <button class="act wa" id="actWa">${WA_ICON}<span>Enviar pelo WhatsApp</span></button>
    </div>
    <div id="docMsg"></div>
    <div class="paper-wrap">${paperHTML(d)}</div>`);
  const run = async (btn, fn) => { if (btn.disabled) return; btn.disabled = true; btn.classList.add('loading'); try { await fn(); } catch (e) { toast('Não foi possível concluir: ' + (e.message || e)); } finally { btn.disabled = false; btn.classList.remove('loading'); } };
  const msg = h => { $('docMsg').innerHTML = h ? `<div class="note" style="margin:0 0 12px">${h}</div>` : ''; };
  $('actPdf').onclick = () => run($('actPdf'), () => deliverPDF(buildPDF(d), fname));
  $('actPrt').onclick = () => run($('actPrt'), async () => {
    if (NATIVE) {
      const blob = buildPDF(d);
      const b64 = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1]); r.onerror = rej; r.readAsDataURL(blob); });
      await FS.writeFile({ path: fname, data: b64, directory: 'CACHE' }); tempFiles.push(fname);
      if (window.AppsicoPrint) { window.AppsicoPrint(fname, fname.replace(/\.pdf$/, '')); return; }
      msg('Escolha um leitor de PDF (ex.: Google Drive) e use a opção <b>Imprimir</b> dele.'); return deliverPDF(blob, fname);
    }
    if (inHost) { msg('A impressão direta não é permitida nesta visualização. O PDF foi gerado: abra o arquivo e imprima pelo leitor de PDF.'); return deliverPDF(buildPDF(d), fname); }
    printPaper(d);
  });
  $('actWa').onclick = () => run($('actWa'), async () => {
    const blob = buildPDF(d), texto = `Olá! Segue o ${docNome(d)} em PDF. — ${d.prof.nome}, Psicólogo(a) CRP ${d.prof.crp}`;
    if (NATIVE) {
      const b64 = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1]); r.onerror = rej; r.readAsDataURL(blob); });
      const w = await FS.writeFile({ path: fname, data: b64, directory: 'CACHE' }); tempFiles.push(fname);
      msg('O WhatsApp vai abrir com o PDF anexado: escolha o contato e envie.');
      try { await SHARE.share({ title: fname, text: texto, files: [w.uri], dialogTitle: 'Enviar pelo WhatsApp', package: 'com.whatsapp' }); } catch (e) { if (!/cancel/i.test(e.message || '')) throw e; }
      return;
    }
    const file = new File([blob], fname, { type: 'application/pdf' });
    if (!inHost && navigator.canShare && navigator.canShare({ files: [file] })) {
      try { await navigator.share({ files: [file], title: fname, text: texto }); return; } catch (e) { if (e.name === 'AbortError') return; }
    }
    await deliverPDF(blob, fname);
    const tel = waPhone(p), url = `https://wa.me/${tel}?text=${encodeURIComponent(texto)}`;
    msg(`O PDF foi gerado. Agora abra a conversa e <b>anexe o arquivo ${esc(fname)}</b> (📎 → Documento).
      <div style="margin-top:8px"><a class="wa-link" href="${url}" target="_blank" rel="noopener">${WA_ICON}<span>Abrir WhatsApp${tel ? ' de ' + esc(p.ident.nome.split(' ')[0] || 'paciente') : ''}</span></a></div>
      ${tel ? '' : '<div style="margin-top:6px;font-size:12px">Cadastre o telefone do paciente para abrir a conversa direto com ele.</div>'}`);
  });
}
const G_ICON_SM = '<svg class="h-ic" viewBox="0 0 24 24"><path fill="#0f9d58" d="M7.7 3.5h8.6l6.2 10.8h-8.6z"/><path fill="#fbbc04" d="M1.5 14.3 5.8 21.7 12 11 7.7 3.5z"/><path fill="#4285f4" d="M5.8 21.7h12.4l4.3-7.4H10.1z"/></svg>';
const DRIVE_ICON = '<svg viewBox="0 0 24 24"><path fill="#0f9d58" d="M7.7 3.5h8.6l6.2 10.8h-8.6z"/><path fill="#fbbc04" d="M1.5 14.3 5.8 21.7 12 11 7.7 3.5z"/><path fill="#4285f4" d="M5.8 21.7h12.4l4.3-7.4H10.1z"/></svg>';
const PIX_ICON = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17.3 16.7a2.9 2.9 0 0 1-2.1-.9l-3-3a.6.6 0 0 0-.8 0l-3 3a2.9 2.9 0 0 1-2.1.9h-.6l3.8 3.8a3 3 0 0 0 4.3 0l3.9-3.8h-.4zM6.3 7.3c.8 0 1.5.3 2.1.9l3 3c.2.2.6.2.8 0l3-3a2.9 2.9 0 0 1 2.1-.9h.4l-3.9-3.8a3 3 0 0 0-4.3 0L5.7 7.3h.6zm14.2 2.5-2.3-2.3h-.9c-.6 0-1.1.2-1.5.6l-3 3a1.5 1.5 0 0 1-2.1 0l-3-3c-.4-.4-1-.6-1.5-.6H5.1L2.9 9.8a3 3 0 0 0 0 4.3l2.2 2.3h1.1c.6 0 1.1-.2 1.5-.6l3-3c.6-.6 1.6-.6 2.1 0l3 3c.4.4 1 .6 1.5.6h.9l2.3-2.3a3 3 0 0 0 0-4.3z"/></svg>';
const WA_ICON = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 0 0-8.6 15.1L2 22l5-1.3A10 10 0 1 0 12 2zm0 18.2c-1.5 0-3-.4-4.3-1.2l-.3-.2-3 .8.8-2.9-.2-.3A8.2 8.2 0 1 1 12 20.2zm4.5-6.1c-.2-.1-1.5-.7-1.7-.8-.2-.1-.4-.1-.6.1l-.8 1c-.1.2-.3.2-.5.1a6.7 6.7 0 0 1-3.3-2.9c-.2-.4.2-.4.7-1.3.1-.2 0-.3 0-.4l-.8-1.9c-.2-.5-.4-.4-.6-.4h-.5c-.2 0-.4.1-.7.3-.2.3-.9.9-.9 2.2s.9 2.5 1 2.7c.1.2 1.8 2.8 4.4 3.9 1.6.7 2.3.8 3.1.6.5-.1 1.5-.6 1.7-1.2.2-.6.2-1.1.2-1.2-.1-.1-.3-.2-.5-.3z"/></svg>';
function buildPDF(d) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'mm', format: 'a4' }), pr = d.prof, L = 22, Wd = 166;
  doc.setTextColor(21, 26, 51);
  doc.setFont('helvetica', 'bold'); doc.setFontSize(13); doc.text(pr.nome || '', L, 24);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5); doc.setTextColor(90, 96, 128);
  doc.text(`Psicólogo(a) · CRP ${pr.crp}${d.kind === 'recibo' && pr.cpf ? ' · CPF ' + pr.cpf : ''}`, L, 29.5);
  const contato = [pr.telefone, pr.email].filter(Boolean).join(' · ');
  if (contato) doc.text(contato, L + Wd, 24, { align: 'right' });
  if (pr.endereco) doc.text(doc.splitTextToSize(pr.endereco, 90), L + Wd, 29.5, { align: 'right' });
  // faixa nas cores do Appsico
  const cols = [[10, 61, 145], [10, 134, 194], [20, 191, 165]];
  for (let i = 0; i < 60; i++) { const t = i / 59, a = t < .5 ? cols[0] : cols[1], b = t < .5 ? cols[1] : cols[2], k = t < .5 ? t * 2 : (t - .5) * 2;
    doc.setFillColor(...a.map((v, j) => Math.round(v + (b[j] - v) * k))); doc.rect(L + Wd * i / 60, 36, Wd / 60 + .2, 1.1, 'F'); }
  let y = 58;
  if (d.kind === 'recibo') {
    doc.setDrawColor(11, 86, 184); doc.setLineWidth(.4); doc.roundedRect(L + Wd - 58, 44, 58, 16, 2, 2);
    doc.setTextColor(90, 96, 128); doc.setFontSize(9); doc.text(`Nº ${d.numero}`, L + Wd - 54, 50);
    doc.setTextColor(21, 26, 51); doc.setFont('helvetica', 'bold'); doc.setFontSize(14); doc.text(brl(d.valor), L + Wd - 4, 56.5, { align: 'right' });
    y = 74;
  }
  doc.setTextColor(21, 26, 51); doc.setFont('helvetica', 'bold'); doc.setFontSize(15); doc.text(d.titulo, 105, y, { align: 'center' });
  y += 14; doc.setFont('helvetica', 'normal'); doc.setFontSize(11.5);
  const lh = 6.4;
  d.texto.split(/\n+/).forEach(par => {
    if (SEC_RE.test(par)) { if (y > 225) { doc.addPage(); y = 30; } doc.setFont('helvetica', 'bold'); doc.text(par, L, y + 2); doc.setFont('helvetica', 'normal'); y += 9; return; }
    const lines = doc.splitTextToSize(par, Wd);
    if (lines.length * lh > 190) { lines.forEach(ln => { if (y > 262) { doc.addPage(); y = 30; } doc.text(ln, L, y); y += lh; }); y += 4; return; }
    if (y + lines.length * lh > 262) { doc.addPage(); y = 30; }
    doc.text(par, L, y, { maxWidth: Wd, align: 'justify', lineHeightFactor: 1.55 });
    y += lines.length * lh + 4;
  });
  y = Math.max(y + 8, 150);
  doc.text(`${d.cidade ? d.cidade + ', ' : ''}${dataExtenso(d.data)}.`, L + Wd, y, { align: 'right' });
  y += 34; if (y > 270) { doc.addPage(); y = 60; }
  doc.setDrawColor(21, 26, 51); doc.setLineWidth(.3); doc.line(65, y, 145, y);
  doc.setFontSize(10.5); doc.text(pr.nome || '', 105, y + 6, { align: 'center' });
  doc.setFontSize(9.5); doc.setTextColor(90, 96, 128); doc.text(`Psicólogo(a) · CRP ${pr.crp}`, 105, y + 11, { align: 'center' });
  if (d.kind === 'recibo' && pr.cpf) doc.text(`CPF ${pr.cpf}`, 105, y + 16, { align: 'center' });
  return doc.output('blob');
}
async function deliverPDF(blob, fname) {
  if (NATIVE) {
    try {
      const b64 = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1]); r.onerror = rej; r.readAsDataURL(blob); });
      const w = await FS.writeFile({ path: fname, data: b64, directory: 'CACHE' }); tempFiles.push(fname);
      await SHARE.share({ title: fname, url: w.uri, dialogTitle: 'Enviar ou imprimir PDF' });
    } catch (e) { if (!/cancel/i.test(e.message || '')) toast('Falha ao gerar PDF: ' + e.message); }
    return;
  }
  const host = hostClaude();
  if (host) {
    const dl = await host.use('downloads');
    if (dl) {
      try { await dl.save({ filename: fname, data: blob }); toast('PDF salvo'); }
      catch (e) { if (e && e.code !== 'declined') toast('Não foi possível salvar o PDF aqui'); }
      return;
    }
  }
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = fname; document.body.appendChild(a); a.click(); a.remove();
}
function printPaper(d) {
  const f = document.createElement('iframe'); f.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  document.body.appendChild(f);
  const css = [...document.styleSheets].map(s => { try { return [...s.cssRules].map(r => r.cssText).join('\n'); } catch (e) { return ''; } }).join('\n');
  f.contentDocument.write(`<html><head><style>${css}@page{size:A4;margin:0}body{background:#fff;margin:0}.paper{box-shadow:none;border:0;margin:0;width:auto;min-height:auto}</style></head><body>${paperHTML(d)}</body></html>`);
  f.contentDocument.close();
  setTimeout(() => { try { f.contentWindow.focus(); f.contentWindow.print(); } catch (e) { toast('Impressão indisponível aqui; use o PDF.'); } setTimeout(() => f.remove(), 2000); }, 300);
}
/* ---------- Modal ---------- */
function modal(h, cls) { $('modalBox').innerHTML = h; $('modal').classList.toggle('sheet', cls === 'sheet'); $('modal').classList.add('show'); }
function closeModal() { $('modal').classList.remove('show'); }
let _cb = null;
function confirmTyped(t, msg, word, cb) {
  modal(`<h2>${esc(t)}</h2><div class="note warn">${esc(msg)}</div><label for="ctIn">Para confirmar, escreva <b>${esc(word)}</b></label><input id="ctIn" autocomplete="off" placeholder="${esc(word)}">
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="btn-del" id="ctGo" disabled>${esc(word)}</button></div>`);
  $('ctIn').oninput = e => { $('ctGo').disabled = e.target.value.trim().toLowerCase() !== word.toLowerCase(); };
  $('ctGo').onclick = () => { closeModal(); cb(); };
}
function confirmBox(t, msg, btn, cb) { _cb = cb; modal(`<h2>${esc(t)}</h2><p>${esc(msg)}</p><div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" onclick="closeModal();_cb&&_cb()">${esc(btn)}</button></div>`); }

/* ---------- Bloqueio automático ---------- */
let lastAct = Date.now(), idleTimer = null, bgAt = 0;
function armIdle() {
  clearInterval(idleTimer);
  idleTimer = setInterval(() => { if (DEK && Date.now() - lastAct > CFG.autoLockMinutes * 60000) lockApp('Bloqueado por inatividade'); }, 15000);
}
['click', 'keydown', 'touchstart', 'scroll'].forEach(ev => document.addEventListener(ev, () => { lastAct = Date.now(); }, { passive: true }));

document.addEventListener('focusin', e => { const t = e.target; if (t && ['uPw', 'nPw', 'cPw', 'xPw', 'sNew'].includes(t.id)) pinHint(t.id); });
document.addEventListener('input', e => { const t = e.target; if (t && t.classList && t.classList.contains('pin')) { const v = t.value.replace(/\D/g, '').slice(0, 6); if (v !== t.value) t.value = v; } }, true);

/* ---------- Início ---------- */
const TEMAS = [
  ['padrao', 'Appsico', 'Azul-marinho, azul e verde-água do logo', '#061a46', 'linear-gradient(135deg,#0a3d91,#0a86c2,#14bfa5)', '#f3f5fb'],
  ['light', 'Claro', 'Menu branco, tudo claro', '#ffffff', 'linear-gradient(135deg,#0a3d91,#0a86c2,#14bfa5)', '#f3f5fb'],
  ['escuro', 'Escuro', 'Fundo escuro, descansa a vista', '#05081a', 'linear-gradient(135deg,#0a3d91,#0a86c2,#14bfa5)', '#0b0f24'],
  ['oceano', 'Oceano', 'Azul petróleo e turquesa', '#062c43', 'linear-gradient(135deg,#2ed3c6,#0891b2,#0e5e9c)', '#f1f8fa'],
  ['floresta', 'Floresta', 'Verde sálvia e calmo', '#0f2e25', 'linear-gradient(135deg,#6ee7b7,#10b981,#047857)', '#f2f7f4'],
  ['lavanda', 'Lavanda', 'Lilás suave', '#271a47', 'linear-gradient(135deg,#c4b5fd,#8b5cf6,#6d28d9)', '#f6f3fd'],
  ['terracota', 'Terracota', 'Tons quentes de terra', '#3a2018', 'linear-gradient(135deg,#fbbf24,#ea7a2a,#c2410c)', '#faf5f0'],
  ['rosa', 'Rosa', 'Rosa e coral', '#3b1230', 'linear-gradient(135deg,#fda4af,#ec4899,#be185d)', '#fdf3f7']
];
function applyTheme() {
  const t = pref.get('theme', 'padrao');
  TEMAS.forEach(x => document.body.classList.remove('t-' + x[0]));
  document.body.classList.toggle('light', t === 'light');
  document.body.classList.add('t-' + t);
  const tm = TEMAS.find(x => x[0] === t) || TEMAS[0], m = document.querySelector('meta[name=theme-color]');
  if (m) m.content = t === 'light' ? '#ffffff' : tm[3];
}
async function boot() {
  applyTheme();
  $('menuBtn').innerHTML = IC.menu;
  $('menuBtn').onclick = toggleSidebar;
  $('scrim').onclick = () => document.body.classList.remove('drawer');
  $('fab').onclick = () => newPatient();
  $('modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });
  if (APP) {
    APP.addListener('pause', () => { bgAt = Date.now(); if (DEK) flush(); });
    APP.addListener('resume', () => { if (DEK && bgAt && Date.now() - bgAt > CFG.backgroundLockSeconds * 1000) lockApp('Bloqueado após uso em segundo plano'); else if (DEK && typeof cloudLinked === 'function' && cloudLinked()) { refreshAcesso().then(render).catch(() => {}); syncNow(); } bgAt = 0; });
    APP.addListener('backButton', () => {
      if (document.querySelector('.lightbox')) return window._closeLightbox && window._closeLightbox();
      if ($('modal').classList.contains('show')) return closeModal();
      if (document.body.classList.contains('drawer')) return document.body.classList.remove('drawer');
      if (DEK && S.view === 'agenda' && S.agModo === 'dia') { S.agModo = 'mes'; return paneAgenda($('main')); }
      if (DEK && S.view === 'patient' && S.tab !== 'painel') return go('patient', { tab: 'painel' });
      if (DEK && S.view === 'patient') return go('home', { cur: null });
      if (DEK && S.view !== 'inicio') return go('inicio', { cur: null });
      APP.minimizeApp ? APP.minimizeApp() : APP.exitApp();
    });
  }
  const t0 = Date.now();
  let ok = true;
  if (!window.crypto || !crypto.subtle) ok = false;
  try { await loadVault(); } catch (e) { V = null; }
  await new Promise(r => setTimeout(r, Math.max(0, 1900 - (Date.now() - t0))));
  if (!ok) authScreen('<h2>Ambiente sem criptografia</h2><div class="sub">Este navegador não oferece criptografia segura. Abra o Appsico pelo app Android.</div>');
  else if (typeof CLOUD !== 'undefined' && CLOUD && (window._recuperarSenha || /type=recovery/.test(location.hash))) showNovaSenhaConta();
  else if (!V) (typeof CLOUD !== 'undefined' && CLOUD ? showCloudStart(/pago=1/.test(location.search) ? 'entrar' : 'criar') : showSetup()); else showLogin();
  window._bootOk = true;
  $('splash').classList.add('out');
  setTimeout(() => $('splash').remove(), 1000);
}
document.addEventListener('DOMContentLoaded', boot);
