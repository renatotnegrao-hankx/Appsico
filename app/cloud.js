'use strict';
/* =====================================================================
   Appsico — conta na nuvem (Supabase)
   - Os prontuários são criptografados NO APARELHO antes de subir.
     O servidor guarda só dados embaralhados (sigilo profissional).
   - A chave dos dados é embrulhada pela senha da conta e pelo código de
     recuperação; em cada aparelho ela também fica protegida pelo PIN.
   - Sincronização com mesclagem: mudanças feitas no celular e no
     computador ao mesmo tempo são combinadas registro a registro.
   - Enquanto config.js não tiver os dados do Supabase, o app funciona
     como antes (somente no aparelho).
   ===================================================================== */
const SUPA = CFG.supabase || {};
const CLOUD = !!(SUPA.url && SUPA.anonKey && window.supabase && window.supabase.createClient);
const sb = CLOUD ? window.supabase.createClient(SUPA.url, SUPA.anonKey, {
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: !NATIVE, storageKey: 'appsico-auth' }
}) : null;
const APP_URL = SUPA.appUrl || (NATIVE ? '' : location.origin + location.pathname);
const DISP = NATIVE ? 'Android' : 'Navegador';
const cloudLinked = () => !!(CLOUD && V && V.cloud && V.cloud.uid);

/* ---------- utilidades ---------- */
function fnv(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(36); }
const fh = v => fnv(JSON.stringify(v === undefined ? null : v)) + ':' + (JSON.stringify(v === undefined ? null : v) || '').length.toString(36);
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const isIdArr = v => Array.isArray(v) && v.every(x => isObj(x) && x.id != null);
const ABSENT = Symbol('ausente');
function hashTree(v, d) {
  const n = { h: fh(v) };
  if (d <= 0) return n;
  if (isIdArr(v) && v.length) { n.m = {}; v.forEach(x => { n.m[x.id] = hashTree(x, d - 1); }); }
  else if (isObj(v)) { n.m = {}; for (const k in v) n.m[k] = hashTree(v[k], d - 1); }
  return n;
}
// Mescla em 3 vias: base = como estava na última sincronização (só os "resumos"),
// l = este aparelho, r = nuvem. Se só um lado mudou, vale esse lado; se os dois mudaram,
// desce nos campos e registros (sessões, metas…) e, num conflito no mesmo campo, vale este aparelho.
function merge3(b, l, r) {
  if (l === ABSENT && r === ABSENT) return ABSENT;
  const lh = l === ABSENT ? null : fh(l), rh = r === ABSENT ? null : fh(r);
  if (lh !== null && lh === rh) return l;
  if (b) { if (lh === b.h) return r; if (rh === b.h) return l; }
  else { if (l === ABSENT) return r; if (r === ABSENT) return l; }
  if (l === ABSENT) return r;
  if (r === ABSENT) return l;
  const bm = b && b.m ? b.m : null;
  if (Array.isArray(l) && Array.isArray(r) && isIdArr(l) && isIdArr(r)) {
    const lm = new Map(l.map(x => [x.id, x])), rm = new Map(r.map(x => [x.id, x])), out = [], seen = new Set();
    for (const id of [...l.map(x => x.id), ...r.map(x => x.id)]) {
      if (seen.has(id)) continue; seen.add(id);
      const v = merge3(bm ? bm[id] : undefined, lm.has(id) ? lm.get(id) : ABSENT, rm.has(id) ? rm.get(id) : ABSENT);
      if (v !== ABSENT) out.push(v);
    }
    return out;
  }
  if (isObj(l) && isObj(r)) {
    const out = {};
    for (const k of new Set([...Object.keys(l), ...Object.keys(r)])) {
      const v = merge3(bm ? bm[k] : undefined, k in l ? l[k] : ABSENT, k in r ? r[k] : ABSENT);
      if (v !== ABSENT) out[k] = v;
    }
    return out;
  }
  return l;
}
const encJSON = async o => seal(DEK, te.encode(JSON.stringify(o)));
const decJSON = async (key, o) => JSON.parse(td.decode(await unseal(key, o)));
async function wrapAcct(senha, raw) { const salt = rnd(16); const k = await kdf('conta:' + senha, salt, ITER); return Object.assign({ salt: b64e(salt), it: ITER }, await seal(k, raw)); }
async function openAcct(senha, w) { const k = await kdf('conta:' + senha, b64d(w.salt), w.it); return unseal(k, w); }
async function wrapRec(rec, raw) { const salt = rnd(16); const k = await kdf(normRec(rec), salt, ITER); return Object.assign({ salt: b64e(salt), it: ITER }, await seal(k, raw)); }
function errMsg(e) {
  const m = String((e && (e.message || e.error_description || e.msg)) || e || '');
  if (/Invalid login credentials/i.test(m)) return 'E-mail ou senha incorretos.';
  if (/Email not confirmed/i.test(m)) return 'Confirme seu e-mail pelo link que enviamos antes de entrar.';
  if (/already registered|already been registered|User already/i.test(m)) return 'Este e-mail já tem conta. Toque em "Entrar".';
  if (/Password should be|weak/i.test(m)) return 'Senha fraca: use pelo menos 8 caracteres, com letras e números.';
  if (/rate limit|too many/i.test(m)) return 'Muitas tentativas. Aguarde alguns minutos.';
  if (/Failed to fetch|NetworkError|network/i.test(m)) return 'Sem conexão com a internet.';
  if (/assinatura inativa/i.test(m)) return 'Seu acesso terminou. Assine para continuar.';
  return m || 'Erro inesperado.';
}
const senhaOk = s => s.length >= 8 && /[A-Za-z]/.test(s) && /\d/.test(s);

/* ---------- base da última sincronização (guardada criptografada) ---------- */
let BASE = null;
async function loadBase() { if (BASE) return BASE; try { BASE = V.cloud.base ? await decJSON(DEK, V.cloud.base) : null; } catch (e) { BASE = null; } return BASE; }
async function setBase(db) { BASE = hashTree(db, 5); V.cloud.base = await encJSON(BASE); }

/* ---------- sincronização ---------- */
const SYNC = { st: 'off', at: null, msg: '' };
let syncBusy = null, syncAgain = false, syncTimer = null, syncLoop = null;
function setSync(st, msg) {
  SYNC.st = st; SYNC.msg = msg || ''; if (st === 'ok') SYNC.at = new Date();
  const el = document.getElementById('syncSt'); if (el) el.outerHTML = syncBadge();
}
function syncBadge() {
  if (!cloudLinked()) return '<span id="syncSt"></span>';
  const t = SYNC.at ? SYNC.at.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }) : '';
  const txt = { ok: `Sincronizado${t ? ' às ' + t : ''}`, sync: 'Sincronizando…', pend: 'Alterações a enviar', off: 'Sem internet — envia depois', login: 'Entre de novo para sincronizar', ro: 'Modo consulta', err: 'Erro ao sincronizar' }[SYNC.st] || '';
  return `<button id="syncSt" class="sync-st s-${SYNC.st}" onclick="${SYNC.st === 'login' ? 'cloudReauth()' : 'syncNow(true)'}" title="${esc(SYNC.msg || txt)}"><i></i><span>${txt}</span></button>`;
}
function cloudDirty() { if (!cloudLinked()) return; if (SYNC.st === 'ok') setSync('pend'); clearTimeout(syncTimer); syncTimer = setTimeout(() => syncNow(), 3000); }
function softRender() {
  const ae = document.activeElement;
  if ($('modal').classList.contains('show') || (ae && /INPUT|TEXTAREA|SELECT/.test(ae.tagName))) { S._dirtyView = true; return; }
  if (S.cur && !DB.patients.some(p => p.id === S.cur)) { S.cur = null; S.view = 'home'; }
  render();
}
async function syncNow(manual) {
  if (!cloudLinked() || !DEK || !DB) return;
  if (syncBusy) { syncAgain = true; return syncBusy; }
  syncBusy = (async () => {
    setSync('sync');
    try {
      const { data: ses } = await sb.auth.getSession();
      if (!ses || !ses.session) { setSync('login'); if (manual) cloudReauth(); return; }
      if (manual || !V.cloud.acesso || Date.now() - (V.cloud.acessoEm || 0) > 10 * 60000) {
        const antes = JSON.stringify(acessoInfo()); await refreshAcesso();
        if (JSON.stringify(acessoInfo()) !== antes) softRender();
      }
      const base = await loadBase();
      for (let tent = 0; tent < 5; tent++) {
        const { data: h, error: e1 } = await sb.from('cofres').select('versao').eq('user_id', V.cloud.uid).maybeSingle();
        if (e1) throw e1;
        if (!h) throw new Error('Cofre não encontrado na nuvem.');
        let remote = null, remoteH = null;
        if (h.versao !== V.cloud.ver || !base) {
          const { data: row, error: e2 } = await sb.from('cofres').select('versao,dados').eq('user_id', V.cloud.uid).single();
          if (e2) throw e2;
          remote = await decJSON(DEK, row.dados); remoteH = fh(remote);
          const merged = merge3(base, DB, remote);
          const mudou = fh(merged) !== fh(DB);
          DB = merged; V.cloud.ver = row.versao;
          if (mudou) { snapPacientes(); softRender(); }
          h.versao = row.versao;
        }
        const atual = fh(DB);
        const precisaEnviar = remote ? atual !== remoteH : !(base && atual === base.h);
        if (!precisaEnviar) { await setBase(DB); await persist(); snapPacientes(); setSync('ok'); return; }
        const { data: nv, error: e3 } = await sb.rpc('salvar_cofre', { p_dados: await encJSON(DB), p_base: h.versao, p_disp: DISP });
        if (e3) { if (/sem_assinatura/.test(String(e3.message))) { await setBase(DB); await persist(); snapPacientes(); setSync('ro', 'Modo consulta: sem assinatura ativa'); return; } throw e3; }
        if (nv) { V.cloud.ver = nv; await setBase(DB); await persist(); setSync('ok'); return; }
        // outro aparelho salvou antes: busca de novo, mescla e tenta outra vez
      }
      throw new Error('Não foi possível concluir a sincronização. Tente de novo.');
    } catch (e) {
      const m = errMsg(e);
      if (/internet/.test(m)) setSync('off', m);
      else if (/JWT|session|refresh/i.test(String(e && e.message))) setSync('login', m);
      else setSync('err', m);
      if (manual) toast(m);
    }
  })();
  try { await syncBusy; } finally { syncBusy = null; if (syncAgain) { syncAgain = false; setTimeout(() => syncNow(), 500); } }
}
function cloudStart() {
  if (!cloudLinked()) return;
  snapPacientes();
  setSync(SYNC.st === 'off' ? 'off' : 'pend');
  syncNow();
  clearInterval(syncLoop); syncLoop = setInterval(() => { if (DEK) syncNow(); }, 60000);
}
function cloudStop() { clearInterval(syncLoop); clearTimeout(syncTimer); BASE = null; }
async function cloudBeforeLock() {
  if (!cloudLinked() || !DEK) return;
  clearTimeout(syncTimer);
  await Promise.race([syncNow(), new Promise(r => setTimeout(r, 5000))]).catch(() => {});
}
window.addEventListener('online', () => { if (DEK) syncNow(); });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && DEK && cloudLinked()) syncNow(); });

/* ---------- acesso: teste grátis e assinatura ---------- */
async function refreshAcesso() {
  if (!cloudLinked()) return null;
  const { data, error } = await sb.rpc('meu_acesso');
  if (error) throw error;
  if (data) { V.cloud.acesso = data; V.cloud.acessoEm = Date.now(); V.cloud.offset = new Date(data.agora).getTime() - Date.now(); await writeVault().catch(() => {}); }
  return data;
}
// Regra de acesso (decisão do dono do app):
// - 15 dias de teste grátis com tudo liberado, depois só com assinatura ativa;
// - sem assinatura ativa o app NÃO registra nada novo: só deixa ver e exportar os prontuários
//   (o psicólogo é obrigado pelo CFP a guardar e poder acessar os registros);
// - sem internet o app funciona até o vencimento conhecido, mas precisa conferir a
//   assinatura no servidor pelo menos a cada 7 dias (e não aceita relógio atrasado).
const DIAS_OFFLINE = 7;
function acessoInfo() {
  const a = V && V.cloud && V.cloud.acesso; if (!a) return { ativo: true, teste: true, dias: 15, desconhecido: true };
  const agora = Date.now() + (V.cloud.offset || 0);
  const teste = a.teste_ate ? new Date(a.teste_ate).getTime() : 0, pago = a.valido_ate ? new Date(a.valido_ate).getTime() : 0;
  const emDia = Math.max(teste, pago) > agora, emTeste = teste > agora && !(pago > agora);
  const fim = emTeste ? teste : pago;
  // conferência periódica: última resposta do servidor há mais de 7 dias, ou relógio voltou no tempo
  const ultima = a.agora ? new Date(a.agora).getTime() : 0;
  const conferir = emDia && !!ultima && (agora - ultima > DIAS_OFFLINE * 864e5 || agora < ultima - 36e5);
  return { ativo: emDia && !conferir, conferir, teste: emTeste, plano: a.plano, ate: fim ? new Date(fim).toISOString().slice(0, 10) : null, dias: fim ? Math.max(0, Math.ceil((fim - agora) / 864e5)) : 0, admin: !!a.admin };
}
// Sem acesso ativo: modo consulta. Nenhum paciente pode ser cadastrado ou alterado,
// nem agenda, financeiro, documentos etc. Ver e exportar continua liberado.
const LIMITE_GRATIS = 0;
const planoGratis = () => cloudLinked() && !acessoInfo().ativo;
const modoConsulta = planoGratis;
const pacienteBloqueado = id => modoConsulta();
let PH = null; // como os dados estavam na última gravação aceita
function snapPacientes() { PH = DB ? fh(DB) : null; }
let _bloqAviso = 0;
function cloudBloqueia() {
  if (!modoConsulta()) { PH = null; return false; }
  if (!PH) { snapPacientes(); return false; }
  if (PH === fh(DB)) return false;
  // desfaz a alteração: volta ao último estado salvo neste aparelho
  (async () => { try { if (V.data) DB = await decJSON(DEK, V.data); } catch (e) {} snapPacientes(); closeModal(); render(); if (Date.now() - _bloqAviso > 1500) { _bloqAviso = Date.now(); paywall(acessoInfo().conferir ? 'conferir' : 'gratis'); } })();
  return true;
}
const PLANOS_NUVEM = [
  { id: 'mensal', nome: 'Mensal', preco: 'R$ 24,90', per: 'por mês', obs: 'Cartão · renova sozinho · cancele quando quiser' },
  { id: 'anual', nome: 'Anual', preco: 'R$ 199,00', per: 'por ano', obs: 'Cartão · renova sozinho · sai por R$ 16,58/mês', tag: 'Economize 33%' },
  { id: 'anualpix', nome: 'Anual no Pix', preco: 'R$ 199,00', per: 'pagamento único', obs: 'Pix ou cartão · vale 1 ano · sem renovação automática', tag: 'Aceita Pix' }
];
function abrirLink(url) {
  if (NATIVE && window.AppsicoNative && AppsicoNative.openExternal) AppsicoNative.openExternal(url);
  else { const w = window.open(url, '_blank', 'noopener'); if (!w) location.href = url; }
}
async function cloudAssinar(plano) {
  try {
    toast('Abrindo o Mercado Pago…');
    const { data, error } = await sb.functions.invoke('mp-assinar', { body: { plano } });
    if (error) { let m = error.message; try { m = (await error.context.json()).error || m; } catch (e) {} throw new Error(m); }
    if (!data || !data.url) throw new Error((data && data.error) || 'Pagamento indisponível no momento.');
    abrirLink(data.url);
    modal(`<h2>Concluir o pagamento</h2><p>O Mercado Pago foi aberto ${NATIVE ? 'no navegador' : 'em outra aba'}. Depois de pagar, volte aqui e toque em <b>Já paguei</b>. Pelo Pix, a liberação costuma levar poucos minutos.</p>
      <div class="row-actions"><button onclick="closeModal()">Fechar</button><button class="pri" onclick="closeModal();conferirPagamento()">Já paguei</button></div>`);
  } catch (e) { toast(errMsg(e)); }
}
async function conferirPagamento() {
  try { await refreshAcesso(); const a = acessoInfo(); render(); toast(a.ativo && !a.teste ? 'Assinatura ativa. Obrigado!' : 'Pagamento ainda não confirmado. Tente de novo em alguns minutos.'); if (a.ativo) syncNow(); }
  catch (e) { toast(errMsg(e)); }
}
async function baixarApk() {
  try {
    const { data, error } = await sb.functions.invoke('apk-link', { body: {} });
    if (error) { let m = error.message; try { m = (await error.context.json()).error || m; } catch (e) {} throw new Error(m); }
    if (!data || !data.url) throw new Error((data && data.error) || 'Download indisponível.');
    location.href = data.url;
  } catch (e) { toast(errMsg(e)); }
}

/* ---------- telas de entrada (conta) ---------- */
function showCloudStart(modo, msg) {
  modo = modo || 'entrar';
  const criar = modo === 'criar';
  authScreen(`<div class="tabs-auth"><button class="${!criar ? 'on' : ''}" id="aEnt">Entrar</button><button class="${criar ? 'on' : ''}" id="aCri">Criar conta</button></div>
    <h2>${criar ? 'Teste grátis por 15 dias' : 'Bem-vindo de volta'}</h2>
    <div class="sub">${criar ? 'Crie sua conta para usar o Appsico no celular e no computador. Os prontuários são criptografados no seu aparelho antes de ir para a nuvem.' : 'Entre com o e-mail e a senha da sua conta Appsico.'}</div>
    ${msg ? `<div class="note">${msg}</div>` : ''}
    ${criar ? `<div class="f"><label>Nome completo</label><input id="cNome" autocomplete="name"></div>
      <div class="f"><label>CRP</label><input id="cCrp" placeholder="06/123456"></div>` : ''}
    <div class="f"><label>E-mail</label><input id="cEmail" type="email" inputmode="email" autocomplete="email" value="${esc(pref.get('lastEmail', ''))}"></div>
    <div class="f"><label>Senha${criar ? ' (mínimo 8 caracteres, com letras e números)' : ''}</label><input id="cSenha" type="password" autocomplete="${criar ? 'new-password' : 'current-password'}"></div>
    ${criar ? `<div class="f"><label>Confirmar senha</label><input id="cSenha2" type="password" autocomplete="new-password"></div>
      <label class="check" style="margin-bottom:12px"><input type="checkbox" id="cAceite"> Li e aceito a ${!NATIVE || SUPA.siteUrl ? `<a href="${(SUPA.siteUrl || '..').replace(/\/$/, '')}/privacidade.html" target="_blank" rel="noopener">política de privacidade</a>` : 'política de privacidade (em Ajuda e suporte)'}</label>` : ''}
    <button class="pri" id="cGo">${criar ? 'Criar conta e começar o teste' : 'Entrar'}</button><div class="err" id="cErr"></div>
    <div class="links">${criar ? '' : '<a id="cEsq">Esqueci minha senha</a>'}</div>`);
  $('aEnt').onclick = () => showCloudStart('entrar');
  $('aCri').onclick = () => showCloudStart('criar');
  if ($('cEsq')) $('cEsq').onclick = () => showCloudForgot(val('cEmail'));
  $('cSenha').addEventListener('keydown', e => { if (e.key === 'Enter' && !criar) $('cGo').click(); });
  $('cGo').onclick = async () => {
    const err = m => { $('cErr').textContent = m; busy($('cGo'), false); };
    const email = val('cEmail').toLowerCase(), senha = $('cSenha').value;
    if (!emailOk(email)) return err('E-mail inválido.');
    if (criar) {
      const nome = val('cNome'), crp = val('cCrp');
      if (!nome || !crp) return err('Informe nome e CRP.');
      if (!senhaOk(senha)) return err('A senha precisa de pelo menos 8 caracteres, com letras e números.');
      if (senha !== $('cSenha2').value) return err('As senhas não conferem.');
      if (!$('cAceite').checked) return err('Aceite a política de privacidade para continuar.');
      busy($('cGo'), true, 'Criando conta…');
      const { data, error } = await sb.auth.signUp({ email, password: senha, options: { data: { nome, crp }, emailRedirectTo: APP_URL || undefined } });
      if (error) return err(errMsg(error));
      pref.set('lastEmail', email); pref.set('pendNome', nome); pref.set('pendCrp', crp);
      if (!data.session) return showCloudStart('entrar', `Enviamos um link de confirmação para <b>${esc(email)}</b>. Abra o e-mail, confirme e depois entre aqui com sua senha.`);
      return cloudAposLogin(senha, $('cGo'));
    }
    if (!senha) return err('Informe a senha.');
    busy($('cGo'), true, 'Entrando…');
    const { error } = await sb.auth.signInWithPassword({ email, password: senha });
    if (error) return err(errMsg(error));
    pref.set('lastEmail', email);
    cloudAposLogin(senha, $('cGo'));
  };
}
function showCloudForgot(email) {
  authScreen(`<h2>Esqueci minha senha</h2><div class="sub">Enviaremos um link para criar uma nova senha. Depois, ao entrar, o app vai pedir o seu <b>código de recuperação</b> para abrir os prontuários.</div>
    <div class="f"><label>E-mail da conta</label><input id="fpEmail" type="email" inputmode="email" value="${esc(email || '')}"></div>
    <button class="pri" id="fpGo">Enviar link</button><div class="err" id="fpErr"></div>
    <div class="links"><a id="fpBack">Voltar</a></div>`);
  $('fpBack').onclick = () => V ? showLogin() : showCloudStart('entrar');
  $('fpGo').onclick = async () => {
    const em = val('fpEmail').toLowerCase(); if (!emailOk(em)) return $('fpErr').textContent = 'E-mail inválido.';
    busy($('fpGo'), true, 'Enviando…');
    const { error } = await sb.auth.resetPasswordForEmail(em, { redirectTo: SUPA.appUrl || APP_URL || undefined });
    busy($('fpGo'), false);
    if (error) return $('fpErr').textContent = errMsg(error);
    showCloudStart('entrar', `Se existir uma conta para <b>${esc(em)}</b>, enviamos o link. Abra-o${NATIVE ? ' (ele abre a versão para computador)' : ''}, crie a nova senha e entre de novo.`);
  };
}
function showNovaSenhaConta() {
  authScreen(`<h2>Criar nova senha</h2><div class="sub">Escolha a nova senha da sua conta Appsico.</div>
    <div class="f"><label>Nova senha</label><input id="nsS1" type="password" autocomplete="new-password"></div>
    <div class="f"><label>Confirmar nova senha</label><input id="nsS2" type="password" autocomplete="new-password"></div>
    <button class="pri" id="nsGo">Salvar nova senha</button><div class="err" id="nsErr"></div>`);
  $('nsGo').onclick = async () => {
    const s1 = $('nsS1').value; if (!senhaOk(s1)) return $('nsErr').textContent = 'Use pelo menos 8 caracteres, com letras e números.';
    if (s1 !== $('nsS2').value) return $('nsErr').textContent = 'As senhas não conferem.';
    busy($('nsGo'), true, 'Salvando…');
    const { error } = await sb.auth.updateUser({ password: s1 });
    if (error) { busy($('nsGo'), false); return $('nsErr').textContent = errMsg(error); }
    await sb.auth.signOut().catch(() => {});
    history.replaceState(null, '', location.pathname);
    showCloudStart('entrar', 'Senha alterada. Entre com a nova senha; o app vai pedir seu código de recuperação para reabrir os prontuários.');
  };
}

// Depois do login: cria o cofre (1º acesso) ou abre o existente
async function cloudAposLogin(senha, btn) {
  const fail = m => { busy(btn, false); const e = $('cErr') || $('lErr'); if (e) e.textContent = m; else toast(m); };
  try {
    const { data: { user } } = await sb.auth.getUser();
    if (!user) return fail('Sessão inválida. Entre de novo.');
    busy(btn, true, 'Abrindo prontuários…');
    const { data: row, error } = await sb.from('cofres').select('versao,chaves,dados').eq('user_id', user.id).maybeSingle();
    if (error) return fail(errMsg(error));
    const meta = user.user_metadata || {};
    if (!row) {
      // Primeiro acesso: gera a chave dos dados e o código de recuperação
      DEKraw = rnd(32); DEK = await aesKey(DEKraw);
      const rec = genRecovery();
      const chaves = { pw: await wrapAcct(senha, DEKraw), rec: await wrapRec(rec, DEKraw) };
      DB = { prof: { nome: meta.nome || pref.get('pendNome', ''), crp: meta.crp || pref.get('pendCrp', ''), email: user.email }, patients: [] };
      const { data: ver, error: e2 } = await sb.rpc('criar_cofre', { p_chaves: chaves, p_dados: await encJSON(DB), p_disp: DISP });
      if (e2) return fail(errMsg(e2));
      novoCofreLocal(user, chaves.rec, ver || 1);
      await setBase(DB);
      return showRecovery(rec, () => showCreatePin('Crie um PIN de 4 números para abrir o Appsico rapidamente neste aparelho.'));
    }
    let raw = null;
    try { raw = await openAcct(senha, row.chaves.pw); } catch (e) { raw = null; }
    if (!raw) return showCloudRecCode(user, row, senha);
    await abrirCofreNuvem(user, row, raw);
  } catch (e) { fail(errMsg(e)); }
}
function novoCofreLocal(user, recWrap, ver) {
  V = { v: 1, app: 'appsico', user: user.email.toLowerCase(), email: user.email.toLowerCase(), createdAt: new Date().toISOString(),
        rec: recWrap, guard: { fails: 0, until: 0 }, data: null, cloud: { uid: user.id, email: user.email.toLowerCase(), ver } };
  pref.set('lastUser', user.email.toLowerCase());
}
async function abrirCofreNuvem(user, row, raw) {
  DEKraw = raw; DEK = await aesKey(raw);
  DB = await decJSON(DEK, row.dados);
  novoCofreLocal(user, row.chaves.rec, row.versao);
  await setBase(DB);
  showCreatePin('Crie um PIN de 4 números para abrir o Appsico rapidamente neste aparelho.');
}
// Senha da conta mudou (ex.: "esqueci a senha"): o código de recuperação reabre os dados
function showCloudRecCode(user, row, senha) {
  authScreen(`<h2>Código de recuperação</h2><div class="sub">A senha da conta foi trocada. Para reabrir os prontuários com segurança, digite o código de recuperação de 20 caracteres que você anotou ao criar a conta.</div>
    <div class="f"><label>Código de recuperação</label><input id="rcCode" placeholder="XXXXX-XXXXX-XXXXX-XXXXX" autocapitalize="characters" style="font-family:monospace"></div>
    <button class="pri" id="rcGo">Continuar</button><div class="err" id="rcErr"></div>
    <div class="links"><a id="rcBack">Voltar</a></div>`);
  $('rcBack').onclick = async () => { await sb.auth.signOut().catch(() => {}); showCloudStart('entrar'); };
  $('rcGo').onclick = async () => {
    busy($('rcGo'), true, 'Verificando…');
    let raw; try { raw = await openWith(normRec(val('rcCode')), row.chaves.rec); } catch (e) { busy($('rcGo'), false); return $('rcErr').textContent = 'Código de recuperação incorreto.'; }
    const chaves = { pw: await wrapAcct(senha, raw), rec: row.chaves.rec };
    const { error } = await sb.rpc('trocar_chaves', { p_chaves: chaves });
    if (error) { busy($('rcGo'), false); return $('rcErr').textContent = errMsg(error); }
    row.chaves = chaves;
    await abrirCofreNuvem(user, row, raw);
  };
}
// Esqueci o PIN (conta na nuvem): entrar de novo com e-mail e senha
function showPinPelaConta() {
  authScreen(`<h2>Esqueci meu PIN</h2><div class="sub">Entre com a senha da sua conta (${esc(V.cloud.email)}) para criar um novo PIN neste aparelho.</div>
    <div class="f"><label>Senha da conta</label><input id="ppS" type="password" autocomplete="current-password"></div>
    <button class="pri" id="ppGo">Continuar</button><div class="err" id="ppErr"></div>
    <div class="links"><a id="ppRec">Usar código de recuperação</a> &nbsp;·&nbsp; <a id="ppBack">Voltar</a></div>`);
  $('ppBack').onclick = () => showLogin();
  $('ppRec').onclick = showRecoveryReset;
  $('ppGo').onclick = async () => {
    const senha = $('ppS').value; if (!senha) return;
    busy($('ppGo'), true, 'Verificando…');
    const { error } = await sb.auth.signInWithPassword({ email: V.cloud.email, password: senha });
    if (error) { busy($('ppGo'), false); return $('ppErr').textContent = errMsg(error); }
    const { data: row, error: e2 } = await sb.from('cofres').select('chaves').eq('user_id', V.cloud.uid).maybeSingle();
    if (e2 || !row) { busy($('ppGo'), false); return $('ppErr').textContent = errMsg(e2 || 'Cofre não encontrado.'); }
    let raw; try { raw = await openAcct(senha, row.chaves.pw); } catch (e) { busy($('ppGo'), false); return $('ppErr').textContent = 'A senha da conta mudou. Use o código de recuperação.'; }
    try { await useDEK(raw); } catch (e) { busy($('ppGo'), false); return $('ppErr').textContent = 'Não foi possível abrir os dados deste aparelho.'; }
    showCreatePin('Crie um novo PIN de 4 números para este aparelho.');
  };
}
// Sessão expirada: entrar de novo sem sair do app
function cloudReauth() {
  modal(`<h2>Entrar de novo</h2><p>Para continuar sincronizando, confirme a senha da conta <b>${esc(V.cloud.email)}</b>.</p>
    <div class="f"><label>Senha da conta</label><input id="raS" type="password" autocomplete="current-password"></div><div class="err" id="raErr"></div>
    <div class="row-actions"><button onclick="closeModal()">Agora não</button><button class="pri" id="raGo">Entrar</button></div>`);
  $('raGo').onclick = async () => {
    busy($('raGo'), true, 'Entrando…');
    const { error } = await sb.auth.signInWithPassword({ email: V.cloud.email, password: $('raS').value });
    if (error) { busy($('raGo'), false); return $('raErr').textContent = errMsg(error); }
    closeModal(); syncNow(true);
  };
}

/* ---------- ligar um aparelho que já tinha dados só no celular ---------- */
function cloudLigar() {
  modal(`<h2>Ativar conta na nuvem</h2><p>Seus prontuários deste aparelho vão para a nuvem <b>criptografados</b> e passam a aparecer também no computador. Você ganha 15 dias de teste grátis.</p>
    <div class="f"><label>E-mail</label><input id="lkEmail" type="email" value="${esc(DB.prof.email || '')}"></div>
    <div class="f"><label>Senha da conta (mín. 8, letras e números)</label><input id="lkS" type="password" autocomplete="new-password"></div>
    <div class="f"><label>Seu PIN deste aparelho</label><input id="lkPin" type="password" inputmode="numeric" maxlength="6" class="pin"></div>
    <label class="check"><input type="checkbox" id="lkTem"> Já tenho conta no Appsico</label>
    <div class="err" id="lkErr"></div>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" id="lkGo">Ativar</button></div>`);
  $('lkGo').onclick = async () => {
    const err = m => { $('lkErr').textContent = m; busy($('lkGo'), false); };
    const email = val('lkEmail').toLowerCase(), senha = $('lkS').value, pin = $('lkPin').value, tem = $('lkTem').checked;
    if (!emailOk(email)) return err('E-mail inválido.');
    if (!senhaOk(senha)) return err('A senha precisa de pelo menos 8 caracteres, com letras e números.');
    busy($('lkGo'), true, 'Conferindo…');
    try { await openPw(pin, V.pw); } catch (e) { return err('PIN incorreto.'); }
    let r = tem ? await sb.auth.signInWithPassword({ email, password: senha }) : await sb.auth.signUp({ email, password: senha, options: { data: { nome: DB.prof.nome || '', crp: DB.prof.crp || '' }, emailRedirectTo: APP_URL || undefined } });
    if (r.error) return err(errMsg(r.error));
    if (!r.data.session) return err('Enviamos um link de confirmação para seu e-mail. Confirme e depois toque em Ativar de novo, marcando "Já tenho conta".');
    const user = r.data.user || r.data.session.user;
    const { data: row, error } = await sb.from('cofres').select('versao,chaves,dados').eq('user_id', user.id).maybeSingle();
    if (error) return err(errMsg(error));
    let remoto = null;
    if (!row) {
      const chaves = { pw: await wrapAcct(senha, DEKraw), rec: V.rec };
      const { data: ver, error: e2 } = await sb.rpc('criar_cofre', { p_chaves: chaves, p_dados: await encJSON(DB), p_disp: DISP });
      if (e2) return err(errMsg(e2));
      V.cloud = { uid: user.id, email, ver: ver || 1 };
    } else {
      // A conta já tem dados: junta os dois lados e passa a usar a chave da conta
      let raw2; try { raw2 = await openAcct(senha, row.chaves.pw); } catch (e) { return err('Não foi possível abrir os dados da conta com essa senha.'); }
      remoto = await decJSON(await aesKey(raw2), row.dados);
      const junto = merge3(null, DB, remoto);
      DEKraw = raw2; DEK = await aesKey(raw2); DB = junto;
      V.rec = row.chaves.rec; V.pw = await wrapWithPassword(pin); await Secure.set('dek', b64e(DEKraw));
      V.cloud = { uid: user.id, email, ver: row.versao };
    }
    V.user = email; V.email = email; pref.set('lastUser', email); pref.set('lastEmail', email);
    BASE = null; await setBase(remoto || DB); await persist();
    closeModal(); toast('Conta na nuvem ativada'); cloudStart(); render();
    if (row) modal(`<h2>Contas unidas</h2><p>Os prontuários deste aparelho foram juntados aos da sua conta. A partir de agora, vale o <b>código de recuperação da conta</b> (o que você anotou quando criou a conta), não o antigo deste aparelho.</p><div class="row-actions"><button class="pri" onclick="closeModal()">Entendi</button></div>`);
  };
}

/* ---------- conta: trocar senha, sair, excluir ---------- */
function cloudTrocarSenha() {
  modal(`<h2>Trocar senha da conta</h2>
    <div class="f"><label>Senha atual</label><input id="tsA" type="password" autocomplete="current-password"></div>
    <div class="f"><label>Nova senha (mín. 8, letras e números)</label><input id="tsN" type="password" autocomplete="new-password"></div>
    <div class="f"><label>Confirmar nova senha</label><input id="tsN2" type="password" autocomplete="new-password"></div>
    <div class="err" id="tsErr"></div>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" id="tsGo">Salvar</button></div>`);
  $('tsGo').onclick = async () => {
    const err = m => { $('tsErr').textContent = m; busy($('tsGo'), false); };
    const a = $('tsA').value, n = $('tsN').value;
    if (!senhaOk(n)) return err('A nova senha precisa de pelo menos 8 caracteres, com letras e números.');
    if (n !== $('tsN2').value) return err('As senhas não conferem.');
    busy($('tsGo'), true, 'Salvando…');
    const { error: e0 } = await sb.auth.signInWithPassword({ email: V.cloud.email, password: a });
    if (e0) return err('Senha atual incorreta.');
    const { data: row, error: e1 } = await sb.from('cofres').select('chaves').eq('user_id', V.cloud.uid).single();
    if (e1) return err(errMsg(e1));
    const { error: e2 } = await sb.auth.updateUser({ password: n });
    if (e2) return err(errMsg(e2));
    const { error: e3 } = await sb.rpc('trocar_chaves', { p_chaves: { pw: await wrapAcct(n, DEKraw), rec: row.chaves.rec } });
    if (e3) return err(errMsg(e3));
    closeModal(); toast('Senha da conta alterada');
  };
}
async function limparAparelho() {
  cloudStop();
  try { await sb.auth.signOut(); } catch (e) {}
  await Store.clear();
  try { localStorage.removeItem('ks_dek'); } catch (e) {}
  location.reload();
}
function cloudSair() {
  confirmTyped('Sair da conta neste aparelho', 'Os prontuários continuam guardados na sua conta, mas a cópia deste aparelho será apagada. Para voltar, entre com e-mail e senha.', 'SAIR', async () => {
    await cloudBeforeLock(); DEK = null; DEKraw = null; DB = null; await limparAparelho();
  });
}
function cloudExcluirConta() {
  confirmTyped('Excluir conta', 'Sua conta, sua assinatura e todos os prontuários na nuvem serão apagados para sempre. Antes, faça um backup se precisar guardar os registros (o CFP exige a guarda).', 'EXCLUIR', async () => {
    const { error } = await sb.rpc('excluir_minha_conta');
    if (error) return toast(errMsg(error));
    DEK = null; DEKraw = null; DB = null; await limparAparelho();
  });
}

/* ---------- cartão "Conta e nuvem" (Configurações) ---------- */
function contaCard() {
  if (!CLOUD) return '';
  if (!cloudLinked()) return `<details class="card acc" open><summary><span class="acc-ic">${IC.backup}</span><span class="acc-t"><b>Conta na nuvem</b><small>Use também no computador</small></span></summary><div class="acc-body">
    <p style="margin:0 0 10px">Ative sua conta para sincronizar os prontuários entre o celular e o computador. Tudo vai <b>criptografado</b>: ninguém além de você consegue ler.</p>
    <div class="row-actions" style="justify-content:flex-start"><button class="pri" onclick="cloudLigar()">Ativar conta na nuvem</button></div></div></details>`;
  const a = acessoInfo();
  const st = a.desconhecido ? 'Verificando…' : a.teste ? `Teste grátis: ${a.dias} dia${a.dias === 1 ? '' : 's'} restante${a.dias === 1 ? '' : 's'}` : a.ativo ? `Assinatura ${nomePlanoN(a.plano)} · até ${fmtD(a.ate)}` : a.conferir ? 'Conecte à internet para conferir a assinatura' : 'Sem assinatura ativa · modo consulta';
  return `<details class="card acc" open><summary><span class="acc-ic">${IC.backup}</span><span class="acc-t"><b>Conta e nuvem</b><small>${esc(V.cloud.email)}</small></span></summary><div class="acc-body">
    <div class="conta-st ${a.ativo ? (a.teste ? 'teste' : 'ok') : 'fim'}"><b>${esc(st)}</b><span>${syncBadge()}</span></div>
    <div class="row-actions" style="justify-content:flex-start;flex-wrap:wrap">
      <button class="pri" onclick="go('premium',{cur:null})">${a.ativo && !a.teste ? 'Minha assinatura' : 'Assinar'}</button>
      <button onclick="syncNow(true)">Sincronizar agora</button>
      ${!NATIVE ? '<button onclick="baixarApk()">Baixar app Android</button>' : ''}
      <button onclick="cloudTrocarSenha()">Trocar senha da conta</button>
      ${a.admin ? `<button onclick="go('admin',{cur:null})">Painel do administrador</button>` : ''}
    </div>
    <div class="row-actions" style="justify-content:flex-start;flex-wrap:wrap;margin-top:6px">
      <button onclick="cloudSair()">Sair da conta neste aparelho</button>
      <button class="danger" onclick="cloudExcluirConta()">Excluir conta</button>
    </div>
    <p class="meta" style="margin-top:10px">Os prontuários são criptografados neste aparelho antes de ir para a nuvem. Se esquecer a senha, só o código de recuperação reabre os dados.</p></div></details>`;
}
const nomePlanoN = id => ({ mensal: 'mensal', anual: 'anual', anualpix: 'anual (Pix)', cortesia: 'cortesia' }[id] || '');

/* ---------- tela de planos (nuvem) ---------- */
function panePremiumNuvem(m) {
  const a = acessoInfo(), sel = S.planoSel || 'anual';
  m.innerHTML = `<div class="head"><div><h1>Assinatura Appsico</h1><div class="meta">${a.teste ? `Teste grátis até ${fmtD(a.ate)} (${a.dias} dia${a.dias === 1 ? '' : 's'})` : a.ativo ? `Assinatura ${nomePlanoN(a.plano)} ativa até ${fmtD(a.ate)}` : a.conferir ? 'Conecte à internet para conferir sua assinatura' : 'Sem assinatura ativa: o app está em modo consulta'}</div></div>${sairBtn()}</div>
    <div class="prem-hero"><span class="ph-ic">${IC.crown}</span><div><b>${a.ativo && !a.teste ? 'Obrigado por assinar o Appsico!' : 'Continue com tudo o que você já usa'}</b>
      <small>Prontuários criptografados no celular e no computador, agenda, lembretes, documentos, financeiro e Pix. Cancele quando quiser.</small></div></div>
    ${!a.ativo ? (a.conferir ? `<div class="note warn">Faz mais de ${DIAS_OFFLINE} dias que o app não confere sua assinatura. Conecte o aparelho à internet e toque em "Já paguei — atualizar". Enquanto isso, você pode ver e exportar os prontuários.</div>` : `<div class="note warn">Sem assinatura ativa, o Appsico fica em <b>modo consulta</b>: você vê e exporta todos os prontuários (em PDF), mas não registra sessões, pacientes, agenda ou financeiro. Nenhum dado é apagado. Assine e tudo volta a funcionar na hora.</div>`) : ''}
    <div class="planos">${PLANOS_NUVEM.map(x => `<button class="plano ${sel === x.id ? 'on' : ''}" onclick="S.planoSel='${x.id}';panePremiumNuvem($('main'))">
      ${x.tag ? `<span class="pl-tag">${x.tag}</span>` : ''}<span class="pl-radio"></span><b>${x.nome}</b><span class="pl-preco">${x.preco}</span><small>${x.per}</small><small class="pl-obs">${x.obs}</small></button>`).join('')}</div>
    <div class="row-actions prem-act"><button class="pri big" onclick="cloudAssinar('${sel}')">${IC.crown} ${sel === 'anualpix' ? 'Pagar' : 'Assinar'} ${PLANOS_NUVEM.find(x => x.id === sel).nome} · ${PLANOS_NUVEM.find(x => x.id === sel).preco}</button></div>
    <div class="row-actions prem-act"><button onclick="conferirPagamento()">Já paguei — atualizar</button>${!NATIVE ? '<button onclick="baixarApk()">Baixar app Android</button>' : ''}</div>
    <p class="meta" style="text-align:center;margin-top:10px">Pagamento pelo Mercado Pago. Mensal e Anual renovam sozinhos no cartão e podem ser cancelados a qualquer momento na sua conta do Mercado Pago. O Anual no Pix é pago uma vez e vale 1 ano.</p>`;
}
function bannerNuvem() {
  const a = acessoInfo(); if (a.desconhecido) return '';
  if (!a.ativo) return a.conferir
    ? `<button class="plano-banner fim" onclick="conferirPagamento()"><span class="pb-ic">${IC.lock}</span><span class="pb-txt"><b>Conecte à internet</b><small>Faz mais de ${DIAS_OFFLINE} dias que o app não confere sua assinatura. Até lá, só consulta e exportação.</small></span><span class="pb-go">Conferir</span></button>`
    : `<button class="plano-banner fim" onclick="go('premium',{cur:null})"><span class="pb-ic">${IC.lock}</span><span class="pb-txt"><b>Modo consulta</b><small>${a.teste === false && a.plano ? 'Sua assinatura venceu.' : 'Seu teste grátis terminou.'} Você vê e exporta os prontuários. Assine para voltar a registrar.</small></span><span class="pb-go">Assinar</span></button>`;
  if (a.teste) { const pct = Math.round((15 - Math.min(15, a.dias)) / 15 * 100);
    return `<button class="plano-banner" onclick="go('premium',{cur:null})"><span class="pb-ic">${IC.crown}</span><span class="pb-txt"><b>Teste grátis: faltam ${a.dias} dia${a.dias === 1 ? '' : 's'}</b><small>Tudo liberado até ${fmtD(a.ate)}. Assine para continuar depois.</small><span class="pb-bar"><i style="width:${pct}%"></i></span></span><span class="pb-go">Ver planos</span></button>`; }
  if (a.dias <= 10 && a.plano !== 'mensal' && a.plano !== 'anual') return `<button class="plano-banner vence" onclick="go('premium',{cur:null})"><span class="pb-ic">${IC.crown}</span><span class="pb-txt"><b>Seu acesso vence em ${a.dias} dia${a.dias === 1 ? '' : 's'}</b><small>Válido até ${fmtD(a.ate)}. Renove para não ficar em modo consulta.</small></span><span class="pb-go">Renovar</span></button>`;
  return '';
}

/* ---------- painel do administrador ---------- */
async function paneAdmin(m) {
  m.innerHTML = `<div class="head"><div><h1>Painel do administrador</h1><div class="meta">Contas e assinaturas (sem acesso a prontuários)</div></div>${sairBtn()}</div><div class="card"><p class="meta">Carregando…</p></div>`;
  try {
    const [{ data: r, error: e1 }, { data: us, error: e2 }] = await Promise.all([sb.rpc('admin_resumo'), sb.rpc('admin_usuarios', { q: S.admQ || '' })]);
    if (e1 || e2) throw (e1 || e2);
    const brl2 = v => Number(v || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
    const sit = u => { const ag = Date.now(); const pago = u.valido_ate && new Date(u.valido_ate) > ag, teste = new Date(u.teste_ate) > ag;
      return pago ? `<span class="tag st-confirmado">${esc(u.plano || 'assinante')} até ${fmtD(u.valido_ate.slice(0, 10))}</span>` : teste ? `<span class="tag">teste até ${fmtD(u.teste_ate.slice(0, 10))}</span>` : '<span class="tag warn">expirado</span>'; };
    m.innerHTML = `<div class="head"><div><h1>Painel do administrador</h1><div class="meta">Contas e assinaturas (sem acesso a prontuários)</div></div>${sairBtn()}</div>
      <div class="kpis"><div class="kpi k-rec"><span>Receita recorrente/mês</span><b>${brl2(r.mrr)}</b></div><div class="kpi"><span>Receita do mês</span><b>${brl2(r.receita_mes)}</b></div><div class="kpi"><span>Receita total</span><b>${brl2(r.receita_total)}</b></div></div>
      <div class="kpis"><div class="kpi"><span>Usuários</span><b>${r.usuarios}</b></div><div class="kpi"><span>Em teste</span><b>${r.em_teste}</b></div><div class="kpi"><span>Assinantes</span><b>${r.mensal + r.anual + r.anualpix}</b></div><div class="kpi k-pag"><span>Expirados</span><b>${r.expirados}</b></div></div>
      <div class="card"><h3>Assinantes por plano</h3><p class="meta">Mensal: <b>${r.mensal}</b> · Anual: <b>${r.anual}</b> · Anual no Pix: <b>${r.anualpix}</b> · Cortesia: <b>${r.cortesia}</b> · Novos em 7 dias: <b>${r.novos_7d}</b> · Ativos na semana: <b>${r.ativos_7d}</b></p></div>
      <div class="card"><h3>Usuários</h3><input id="admQ" placeholder="Buscar por nome ou e-mail" value="${esc(S.admQ || '')}" style="margin-bottom:10px">
        <div class="adm-list">${(us || []).map(u => `<div class="adm-u"><div><b>${esc(u.nome || '—')}</b><small>${esc(u.email)}${u.crp ? ' · CRP ' + esc(u.crp) : ''} · desde ${fmtD(String(u.criado_em).slice(0, 10))}</small>${sit(u)}</div>
          <select onchange="admLiberar('${u.id}', this.value);this.value=''"><option value="">Ações…</option><option value="teste15">+15 dias de teste</option><option value="30d">Cortesia 30 dias</option><option value="90d">Cortesia 90 dias</option><option value="1y">Cortesia 1 ano</option><option value="remover">Remover assinatura</option></select></div>`).join('') || '<p class="meta">Nenhum usuário.</p>'}</div></div>`;
    $('admQ').onchange = e => { S.admQ = e.target.value; paneAdmin($('main')); };
  } catch (e) { m.querySelector('.card').innerHTML = `<p class="err">${esc(errMsg(e))}</p>`; }
}
async function admLiberar(id, modo) {
  if (!modo) return;
  const { error } = await sb.rpc('admin_liberar', { alvo: id, modo });
  if (error) return toast(errMsg(error));
  toast('Atualizado'); paneAdmin($('main'));
}

/* ---------- link de recuperação de senha aberto no navegador ---------- */
if (CLOUD) sb.auth.onAuthStateChange(ev => { if (ev === 'PASSWORD_RECOVERY') { window._recuperarSenha = true; if (window._bootOk) setTimeout(showNovaSenhaConta, 50); } });
