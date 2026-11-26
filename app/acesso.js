/* Appsico — formas de recuperar e abrir o acesso
   1) Recuperação pelo Appsico (custódia): uma cópia da chave dos prontuários fica guardada no servidor,
      trancada no Supabase Vault, e só volta para o próprio psicólogo logado na conta (senha ou link do e-mail).
   2) Nova senha da conta por um aparelho que ainda abre com o PIN.
   3) Ver e gerar um novo código de recuperação em Configurações.
   4) Biometria (digital/rosto) para abrir o app no lugar do PIN. */

/* ---------- 4) Biometria ---------- */
const BIO = {
  async disponivel() {
    if (NATIVE) { try { return !!(window.AppsicoNative && AppsicoNative.bioAvailable && AppsicoNative.bioAvailable()); } catch (e) { return false; } }
    try { return !!(window.PublicKeyCredential && window.isSecureContext && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); } catch (e) { return false; }
  },
  nativo(titulo) {
    return new Promise(res => {
      const t = setTimeout(() => { window.__bio = null; res(false); }, 90000);
      window.__bio = (r) => { clearTimeout(t); window.__bio = null; res(r === 1); };
      try { AppsicoNative.bioAuth(titulo); } catch (e) { clearTimeout(t); window.__bio = null; res(false); }
    });
  },
  async ativar() {
    if (NATIVE) { if (!(await BIO.nativo('Ativar a biometria no Appsico'))) throw new Error('Biometria não confirmada.'); return { tipo: 'android', em: today() }; }
    const nome = (V.cloud && V.cloud.email) || V.user || V.email || 'appsico';
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: rnd(32), rp: { name: 'Appsico' }, user: { id: rnd(16), name: nome, displayName: (DB && DB.prof && DB.prof.nome) || nome },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged' }, timeout: 60000 } });
    if (!cred) throw new Error('Biometria não confirmada.');
    return { tipo: 'web', id: b64e(new Uint8Array(cred.rawId)), em: today() };
  },
  async verificar() {
    if (!V.bio) return false;
    if (V.bio.tipo === 'android') return NATIVE ? BIO.nativo('Entrar no Appsico') : false;
    const a = await navigator.credentials.get({ publicKey: { challenge: rnd(32), allowCredentials: [{ type: 'public-key', id: b64d(V.bio.id) }], userVerification: 'required', timeout: 60000 } });
    if (!a || !a.response) return false;
    const flags = new Uint8Array(a.response.authenticatorData)[32];
    return (flags & 4) === 4; // a pessoa foi verificada (digital, rosto ou senha do aparelho)
  }
};
// Botão "Entrar com biometria" na tela de entrada (chamado por showLogin)
async function bioNaEntrada() {
  if (!V || !V.bio || !$('lGo')) return;
  if (!(await Secure.get('dek'))) return;
  const b = document.createElement('button'); b.id = 'lBio'; b.className = 'bio-btn';
  b.innerHTML = `${IC.shield}<span>Entrar com biometria</span>`;
  $('lGo').parentNode.insertBefore(b, $('lGo'));
  b.onclick = async () => {
    try {
      busy(b, true, 'Aguardando a biometria…');
      const ok = await BIO.verificar(); busy(b, false);
      if (!ok) return ($('lErr').textContent = 'Biometria não reconhecida. Tente de novo ou use o PIN.');
      const k = await Secure.get('dek'); if (!k) return ($('lErr').textContent = 'Use o PIN neste aparelho.');
      await useDEK(b64d(k));
      V.guard = { fails: 0, until: 0 }; await writeVault().catch(() => {});
      enterApp();
    } catch (e) { busy(b, false); $('lErr').textContent = 'Biometria cancelada. Use o PIN.'; }
  };
  if (NATIVE && !showLogin._bioAuto) { showLogin._bioAuto = true; setTimeout(() => b.click(), 300); } // no Android já abre a janela da digital
}
async function bioAtivar() {
  try {
    if (!(await BIO.disponivel())) return toast('Este aparelho não tem biometria disponível.');
    V.bio = await BIO.ativar(); await writeVault();
    toast('Biometria ativada'); renderMain();
  } catch (e) { toast(e && e.name === 'NotAllowedError' ? 'Biometria cancelada' : (e.message || 'Não foi possível ativar')); }
}
async function bioDesativar() { delete V.bio; await writeVault().catch(() => {}); toast('Biometria desativada'); renderMain(); }

/* ---------- 3) Código de recuperação: ver e gerar um novo ---------- */
function guardaCodigoNoProntuario(rec) { DB.seg = Object.assign({}, DB.seg, { recCode: rec, recEm: today() }); }
async function gerarNovoCodigoRec() {
  confirmBox('Gerar novo código de recuperação?', 'O código antigo deixa de funcionar. Anote o novo em local seguro, fora do celular.', 'Gerar novo código', async () => {
    try {
      const rec = genRecovery();
      const recW = await wrapRec(rec, DEKraw);
      if (typeof cloudLinked === 'function' && cloudLinked()) {
        const { data: row, error } = await sb.from('cofres').select('chaves').eq('user_id', V.cloud.uid).single();
        if (error) throw error;
        const { error: e2 } = await sb.rpc('trocar_chaves', { p_chaves: Object.assign({}, row.chaves, { rec: recW }) });
        if (e2) throw e2;
      }
      V.rec = recW; guardaCodigoNoProntuario(rec); save(); await writeVault();
      mostrarCodigoRec(rec, true);
    } catch (e) { toast('Não foi possível gerar: ' + errMsg(e)); }
  });
}
function mostrarCodigoRec(rec, novo) {
  modal(`<h2>${novo ? 'Novo código de recuperação' : 'Seu código de recuperação'}</h2>
    <p>${novo ? 'Este é o seu novo código. O antigo não funciona mais.' : 'Guarde em local seguro, fora do celular (papel, cofre de senhas).'}</p>
    <div class="rec-code">${esc(rec)}</div>
    <div class="row-actions"><button onclick="navigator.clipboard.writeText('${esc(rec)}').then(()=>toast('Código copiado'),()=>toast('Selecione e copie manualmente'))">Copiar</button><button class="pri" onclick="closeModal()">Já anotei</button></div>`);
}
function verCodigoRec() {
  const r = DB.seg && DB.seg.recCode;
  if (!r) return modal(`<h2>Código de recuperação</h2><p>O código criado no cadastro não fica guardado no app, por segurança. Gere um novo agora: ele passa a ficar visível aqui, só para você.</p>
    <div class="row-actions"><button onclick="closeModal()">Agora não</button><button class="pri" onclick="closeModal();gerarNovoCodigoRec()">Gerar novo código</button></div>`);
  mostrarCodigoRec(r, false);
}

/* ---------- 1) Recuperação pelo Appsico (custódia da chave) ---------- */
async function garanteCustodia() {
  if (typeof cloudLinked !== 'function' || !cloudLinked() || !DEKraw || (V.cloud && V.cloud.custodia)) return;
  try {
    const { error } = await sb.rpc('custodia_guardar', { p_dek: b64e(DEKraw) });
    if (error) return;
    V.cloud.custodia = today(); await writeVault().catch(() => {});
  } catch (e) {}
}
async function recuperarPelaCustodia(user, row, senha, btn, errEl) {
  try {
    busy(btn, true, 'Recuperando…');
    const { data, error } = await sb.rpc('custodia_recuperar');
    if (error) { busy(btn, false); return errEl.textContent = /sem_custodia/.test(error.message) ? 'A recuperação pelo Appsico ainda não estava ativa nesta conta. Use o código ou abra o Appsico num aparelho onde você ainda entra com o PIN.' : errMsg(error); }
    const raw = b64d(data);
    await decJSON(await aesKey(raw), row.dados); // confere se a chave abre mesmo os prontuários
    const chaves = Object.assign({}, row.chaves, { pw: await wrapAcct(senha, raw) });
    const { error: e2 } = await sb.rpc('trocar_chaves', { p_chaves: chaves });
    if (e2) { busy(btn, false); return errEl.textContent = errMsg(e2); }
    row.chaves = chaves;
    toast('Acesso recuperado');
    await abrirCofreNuvem(user, row, raw);
  } catch (e) { busy(btn, false); errEl.textContent = 'Não foi possível recuperar: ' + errMsg(e); }
}

/* ---------- 2) Nova senha da conta por este aparelho (sem a senha antiga) ---------- */
function novaSenhaPeloAparelho() {
  modal(`<h2>Criar nova senha da conta</h2>
    <p>Esqueceu a senha da conta? Como este aparelho já está aberto com o seu PIN, você pode criar uma senha nova aqui, sem a antiga.</p>
    <div class="f"><label>Nova senha (mín. 8, letras e números)</label><input id="nsaN" type="password" autocomplete="new-password"></div>
    <div class="f"><label>Confirmar nova senha</label><input id="nsaN2" type="password" autocomplete="new-password"></div>
    <div class="err" id="nsaErr"></div>
    <div class="row-actions"><button onclick="closeModal()">Cancelar</button><button class="pri" id="nsaGo">Salvar nova senha</button></div>`);
  $('nsaGo').onclick = async () => {
    const err = m => { $('nsaErr').textContent = m; busy($('nsaGo'), false); };
    const n = $('nsaN').value;
    if (!senhaOk(n)) return err('A nova senha precisa de pelo menos 8 caracteres, com letras e números.');
    if (n !== $('nsaN2').value) return err('As senhas não conferem.');
    busy($('nsaGo'), true, 'Salvando…');
    const { data: s } = await sb.auth.getSession();
    if (!s || !s.session) return err('Este aparelho está sem conexão com a conta. Conecte à internet e tente de novo, ou use "Esqueci minha senha" na tela de entrada.');
    const { data: row, error: e1 } = await sb.from('cofres').select('chaves').eq('user_id', V.cloud.uid).single();
    if (e1) return err(errMsg(e1));
    const { error: e2 } = await sb.auth.updateUser({ password: n });
    if (e2) return err(/reauth/i.test(e2.message) ? 'O servidor pediu confirmação por e-mail. Use "Esqueci minha senha" na tela de entrada.' : errMsg(e2));
    const { error: e3 } = await sb.rpc('trocar_chaves', { p_chaves: Object.assign({}, row.chaves, { pw: await wrapAcct(n, DEKraw) }) });
    if (e3) return err(errMsg(e3));
    closeModal(); toast('Nova senha da conta criada');
  };
}

/* ---------- Quadro em Configurações ---------- */
function acessoCard() {
  const nuvem = typeof cloudLinked === 'function' && cloudLinked();
  const cust = nuvem && V.cloud.custodia, temCod = !!(DB.seg && DB.seg.recCode);
  const bio = V.bio;
  const linha = (ok, titulo, txt, botoes) => `<div class="acs-l"><span class="acs-st ${ok ? 'ok' : 'pend'}">${ok ? '✓' : '!'}</span><div><b>${titulo}</b><small>${txt}</small>${botoes ? `<div class="acs-b">${botoes}</div>` : ''}</div></div>`;
  return `<details class="card acc" ${!temCod || (nuvem && !cust) ? 'open' : ''}><summary><span class="acc-ic">${IC.shield}</span><span class="acc-t"><b>Recuperação de acesso</b><small>Como voltar a abrir os prontuários se esquecer a senha</small></span></summary><div class="acc-body acs">
    ${nuvem ? linha(cust, 'Recuperação pelo e-mail', cust ? 'Ativa. Se perder a senha e o código, use "Esqueci minha senha" na tela de entrada: o Appsico devolve o acesso pelo seu e-mail.' : 'Ativando… (precisa de internet)', '') : ''}
    ${linha(temCod, 'Código de recuperação', temCod ? `Gerado em ${fmtD(DB.seg.recEm)}. Você pode ver o código quando quiser.` : 'O código do cadastro não fica visível no app. Gere um novo para poder consultá-lo aqui.', `<button onclick="verCodigoRec()">Ver código</button><button onclick="gerarNovoCodigoRec()">Gerar novo código</button>`)}
    ${nuvem ? linha(true, 'Nova senha por este aparelho', 'Esqueceu a senha da conta? Crie uma nova aqui mesmo, porque este aparelho já está aberto com o seu PIN.', `<button onclick="novaSenhaPeloAparelho()">Criar nova senha da conta</button>`) : ''}
    <div id="acsBio">${linha(!!bio, 'Biometria (digital ou rosto)', bio ? 'Ativa neste aparelho: na tela de entrada, use "Entrar com biometria".' : 'Abra o Appsico com a digital ou o rosto, no lugar do PIN.', bio ? `<button onclick="bioDesativar()">Desativar</button>` : `<button class="pri" onclick="bioAtivar()">Ativar biometria</button>`)}</div>
  </div></details>`;
}
// some o botão de biometria se o aparelho não tiver
async function acessoCardDepois() {
  const el = document.getElementById('acsBio'); if (!el || V.bio) return;
  if (!(await BIO.disponivel())) el.innerHTML = `<div class="acs-l"><span class="acs-st pend">–</span><div><b>Biometria (digital ou rosto)</b><small>Este aparelho ou navegador não tem biometria disponível.</small></div></div>`;
}
