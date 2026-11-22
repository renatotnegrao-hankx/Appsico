// APPSICO — recebe os avisos do Mercado Pago, libera a assinatura e registra a receita.
// IMPORTANTE: desligue "Enforce JWT verification" nesta função.
// Segredo: MP_ACCESS_TOKEN. A situação é sempre consultada na API do Mercado Pago, então um aviso falso não libera nada.
import { createClient } from 'npm:@supabase/supabase-js@2';

const VALOR: Record<string, number> = { mensal: 24.9, anual: 199, anualpix: 199 };

Deno.serve(async (req) => {
  const url = new URL(req.url);
  let body: any = {};
  try { body = await req.json(); } catch { /* sem corpo */ }
  const tipo = String(body.type || body.topic || url.searchParams.get('type') || url.searchParams.get('topic') || '');
  const id = body?.data?.id || url.searchParams.get('data.id') || url.searchParams.get('id');
  if (!id) return new Response('sem id', { status: 200 });

  const token = Deno.env.get('MP_ACCESS_TOKEN')!;
  const mp = (p: string) => fetch('https://api.mercadopago.com' + p, { headers: { Authorization: `Bearer ${token}` } }).then((r) => r.json());
  const adm = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  const emailDe = async (uid: string) => (await adm.from('perfis').select('email').eq('id', uid).maybeSingle()).data?.email ?? null;
  const registrar = async (uid: string, plano: string, valor: number, ext: string, payload: unknown) => {
    await adm.from('pagamentos').upsert({ user_id: uid, email: await emailDe(uid), provedor: 'mercadopago', plano, valor, status: 'approved', externo_id: 'mp:' + ext, payload },
      { onConflict: 'externo_id', ignoreDuplicates: true });
  };

  // Pagamento único (Anual no Pix): vale 1 ano a partir do fim do acesso atual
  if (tipo === 'payment' || (tipo.includes('payment') && !tipo.includes('authorized'))) {
    const p = await mp(`/v1/payments/${id}`);
    const [uid, plano] = String(p?.external_reference || '').split('|');
    if (uid && plano === 'anualpix' && p.status === 'approved') {
      const { data: ja } = await adm.from('pagamentos').select('id').eq('externo_id', 'mp:' + p.id).maybeSingle();
      if (!ja) {
        await registrar(uid, plano, Number(p.transaction_amount) || VALOR.anualpix, String(p.id), p);
        const { data: pf } = await adm.from('perfis').select('valido_ate').eq('id', uid).maybeSingle();
        const inicio = pf?.valido_ate && new Date(pf.valido_ate) > new Date() ? new Date(pf.valido_ate) : new Date();
        inicio.setFullYear(inicio.getFullYear() + 1);
        await adm.from('perfis').update({ valido_ate: inicio.toISOString(), plano, provedor: 'mercadopago', provedor_ref: String(p.id) }).eq('id', uid);
      }
    }
    return new Response('ok', { status: 200 });
  }

  // Assinaturas (mensal / anual)
  let pre: any = null, ap: any = null;
  if (tipo.includes('preapproval')) pre = await mp(`/preapproval/${id}`);
  else if (tipo.includes('authorized_payment')) {
    ap = await mp(`/authorized_payments/${id}`);
    if (ap?.preapproval_id) pre = await mp(`/preapproval/${ap.preapproval_id}`);
  }
  if (!pre?.external_reference) return new Response('ignorado', { status: 200 });
  const [uid, plano] = String(pre.external_reference).split('|');

  if (ap && (ap.payment?.status === 'approved' || ap.status === 'processed')) {
    await registrar(uid, plano, Number(ap.transaction_amount) || VALOR[plano] || 0, String(ap.id), ap);
  }
  if (pre.status === 'authorized') {
    const ate = pre.next_payment_date ? new Date(pre.next_payment_date) : new Date();
    if (!pre.next_payment_date) ate.setMonth(ate.getMonth() + (plano === 'anual' ? 12 : 1));
    ate.setDate(ate.getDate() + 3); // folga para a cobrança cair
    await adm.from('perfis').update({ valido_ate: ate.toISOString(), plano, provedor: 'mercadopago', provedor_ref: pre.id }).eq('id', uid);
  }
  return new Response('ok', { status: 200 });
});
