// APPSICO — abre o pagamento no Mercado Pago.
// mensal e anual: assinatura com renovação automática no cartão (preapproval).
// anualpix: pagamento único (Checkout Pro, aceita Pix e cartão), vale 1 ano.
// Segredos (Edge Functions → Secrets): MP_ACCESS_TOKEN e APP_URL (endereço da versão web, ex.: https://www.appsico.com.br/app/)
import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

// Para mudar preços, altere aqui (e os valores de "mrr" em admin_resumo no schema.sql)
const PLANOS: Record<string, { valor: number; meses?: number; titulo: string }> = {
  mensal:   { valor: 24.9, meses: 1,  titulo: 'Appsico — assinatura mensal' },
  anual:    { valor: 199,  meses: 12, titulo: 'Appsico — assinatura anual' },
  anualpix: { valor: 199,             titulo: 'Appsico — 1 ano (pagamento único)' },
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  try {
    const sb = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } },
    });
    const { data: { user } } = await sb.auth.getUser();
    if (!user) return json({ error: 'Entre na sua conta para assinar.' }, 401);
    const { plano } = await req.json();
    const P = PLANOS[plano];
    if (!P) return json({ error: 'Plano inválido.' }, 400);

    const appUrl = Deno.env.get('APP_URL') ?? '';
    const token = Deno.env.get('MP_ACCESS_TOKEN');
    if (!token) return json({ error: 'Pagamento ainda não configurado.' }, 503);
    const ref = `${user.id}|${plano}`;
    const aviso = `${Deno.env.get('SUPABASE_URL')}/functions/v1/mp-webhook`;
    let r: Response;
    if (plano === 'anualpix') {
      r = await fetch('https://api.mercadopago.com/checkout/preferences', {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          items: [{ title: P.titulo, quantity: 1, unit_price: P.valor, currency_id: 'BRL' }],
          payer: { email: user.email }, external_reference: ref, notification_url: aviso,
          back_urls: { success: `${appUrl}?pago=1`, pending: `${appUrl}?pago=1`, failure: appUrl }, auto_return: 'approved',
          statement_descriptor: 'APPSICO',
        }),
      });
    } else {
      r = await fetch('https://api.mercadopago.com/preapproval', {
        method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: P.titulo, external_reference: ref, payer_email: user.email, back_url: `${appUrl}?pago=1`,
          auto_recurring: { frequency: P.meses, frequency_type: 'months', transaction_amount: P.valor, currency_id: 'BRL' },
          status: 'pending',
        }),
      });
    }
    const j = await r.json();
    if (!r.ok) return json({ error: j.message || 'Erro no Mercado Pago.', detalhe: j }, 502);
    return json({ url: j.init_point, id: j.id });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
