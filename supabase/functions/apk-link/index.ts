// APPSICO — devolve um link temporário (1 hora) para baixar o app Android.
// Só funciona para quem está no teste grátis ou com assinatura ativa.
// O arquivo fica no Storage, pasta privada "apk", com o nome "appsico.apk".
import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  try {
    const sb = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } },
    });
    const { data: { user } } = await sb.auth.getUser();
    if (!user) return json({ error: 'Entre na sua conta para baixar o app.' }, 401);
    const { data: ac } = await sb.rpc('meu_acesso');
    if (!ac?.ativo) return json({ error: 'Seu teste grátis terminou. Assine para baixar o app.' }, 402);
    const adm = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
    const { data, error } = await adm.storage.from('apk').createSignedUrl('appsico.apk', 3600, { download: 'Appsico.apk' });
    if (error || !data) return json({ error: 'Arquivo do app não encontrado.' }, 404);
    return json({ url: data.signedUrl });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
