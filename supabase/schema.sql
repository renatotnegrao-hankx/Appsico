-- =====================================================================
--  APPSICO — banco de dados (Supabase)
--  Cole TUDO no Supabase: menu "SQL Editor" → "New query" → colar → "Run".
--  Pode rodar de novo sem problema.
--
--  Sigilo: os prontuários chegam aqui JÁ CRIPTOGRAFADOS pelo app
--  (AES-256-GCM). O servidor guarda só dados embaralhados: nem o Supabase
--  nem o administrador do Appsico conseguem ler o conteúdo.
-- =====================================================================

-- 1) Perfil de cada psicólogo (dados de conta e assinatura — nada clínico)
create table if not exists public.perfis (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text,
  nome          text,
  crp           text,
  criado_em     timestamptz not null default now(),
  teste_ate     timestamptz not null default (now() + interval '15 days'),
  valido_ate    timestamptz,          -- assinatura paga válida até
  plano         text,                 -- mensal | anual | anualpix | cortesia
  provedor      text,                 -- mercadopago | admin
  provedor_ref  text
);

-- 2) Cofre: prontuários criptografados de cada psicólogo
create table if not exists public.cofres (
  user_id       uuid primary key references auth.users(id) on delete cascade,
  versao        bigint not null default 1,
  chaves        jsonb  not null,      -- chave dos dados, embrulhada pela senha e pelo código de recuperação
  dados         jsonb  not null,      -- {iv, ct}: todo o prontuário, criptografado no aparelho
  dispositivo   text,
  atualizado_em timestamptz not null default now()
);

-- 3) Pagamentos recebidos (só o servidor grava)
create table if not exists public.pagamentos (
  id          bigserial primary key,
  user_id     uuid,
  email       text,
  provedor    text,
  plano       text,
  valor       numeric(10,2) not null default 0,
  status      text,
  externo_id  text unique,
  payload     jsonb,
  criado_em   timestamptz not null default now()
);

-- 4) Administradores (cadastre o seu e-mail com o comando do guia)
create table if not exists public.admins (email text primary key);

-- 5) Segurança: cada pessoa só enxerga o que é dela
alter table public.perfis     enable row level security;
alter table public.cofres     enable row level security;
alter table public.pagamentos enable row level security;
alter table public.admins     enable row level security;

drop policy if exists "perfil: ler o próprio"   on public.perfis;
drop policy if exists "perfil: editar o próprio" on public.perfis;
drop policy if exists "cofre: ler o próprio"    on public.cofres;
create policy "perfil: ler o próprio"    on public.perfis for select using (auth.uid() = id);
create policy "perfil: editar o próprio" on public.perfis for update using (auth.uid() = id) with check (auth.uid() = id);
create policy "cofre: ler o próprio"     on public.cofres for select using (auth.uid() = user_id);

grant usage on schema public to anon, authenticated;
revoke all on public.perfis, public.cofres, public.pagamentos, public.admins from anon, authenticated;
grant select on public.perfis to authenticated;
grant update (nome, crp) on public.perfis to authenticated;   -- teste, plano e validade só o servidor altera
grant select on public.cofres to authenticated;              -- gravações só pelas funções abaixo

-- 6) Cria o perfil (com 15 dias de teste) quando alguém se cadastra
create or replace function public.novo_usuario()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.perfis (id, email, nome, crp)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'nome', ''), coalesce(new.raw_user_meta_data->>'crp', ''))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists ao_criar_usuario on auth.users;
create trigger ao_criar_usuario after insert on auth.users for each row execute function public.novo_usuario();

-- 7) Quem é administrador
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public, auth as $$
  select exists (select 1 from auth.users u join public.admins a on lower(a.email) = lower(u.email)
                 where u.id = auth.uid() and u.email_confirmed_at is not null);
$$;

-- 7b) Situação do acesso (teste ou assinatura), com o horário do servidor
create or replace function public.meu_acesso()
returns json language sql stable security definer set search_path = public as $$
  select json_build_object(
    'teste_ate', p.teste_ate, 'valido_ate', p.valido_ate, 'plano', p.plano,
    'agora', now(),
    'ativo', (p.teste_ate > now() or coalesce(p.valido_ate > now(), false)),
    'em_teste', (p.teste_ate > now() and not coalesce(p.valido_ate > now(), false)),
    'admin', public.is_admin())
  from public.perfis p where p.id = auth.uid();
$$;

-- 8) Cofre: criar, salvar (com controle de versão) e trocar as chaves
create or replace function public.criar_cofre(p_chaves jsonb, p_dados jsonb, p_disp text default null)
returns bigint language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'não autenticado'; end if;
  insert into cofres (user_id, versao, chaves, dados, dispositivo) values (auth.uid(), 1, p_chaves, p_dados, p_disp);
  return 1;
exception when unique_violation then
  raise exception 'cofre já existe';
end $$;

-- Grava só se ninguém salvou antes (versão igual); senão devolve null e o app mescla e tenta de novo
create or replace function public.salvar_cofre(p_dados jsonb, p_base bigint, p_disp text default null)
returns bigint language plpgsql security definer set search_path = public as $$
declare v bigint;
begin
  if auth.uid() is null then raise exception 'não autenticado'; end if;
  if not exists (select 1 from perfis p where p.id = auth.uid() and (p.teste_ate > now() or coalesce(p.valido_ate > now(), false))) then
    raise exception 'assinatura inativa';
  end if;
  update cofres set dados = p_dados, versao = versao + 1, dispositivo = p_disp, atualizado_em = now()
   where user_id = auth.uid() and versao = p_base
   returning versao into v;
  return v;
end $$;

create or replace function public.trocar_chaves(p_chaves jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'não autenticado'; end if;
  update cofres set chaves = p_chaves where user_id = auth.uid();
end $$;

-- 9) "Excluir minha conta": apaga a conta, o perfil e o cofre
create or replace function public.excluir_minha_conta()
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'não autenticado'; end if;
  delete from auth.users where id = auth.uid();
end $$;

-- 10) Administrador
create or replace function public.admin_resumo()
returns json language plpgsql stable security definer set search_path = public as $$
declare r json;
begin
  if not public.is_admin() then raise exception 'acesso negado'; end if;
  with a as (select * from perfis where valido_ate > now())
  select json_build_object(
    'usuarios',     (select count(*) from perfis),
    'novos_7d',     (select count(*) from perfis where criado_em > now() - interval '7 days'),
    'novos_30d',    (select count(*) from perfis where criado_em > now() - interval '30 days'),
    'ativos_7d',    (select count(*) from cofres where atualizado_em > now() - interval '7 days'),
    'em_teste',     (select count(*) from perfis where teste_ate > now() and (valido_ate is null or valido_ate <= now())),
    'expirados',    (select count(*) from perfis where teste_ate <= now() and (valido_ate is null or valido_ate <= now())),
    'mensal',       (select count(*) from a where plano = 'mensal'),
    'anual',        (select count(*) from a where plano = 'anual'),
    'anualpix',     (select count(*) from a where plano = 'anualpix'),
    'cortesia',     (select count(*) from a where plano = 'cortesia'),
    'mrr',          round((select count(*) from a where plano = 'mensal') * 24.90
                        + (select count(*) from a where plano in ('anual', 'anualpix')) * 199.00 / 12, 2),
    'receita_total',(select coalesce(sum(valor),0) from pagamentos where status = 'approved'),
    'receita_mes',  (select coalesce(sum(valor),0) from pagamentos where status = 'approved' and criado_em >= date_trunc('month', now())),
    'recentes',     (select coalesce(json_agg(y), '[]'::json) from (
                       select email, plano, valor, criado_em from pagamentos where status = 'approved' order by criado_em desc limit 10) y)
  ) into r;
  return r;
end $$;

create or replace function public.admin_usuarios(q text default '')
returns table (id uuid, email text, nome text, crp text, criado_em timestamptz, teste_ate timestamptz,
               valido_ate timestamptz, plano text, ultimo_uso timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'acesso negado'; end if;
  return query
    select p.id, p.email, p.nome, p.crp, p.criado_em, p.teste_ate, p.valido_ate, p.plano, c.atualizado_em
    from perfis p left join cofres c on c.user_id = p.id
    where coalesce(q,'') = '' or p.email ilike '%'||q||'%' or p.nome ilike '%'||q||'%'
    order by p.criado_em desc limit 300;
end $$;

-- Dar cortesia (30d | 90d | 1y), estender o teste (+15d) ou remover
create or replace function public.admin_liberar(alvo uuid, modo text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'acesso negado'; end if;
  if modo = 'remover' then
    update perfis set valido_ate = null, plano = null, provedor = null, provedor_ref = null where id = alvo;
  elsif modo = 'teste15' then
    update perfis set teste_ate = greatest(teste_ate, now()) + interval '15 days' where id = alvo;
  else
    update perfis set
      valido_ate = case modo when '30d' then now() + interval '30 days'
                             when '90d' then now() + interval '90 days'
                             else now() + interval '1 year' end,
      plano = 'cortesia', provedor = 'admin', provedor_ref = modo
    where id = alvo;
  end if;
end $$;

revoke all on function public.meu_acesso(), public.criar_cofre(jsonb, jsonb, text), public.salvar_cofre(jsonb, bigint, text),
  public.trocar_chaves(jsonb), public.excluir_minha_conta(), public.is_admin(), public.admin_resumo(),
  public.admin_usuarios(text), public.admin_liberar(uuid, text) from public, anon;
grant execute on function public.meu_acesso(), public.criar_cofre(jsonb, jsonb, text), public.salvar_cofre(jsonb, bigint, text),
  public.trocar_chaves(jsonb), public.excluir_minha_conta(), public.is_admin(), public.admin_resumo(),
  public.admin_usuarios(text), public.admin_liberar(uuid, text) to authenticated;

-- 11) Arquivo do app Android (APK) em pasta privada: só quem tem acesso ativo baixa
insert into storage.buckets (id, name, public) values ('apk', 'apk', false) on conflict (id) do nothing;
