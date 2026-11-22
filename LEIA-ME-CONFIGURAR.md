# Appsico — ligar a conta na nuvem, a assinatura e o download do app

Enquanto `app/config.js` estiver sem os dados do Supabase, o Appsico funciona como antes
(dados só no aparelho). Depois de configurado:

- cada psicólogo cria a conta com **e-mail e senha** e ganha **15 dias grátis**;
- os prontuários são **criptografados no aparelho** antes de ir para a nuvem
  (nem você, como dono do Appsico, consegue ler);
- celular (app Android) e computador (navegador, em `/app/`) ficam sincronizados;
- depois dos 15 dias, sem assinar, ele fica no **plano grátis**: usa tudo com até 5 pacientes (os 5 primeiros), não cadastra o 6º em diante, e os pacientes além do limite ficam só para consulta;
- o **app Android só é baixado de dentro da conta**, por um link temporário, por quem está no teste ou com assinatura ativa.

Faça na ordem. Total: uns 40 minutos.

---

## 1. Criar o projeto no Supabase (5 min)
1. Acesse **supabase.com** → entre com o GitHub.
2. **New project** → nome `appsico` → crie uma senha do banco (guarde) → região **South America (São Paulo)** → **Create**. Espere ~2 min.
   (Projeto separado do Hankx: o plano grátis permite 2 projetos.)

## 2. Criar as tabelas (2 min)
1. Menu **SQL Editor** → **New query**.
2. Cole **todo** o arquivo `supabase/schema.sql` → **Run** → deve aparecer "Success".
3. Em outra *New query*, cadastre você como administrador (troque o e-mail) → **Run**:
   ```sql
   insert into public.admins (email) values ('SEU-EMAIL-AQUI') on conflict do nothing;
   ```

## 3. Login por e-mail (3 min)
Menu **Authentication → URL Configuration**:
- **Site URL**: o endereço da versão web, por exemplo `https://www.appsico.com.br/app/`
  (enquanto não tiver o domínio: `https://renatotnegrao-hankx.github.io/Appsico/app/`)
- **Redirect URLs**: o mesmo endereço.

Em **Authentication → Sign In / Providers → Email**, deixe **Confirm email** ligado.

## 4. Mandar para o Claude (ou colar você mesmo em `app/config.js`)
Menu **Project Settings → API**: copie a **Project URL** e a chave **anon public** (ou *publishable*).
Essas duas são públicas por natureza. **Nunca** envie nem publique a chave `service_role`.

## 5. Receber pelo Mercado Pago (15 min)
1. **mercadopago.com.br/developers/panel** → **Criar aplicação** (`Appsico`, Pagamentos online / Assinaturas).
2. Copie o **Access Token de produção** (`APP_USR-…`). É **secreto**: não envie por chat.
3. Supabase → **Edge Functions** → **Deploy a new function** → **Via Editor**, uma de cada vez:
   - `mp-assinar` → cole `supabase/functions/mp-assinar/index.ts` → **Deploy**.
   - `mp-webhook` → cole `supabase/functions/mp-webhook/index.ts` → **desligue "Enforce JWT verification"** → **Deploy**.
   - `apk-link` → cole `supabase/functions/apk-link/index.ts` → **Deploy**.
4. Supabase → **Edge Functions → Secrets**:
   - `MP_ACCESS_TOKEN` = o token do passo 2
   - `APP_URL` = o endereço da versão web (o mesmo do passo 3)
5. Mercado Pago → sua aplicação → **Webhooks** → URL de produção:
   `https://SEU-PROJETO.supabase.co/functions/v1/mp-webhook`
   → marque **Pagamentos** e **Planos e assinaturas** → **Salvar**.

Planos: **Mensal R$ 24,90** e **Anual R$ 199** (renovam sozinhos no cartão) e **Anual no Pix R$ 199** (pagamento único, vale 1 ano).
Para mudar preços: edite `PLANOS` em `mp-assinar/index.ts`, `VALOR` em `mp-webhook/index.ts` e os valores do `mrr` em `admin_resumo` no `schema.sql`.

## 6. Colocar o app Android para download (2 min)
1. Supabase → **Storage** → a pasta **apk** já existe (privada).
2. **Upload file** → envie o APK com o nome exato **`appsico.apk`**.
3. Para lançar uma versão nova, envie o arquivo novo com o mesmo nome (substituir).

O botão **Baixar app Android** aparece em Configurações → Conta e nuvem (na versão do navegador).

## 7. Publicar o site
GitHub → repositório **Appsico** → **Settings → Pages** → Branch **main**, pasta **/ (root)** → **Save**.
O site fica na raiz e o app web em `/app/`.

---

### Painel do administrador
Com o seu e-mail na tabela `admins`, aparece em Configurações → Conta e nuvem → **Painel do administrador**:
receita, assinantes por plano, quem está em teste ou expirado e a lista de usuários, onde você pode dar
**+15 dias de teste**, **cortesia** (30 dias, 90 dias, 1 ano) ou remover a assinatura.
O painel nunca mostra prontuários: eles estão criptografados.

### Segurança — o que o Supabase guarda
| Tabela | Conteúdo |
|---|---|
| `perfis` | nome, CRP, e-mail, fim do teste, plano e validade |
| `cofres` | prontuário inteiro **criptografado** + a chave embrulhada pela senha e pelo código de recuperação |
| `pagamentos` | pagamentos aprovados pelo Mercado Pago |

Se o psicólogo esquecer a senha **e** o código de recuperação, os prontuários não podem ser recuperados — por ninguém.
