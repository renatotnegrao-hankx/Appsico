# Site do Appsico

Site institucional do Appsico (prontuário eletrônico para psicólogos), publicado pelo GitHub Pages.

## Arquivos
- `index.html` — página principal
- `privacidade.html` — política de privacidade (use este link na Google Play)
- `assets/logo.png` — símbolo do logo (cabeça com Ψ); `assets/logo-completo.png` — logo com o nome; `assets/favicon.png` — ícone da aba
- `assets/fotos/` — fotos de bem-estar usadas no site (topo, faixa central, "Cuidar de quem cuida", sigilo e download)
- `assets/telas/` — telas reais do app (pacientes fictícios de demonstração)
- `app/` — versão web do Appsico (para computador), a mesma do app Android
- `supabase/` — banco de dados e funções (assinatura pelo Mercado Pago e download do APK)
- `LEIA-ME-CONFIGURAR.md` — passo a passo para ligar a conta na nuvem, a assinatura e o download do app

## Trocar para o domínio appsico.com.br (quando quiser)

1. **No GitHub:** repositório → *Settings* → *Pages* → em *Custom domain* digite `appsico.com.br` → *Save*.
   (O GitHub cria sozinho um arquivo `CNAME` no repositório.)
2. **No Registro.br** (ou onde o domínio estiver) → *DNS* → crie estes registros:

   | Tipo  | Nome | Valor                         |
   |-------|------|-------------------------------|
   | A     | @    | 185.199.108.153               |
   | A     | @    | 185.199.109.153               |
   | A     | @    | 185.199.110.153               |
   | A     | @    | 185.199.111.153               |
   | CNAME | www  | renatotnegrao-hankx.github.io |

3. Espere a propagação (de alguns minutos até 24 h) e, em *Settings → Pages*, marque **Enforce HTTPS**.
