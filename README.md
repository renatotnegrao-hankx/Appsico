# Site do Appsico

Site institucional do Appsico (prontuário eletrônico para psicólogos), publicado pelo GitHub Pages.

## Arquivos
- `index.html` — página principal
- `privacidade.html` — política de privacidade (use este link na Google Play)
- `assets/logo.png` — logo oficial (o `logo.svg` antigo ficou guardado, mas não é mais usado)
- `assets/telas/` — telas reais do app (pacientes fictícios de demonstração)
- `downloads/appsico.apk` — APK do app (versão 3.4). Para atualizar, substitua por um novo com o mesmo nome

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
