/*
 * Configuração do Appsico
 *
 * Envio do código de redefinição de senha por e-mail (EmailJS - https://www.emailjs.com)
 * 1. Crie uma conta gratuita no EmailJS e conecte um serviço de e-mail (ex.: Gmail).
 * 2. Crie um template com as variáveis {{to_email}}, {{code}} e {{app_name}}
 *    e coloque {{to_email}} no campo "To Email" do template.
 * 3. Preencha os três campos abaixo e gere o APK de novo.
 *
 * Enquanto estiver vazio, a redefinição por e-mail fica desativada no celular
 * e só o código de recuperação funciona.
 */
window.APPSICO_CONFIG = {
  // Conta na nuvem (Supabase): sincroniza celular e computador, com os prontuários criptografados.
  // Preencha com os dados do seu projeto (Project Settings → API). Enquanto estiver vazio,
  // o app funciona como antes, com os dados só no aparelho.
  supabase: {
    url: "https://nbyktcpvhlolunkzjbvf.supabase.co",
    anonKey: "sb_publishable_wvIsl-i4-74JKGH7GnzCMg_kkcj2zL8",      // a chave "anon public" / "publishable" (pode ficar no app, é pública)
    appUrl: "https://www.appsico.com.br/app/",       // endereço da versão web, ex.: "https://www.appsico.com.br/app/"
    siteUrl: "https://www.appsico.com.br"       // endereço do site, ex.: "https://www.appsico.com.br"
  },
  emailjs: {
    serviceId: "",
    templateId: "",
    publicKey: ""
  },
  // Login com Google para backup automático no Drive (credencial "App para computador" do Google Cloud)
  google: {
    clientId: "",
    clientSecret: ""
  },
  // Versão mostrada em Ajuda e suporte
  loja: "site",        // "site" = APK do site (assinatura pelo Mercado Pago); "play" = versão da Google Play (sem compras no app)
  versao: "6.0",
  // Contato do suporte (aparece em Ajuda e suporte). Ex.: whatsapp: "11999998888", email: "suporte@appsico.com.br"
  suporte: {
    whatsapp: "",
    email: ""
  },
  // Plano grátis x Premium (cobrança pela Google Play quando o app for publicado)
  billing: {
    limiteGratis: 5,   // pacientes no plano grátis
    diasTeste: 30,     // duração do Premium de teste enquanto não há conta na Google Play
    produtos: { mensal: "appsico_premium_mensal", anual: "appsico_premium_anual", anualpix: "appsico_premium_anual_pix" }
  },
  // Bloqueio automático por inatividade (minutos)
  autoLockMinutes: 5,
  // Tempo em segundo plano que exige a senha de novo (segundos)
  backgroundLockSeconds: 60
};
