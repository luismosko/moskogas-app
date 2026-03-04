import { ImapFlow } from 'imapflow';

const log = (msg) => console.log(`[imap] ${new Date().toISOString()} ${msg}`);

/**
 * Marca todos os emails não lidos da Ultragaz como lidos (limpa antes de solicitar novo código)
 */
export async function limparEmailsUltragaz(gmailUser, gmailAppPassword) {
  const client = new ImapFlow({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    auth: { user: gmailUser, pass: gmailAppPassword },
    logger: false,
  });
  await client.connect();
  try {
    await client.mailboxOpen('INBOX');
    const msgs = await client.search({ unseen: true, from: 'ultragaz' }).catch(() => []);
    if (msgs && msgs.length > 0) {
      await client.messageFlagsAdd(msgs, ['\\Seen']);
      log(`${msgs.length} email(s) da Ultragaz marcados como lidos`);
    } else {
      log('Nenhum email antigo da Ultragaz para limpar');
    }
  } finally {
    await client.logout();
  }
}

/**
 * Aguarda novo email da Ultragaz com código 2FA (polling via IMAP)
 */
export async function buscarCodigo2FA(gmailUser, gmailAppPassword, maxWaitMs = 300000) {
  const inicio = Date.now();
  const checkInterval = 5000;
  let tentativa = 0;

  while (Date.now() - inicio < maxWaitMs) {
    try {
      const codigo = await lerUltimoCodigoNaoLido(gmailUser, gmailAppPassword);
      if (codigo) {
        log(`Código 2FA encontrado: ${codigo}`);
        return codigo;
      }
    } catch (e) {
      log(`Erro IMAP: ${e.message}`);
    }
    tentativa++;
    const elapsed = Math.round((Date.now() - inicio) / 1000);
    if (elapsed % 30 === 0 || tentativa === 1) log(`Aguardando código 2FA... (${elapsed}s)`);
    await new Promise(r => setTimeout(r, checkInterval));
  }

  throw new Error('Timeout aguardando código 2FA via email (5min)');
}

async function lerUltimoCodigoNaoLido(user, password) {
  const client = new ImapFlow({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    auth: { user, pass: password },
    logger: false,
  });

  await client.connect();
  try {
    await client.mailboxOpen('INBOX');

    // Busca apenas emails NÃO LIDOS da Ultragaz
    const msgs = await client.search({
      unseen: true,
      or: [
        { from: 'ultragaz' },
        { subject: 'código de autenticação' },
        { subject: 'codigo de autenticacao' },
      ]
    });

    if (!msgs || msgs.length === 0) return null;

    log(`${msgs.length} email(s) não lido(s) da Ultragaz encontrado(s)`);

    // Lê o mais recente
    for (const uid of msgs.reverse().slice(0, 3)) {
      const msg = await client.fetchOne(uid, { source: true });
      if (!msg) continue;
      const text = msg.source.toString('utf8');

      // Extrai código numérico de 4-8 dígitos
      const match = text.match(/\b(\d{4,8})\b/);
      if (match) {
        await client.messageFlagsAdd(uid, ['\\Seen']);
        return match[1];
      }
    }
    return null;
  } finally {
    await client.logout();
  }
}
