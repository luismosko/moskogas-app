import { ImapFlow } from 'imapflow';

const log = (msg) => console.log(`[imap] ${new Date().toISOString()} ${msg}`);

/**
 * Busca o código 2FA da Ultragaz no Gmail via IMAP
 * Aguarda até maxWaitMs por um email novo da Ultragaz
 */
export async function buscarCodigo2FA(gmailUser, gmailAppPassword, maxWaitMs = 300000, desde = null) {
  const inicio = Date.now();
  const checkInterval = 5000;
  const naoAntesDe = desde || inicio; // ignora emails anteriores a este timestamp

  while (Date.now() - inicio < maxWaitMs) {
    try {
      const codigo = await lerCodigoDoGmail(gmailUser, gmailAppPassword, naoAntesDe);
      if (codigo) {
        log(`Código 2FA encontrado: ${codigo}`);
        return codigo;
      }
    } catch (e) {
      log(`Erro IMAP: ${e.message}`);
    }
    const elapsed = Math.round((Date.now() - inicio) / 1000);
    if (elapsed % 30 === 0) log(`Aguardando código 2FA... (${elapsed}s)`);
    await new Promise(r => setTimeout(r, checkInterval));
  }

  throw new Error('Timeout aguardando código 2FA via email (5min)');
}

async function lerCodigoDoGmail(user, password, naoAntesDe = 0) {
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

    // Busca emails não lidos da Ultragaz após o momento do request
    const since = new Date(Math.max(naoAntesDe - 30000, Date.now() - 10 * 60 * 1000));
    const msgs = await client.search({
      unseen: true,
      since,
      or: [
        { from: 'ultragaz' },
        { subject: 'código' },
        { subject: 'autenticacao' },
        { subject: 'autenticação' },
        { subject: 'codigo' },
      ]
    });

    if (!msgs || msgs.length === 0) return null;

    // Lê o email mais recente
    for (const uid of msgs.reverse().slice(0, 3)) {
      const msg = await client.fetchOne(uid, { source: true });
      if (!msg) continue;
      const text = msg.source.toString('utf8');

      // Verifica se email é recente (após naoAntesDe)
      const dateMatch = text.match(/Date: (.+)/i);
      if (dateMatch) {
        const emailDate = new Date(dateMatch[1]);
        if (emailDate.getTime() < naoAntesDe - 60000) continue; // email muito antigo
      }

      // Extrai código numérico de 4-8 dígitos
      const match = text.match(/\b(\d{4,8})\b/);
      if (match) {
        // Marca como lido
        await client.messageFlagsAdd(uid, ['\\Seen']);
        return match[1];
      }
    }
    return null;
  } finally {
    await client.logout();
  }
}
