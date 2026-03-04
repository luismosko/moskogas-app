// browser.js — Playwright: login no Hub Ultragaz + captura URL assinada do WebSocket
import { chromium } from 'playwright';
import { buscarCodigo2FA } from './imap-reader.js';

let browserInstance = null;
let contextInstance = null;

const log = (msg) => console.log(`[browser] ${new Date().toISOString()} ${msg}`);

// Inicializa ou reutiliza browser/context
async function getBrowser() {
  if (browserInstance && browserInstance.isConnected()) return browserInstance;
  log('Iniciando Chromium headless...');
  browserInstance = await chromium.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled',
    ],
  });
  return browserInstance;
}

// Faz login e retorna o context com cookies de sessão
export async function loginHub(login, senha, hubUrl = 'https://hub.ultragaz.com.br') {
  log(`Fazendo login como ${login}...`);

  const browser = await getBrowser();

  // Fecha context anterior se existir
  if (contextInstance) {
    try { await contextInstance.close(); } catch {}
    contextInstance = null;
  }

  contextInstance = await browser.newContext({
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    viewport: { width: 1366, height: 768 },
    locale: 'pt-BR',
    timezoneId: 'America/Campo_Grande',
  });

  const page = await contextInstance.newPage();

  // Oculta sinais de automação
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  });

  try {
    await page.goto(hubUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    log(`URL inicial: ${page.url()}`);

    // Screenshot inicial
    await page.screenshot({ path: '/tmp/ultragaz-page-init.png' }).catch(() => {});

    // Formulário de UMA etapa: email + senha + botão Login
    await page.waitForSelector('input[type="email"], input[type="text"], input[name="P101_USERNAME"]', { timeout: 15000 });
    await page.waitForTimeout(1000);

    // Preenche email
    const emailField = await page.$('input[type="email"]') ||
                       await page.$('input[name="P101_USERNAME"]') ||
                       await page.$('input[type="text"]');
    if (!emailField) throw new Error('Campo de email não encontrado');
    await emailField.fill('');
    await emailField.fill(login.toLowerCase().trim());
    log(`Email preenchido: ${login.toLowerCase().trim()}`);
    await page.waitForTimeout(300);

    // Preenche senha
    const senhaField = await page.$('input[type="password"]') ||
                       await page.$('input[name="P101_PASSWORD"]');
    if (!senhaField) throw new Error('Campo de senha não encontrado');
    await senhaField.fill('');
    await senhaField.click();
    await page.keyboard.type(senha, { delay: 50 }); // digita tecla por tecla (melhor com chars especiais)
    log('Senha preenchida (keyboard.type)');
    await page.waitForTimeout(300);

    // Screenshot antes de submeter
    await page.screenshot({ path: '/tmp/ultragaz-before-submit.png' }).catch(() => {});
    log(`URL antes de submeter: ${page.url()}`);

    // Inspeciona todos os botões da página para debug
    const allBtns = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('button, input[type="submit"], a')).map(el => ({
        tag: el.tagName,
        type: el.type || '',
        text: el.textContent?.trim() || el.value || '',
        id: el.id || '',
        cls: el.className || ''
      }));
    });
    log(`Botões encontrados: ${JSON.stringify(allBtns)}`);

    // Clica no botão "Login" direto (id=b-login), NÃO no "Login Ultragaz" (SSO Microsoft)
    const clicked = await page.evaluate(() => {
      // Prioridade: id="b-login" (login direto)
      const btnDireto = document.getElementById('b-login');
      if (btnDireto) { btnDireto.click(); return 'clicked:b-login:' + btnDireto.textContent.trim(); }
      // Fallback: botão com texto exato "Login" (não "Login Ultragaz")
      const all = Array.from(document.querySelectorAll('button'));
      const loginBtn = all.find(el => el.textContent.trim() === 'Login');
      if (loginBtn) { loginBtn.click(); return 'clicked:text:' + loginBtn.textContent.trim(); }
      return 'none';
    });
    log(`Resultado clique JS: ${clicked}`);

    await page.waitForTimeout(3000);

    // ── VERIFICA SE APARECEU MODAL DE 2FA ──
    const modal2fa = await page.$('#enviarCodigo, [id*="codigo"], [class*="modal"]').catch(() => null);
    const modal2faTexto = await page.evaluate(() => {
      const el = document.querySelector('body');
      return el ? el.innerText : '';
    }).catch(() => '');

    if (modal2faTexto.includes('Enviar') && modal2faTexto.includes('digo')) {
      log('Modal 2FA detectado! Selecionando opção email...');
      await page.screenshot({ path: '/tmp/ultragaz-2fa-modal.png' }).catch(() => {});

      // Seleciona radio "Receber no e-mail"
      const emailRadioClicked = await page.evaluate(() => {
        const labels = Array.from(document.querySelectorAll('label, span, div'));
        const emailLabel = labels.find(el => /e-mail/i.test(el.textContent));
        if (emailLabel) {
          // Clica no radio input associado
          const radio = emailLabel.querySelector('input[type="radio"]') ||
                        emailLabel.closest('label')?.querySelector('input') ||
                        document.querySelector('input[type="radio"]:not(:checked)');
          if (radio) { radio.click(); return true; }
          emailLabel.click();
          return 'label';
        }
        // Fallback: segundo radio da página
        const radios = document.querySelectorAll('input[type="radio"]');
        if (radios[1]) { radios[1].click(); return 'radio[1]'; }
        return false;
      });
      log(`Radio email selecionado: ${emailRadioClicked}`);
      await page.waitForTimeout(500);

      // Clica em "Enviar código de autenticação"
      const enviarClicked = await page.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        const enviar = btns.find(el => /enviar/i.test(el.textContent) || /enviar/i.test(el.value));
        if (enviar) { enviar.click(); return enviar.textContent || enviar.value; }
        return false;
      });
      log(`Botão enviar clicado: ${enviarClicked}`);
      await page.waitForTimeout(2000);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-enviado.png' }).catch(() => {});

      // ── AGUARDA CÓDIGO 2FA VIA GMAIL IMAP ──
      log('Aguardando código 2FA via Gmail IMAP...');
      const gmailUser = process.env.GMAIL_USER;
      const gmailPass = process.env.GMAIL_APP_PASSWORD;
      if (!gmailUser || !gmailPass) throw new Error('GMAIL_USER e GMAIL_APP_PASSWORD não configurados no .env');
      const codigo2fa = await buscarCodigo2FA(gmailUser, gmailPass, 300000);

      // Digita o código no campo
      await page.waitForSelector('input[type="text"], input[type="number"], input[maxlength]', { timeout: 10000 });
      const codigoField = await page.$('input[maxlength]') ||
                          await page.$('input[type="number"]') ||
                          await page.$('input[type="text"]');
      if (codigoField) {
        await codigoField.fill(codigo2fa);
        log(`Código ${codigo2fa} digitado`);
      }

      // Confirma o código
      const confirmarClicked = await page.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        const confirmar = btns.find(el => /confirmar|validar|entrar|ok/i.test(el.textContent));
        if (confirmar) { confirmar.click(); return confirmar.textContent; }
        if (btns[0]) { btns[0].click(); return 'first-btn'; }
        return false;
      });
      log(`Confirmação 2FA clicada: ${confirmarClicked}`);

      // Código 2FA usado — email já marcado como lido no Gmail

      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
      await page.waitForTimeout(2000);
    }

    // Screenshot após login
    await page.screenshot({ path: '/tmp/ultragaz-login.png' }).catch(() => {});

    // Verifica se logou
    const currentUrl = page.url();
    log(`URL final: ${currentUrl}`);

    if (currentUrl.includes('login') || currentUrl.includes('P101') || currentUrl.includes('signin')) {
      throw new Error('Login falhou — verifique as credenciais no config.html');
    }

    log(`Login realizado! URL: ${currentUrl}`);
    return { page, context: contextInstance };
  } catch (e) {
    await page.close().catch(() => {});
    throw e;
  }
}

// Chama processo APEX para obter URL WSS assinada
export async function getWebsocketInfo(page) {
  log('Buscando URL assinada do WebSocket...');

  const result = await page.evaluate(async () => {
    return new Promise((resolve, reject) => {
      if (typeof apex === 'undefined') {
        reject(new Error('APEX não disponível na página'));
        return;
      }
      apex.server.process('GET_WEBSOCKET_INFO', {}, {
        success: (data) => resolve(data),
        error: (err) => reject(new Error('GET_WEBSOCKET_INFO falhou: ' + JSON.stringify(err))),
        dataType: 'json',
      });
    });
  });

  if (!result || (!result.url && !result.wss_url && !result.endpoint)) {
    throw new Error('URL WSS não retornada: ' + JSON.stringify(result));
  }

  const wssUrl = result.url || result.wss_url || result.endpoint || result;
  log(`URL WSS obtida: ${typeof wssUrl === 'string' ? wssUrl.substring(0, 60) : JSON.stringify(wssUrl)}...`);
  return typeof wssUrl === 'string' ? wssUrl : JSON.stringify(wssUrl);
}

// Busca detalhes completos de um pedido via GET_SELECTS
export async function getOrderDetails(page, orderId) {
  log(`Buscando detalhes do pedido #${orderId}...`);

  const result = await page.evaluate(async (id) => {
    return new Promise((resolve, reject) => {
      apex.server.process('GET_SELECTS', { x01: id }, {
        success: (data) => resolve(data),
        error: (err) => reject(new Error('GET_SELECTS falhou: ' + JSON.stringify(err))),
        dataType: 'json',
      });
    });
  }, String(orderId));

  return result;
}

// Fecha tudo
export async function closeBrowser() {
  if (contextInstance) { try { await contextInstance.close(); } catch {} contextInstance = null; }
  if (browserInstance) { try { await browserInstance.close(); } catch {} browserInstance = null; }
}
