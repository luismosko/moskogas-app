// browser.js — Playwright: login no Hub Ultragaz + captura URL assinada do WebSocket
import { chromium } from 'playwright';
import { buscarCodigo2FA, limparEmailsUltragaz } from './imap-reader.js';

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

  // Oculta sinais de automação (anti-bot detection)
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
    Object.defineProperty(navigator, 'languages', { get: () => ['pt-BR', 'pt', 'en'] });
    window.chrome = { runtime: {} };
    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
  });

  try {
    // Aguarda um pouco antes de navegar (simula comportamento humano)
    await page.waitForTimeout(1000 + Math.floor(Math.random() * 1000));
    await page.goto(hubUrl, { waitUntil: 'networkidle', timeout: 30000 });
    log(`URL inicial: ${page.url()}`);
    await page.waitForTimeout(1500);

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
    // Aguarda até 8s pelo modal de 2FA
    const modal2faTexto = await Promise.race([
      page.waitForSelector('text=Enviar código de autenticação', { timeout: 8000 })
        .then(() => page.evaluate(() => document.body.innerText))
        .catch(() => null),
      page.evaluate(() => document.body.innerText)
    ]).catch(() => '');

    const tem2FA = modal2faTexto && (
      modal2faTexto.includes('Enviar') && modal2faTexto.includes('digo')
    );
    log(`Texto modal 2FA detectado: ${tem2FA} — preview: ${(modal2faTexto||'').substring(0,100)}`);

    if (tem2FA) {
      log('Modal 2FA detectado! Selecionando opção email...');
      await page.screenshot({ path: '/tmp/ultragaz-2fa-modal.png' }).catch(() => {});

      // Modal 2FA está dentro de um IFRAME — precisa acessar o frame
      log('Buscando iframe do modal 2FA...');
      await page.waitForTimeout(1000);

      // Pega o frame do modal MFA
      let mfaFrame = null;
      for (const frame of page.frames()) {
        const url = frame.url();
        if (url.includes('user-mfa') || url.includes('mfa')) {
          mfaFrame = frame;
          log(`Frame 2FA encontrado: ${url}`);
          break;
        }
      }

      if (!mfaFrame) {
        log('Frame 2FA não encontrado — tentando via iframe selector');
        const iframeEl = await page.$('iframe[src*="mfa"], iframe[title*="Autenticação"]');
        if (iframeEl) mfaFrame = await iframeEl.contentFrame();
      }

      if (!mfaFrame) throw new Error('Frame do modal 2FA não encontrado');

      // Aguarda conteúdo do frame carregar
      await mfaFrame.waitForLoadState('domcontentloaded').catch(() => {});
      await page.waitForTimeout(1000);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-modal.png' }).catch(() => {});

      // Seleciona radio email dentro do frame
      const emailRadioClicked = await mfaFrame.evaluate(() => {
        const radios = Array.from(document.querySelectorAll('input[type="radio"]'));
        const emailRadio = radios.find(r => {
          const label = document.querySelector(`label[for="${r.id}"]`);
          return /mail/i.test(r.value) || (label && /mail/i.test(label.textContent));
        }) || radios[1];
        if (emailRadio && !emailRadio.checked) {
          emailRadio.click();
          emailRadio.checked = true;
          emailRadio.dispatchEvent(new Event('change', { bubbles: true }));
          return 'radio:' + emailRadio.id;
        }
        return emailRadio ? 'ja-selecionado' : 'nao-encontrado';
      });
      log(`Radio email selecionado: ${emailRadioClicked}`);
      await page.waitForTimeout(800);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-radio.png' }).catch(() => {});

      // Clica em "Enviar código de autenticação" dentro do frame
      const enviarClicked = await mfaFrame.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        const info = btns.map(b => `"${b.textContent.trim()}" id="${b.id}"`).join(' | ');
        const enviar = btns.find(el =>
          /enviar/i.test(el.textContent) ||
          /enviar/i.test(el.value) ||
          /submit/i.test(el.type)
        );
        if (enviar) { enviar.click(); return 'OK:' + (enviar.textContent || enviar.value).trim().substring(0, 30); }
        return 'nao-encontrado | ' + info;
      });
      log(`Botão enviar clicado: ${enviarClicked}`);
      await page.waitForTimeout(3000);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-enviado.png' }).catch(() => {});
      await page.waitForTimeout(2000);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-enviado.png' }).catch(() => {});

      // ── AGUARDA CÓDIGO 2FA VIA GMAIL IMAP ──
      const gmailUser = process.env.GMAIL_USER;
      const gmailPass = process.env.GMAIL_APP_PASSWORD;
      if (!gmailUser || !gmailPass) throw new Error('GMAIL_USER e GMAIL_APP_PASSWORD não configurados no .env');

      // Limpa emails antigos da Ultragaz antes de solicitar novo código
      log('Limpando emails antigos da Ultragaz...');
      await limparEmailsUltragaz(gmailUser, gmailPass);

      log('Aguardando código 2FA via Gmail IMAP...');
      const codigo2fa = await buscarCodigo2FA(gmailUser, gmailPass, 300000);

      // Digita o código no IFRAME do 2FA
      await mfaFrame.waitForSelector('input', { timeout: 10000 }).catch(() => {});
      const codigoField = await mfaFrame.$('input[maxlength]') ||
                          await mfaFrame.$('input[type="number"]') ||
                          await mfaFrame.$('input[type="text"]') ||
                          await mfaFrame.$('input');
      if (!codigoField) throw new Error('Campo de código 2FA não encontrado no iframe');
      await codigoField.fill('');
      await codigoField.fill(codigo2fa);
      log(`Código ${codigo2fa} digitado no iframe`);
      await page.waitForTimeout(500);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-codigo.png' }).catch(() => {});

      // Confirma o código dentro do iframe
      const confirmarClicked = await mfaFrame.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        const confirmar = btns.find(el => /confirmar|validar|entrar|verificar|ok|enviar/i.test(el.textContent || el.value));
        if (confirmar) { confirmar.click(); return confirmar.textContent || confirmar.value; }
        if (btns[0]) { btns[0].click(); return 'first-btn:' + (btns[0].textContent || ''); }
        return 'nenhum-botao';
      });
      log(`Confirmação 2FA clicada: ${confirmarClicked}`);

      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
      await page.waitForTimeout(3000);
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
