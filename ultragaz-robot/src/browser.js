// browser.js — Playwright: login no Hub Ultragaz + captura URL assinada do WebSocket
import { chromium } from 'playwright';

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

    // Aguarda campo de login
    await page.waitForSelector('input[type="text"], input[name="P101_USERNAME"], input[name="p_username"]', { timeout: 15000 });

    // Preenche credenciais
    const loginField = await page.$('input[name="P101_USERNAME"]') ||
                       await page.$('input[type="text"]') ||
                       await page.$('input[name="p_username"]');
    const senhaField = await page.$('input[name="P101_PASSWORD"]') ||
                       await page.$('input[type="password"]') ||
                       await page.$('input[name="p_password"]');

    if (!loginField || !senhaField) throw new Error('Campos de login não encontrados');

    await loginField.fill(login);
    await senhaField.fill(senha);

    // Clica no botão de login
    await page.click('button[type="submit"], input[type="submit"], #B3564791325482448, .t-Button--hot');
    await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});

    // Verifica se logou (URL mudou ou elemento do dashboard apareceu)
    const currentUrl = page.url();
    if (currentUrl.includes('P101') || currentUrl.includes('login')) {
      // Tenta verificar mensagem de erro
      const errMsg = await page.$eval('.t-Alert-body, .apex-error-message', el => el.textContent).catch(() => null);
      throw new Error('Login falhou' + (errMsg ? `: ${errMsg}` : ' — verifique as credenciais no config.html'));
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
