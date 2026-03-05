import { chromium } from 'playwright';

let browserInstance = null;
let contextInstance = null;

const log = (msg) => console.log(`[browser] ${new Date().toISOString()} ${msg}`);

async function getBrowser() {
  if (browserInstance) {
    try { await browserInstance.version(); return browserInstance; } catch {}
    browserInstance = null;
  }
  log('Iniciando Chromium headless...');
  browserInstance = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-blink-features=AutomationControlled'],
  });
  return browserInstance;
}

// Atualiza status no Worker
async function updateHubStatus(apiUrl, apiKey, conectado, status, mensagem = '') {
  await fetch(`${apiUrl}/api/ultragaz/hub-status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
    body: JSON.stringify({ conectado, status, mensagem })
  }).catch(e => log(`Erro updateHubStatus: ${e.message}`));
}

// Faz login e retorna o context com cookies de sessão
export async function loginHub(login, senha, hubUrl = 'https://hub.ultragaz.com.br') {
  log(`Fazendo login como ${login}...`);

  const apiUrl = process.env.MOSKOGAS_API_URL || 'https://moskogas.com.br';
  const apiKey = process.env.MOSKOGAS_API_KEY;

  const browser = await getBrowser();
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
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
    window.chrome = { runtime: {} };
  });

  try {
    await updateHubStatus(apiUrl, apiKey, false, 'conectando', 'Abrindo Hub Ultragaz...');
    await page.goto(hubUrl, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await page.waitForTimeout(3000);
    log(`URL inicial: ${page.url()}`);

    // Log todos os inputs encontrados para diagnóstico
    const inputsInfo = await page.evaluate(() =>
      Array.from(document.querySelectorAll('input')).map(i => ({
        type: i.type, name: i.name, id: i.id, placeholder: i.placeholder, cls: i.className.substring(0,40)
      }))
    );
    const pageUrl = page.url();
    const pageTitle = await page.title().catch(() => '');
    log(`Inputs na página (${inputsInfo.length}): ${JSON.stringify(inputsInfo)}`);
    log(`URL: ${pageUrl} | Title: ${pageTitle}`);

    // Envia diagnóstico para o Worker (visível no config.html)
    await fetch(`${apiUrl}/api/ultragaz/robot-log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify({ url: pageUrl, title: pageTitle, inputs: inputsInfo, step: 'login-page' })
    }).catch(() => {});

    await page.screenshot({ path: '/tmp/ultragaz-login-page.png' }).catch(() => {});

    // Preenche email/usuário — tenta múltiplos seletores
    let emailField = null;
    const emailSelectors = [
      'input[type="email"]',
      'input[name="P101_USERNAME"]',
      'input[id="P101_USERNAME"]',
      'input[name="username"]',
      'input[name="email"]',
      'input[id*="user"]',
      'input[id*="email"]',
      'input[id*="login"]',
      'input:not([type="password"]):not([type="hidden"]):not([type="submit"])',
    ];
    for (const sel of emailSelectors) {
      try {
        await page.waitForSelector(sel, { timeout: 3000 });
        emailField = await page.$(sel);
        if (emailField) { log(`Campo email encontrado: ${sel}`); break; }
      } catch {}
    }
    if (!emailField) throw new Error('Campo de usuário/email não encontrado na página de login');
    await emailField.fill(login);
    log(`Email preenchido: ${login}`);

    // Preenche senha
    const senhaField = await page.$('input[type="password"]');
    if (senhaField) {
      await senhaField.click();
      await page.keyboard.type(senha, { delay: 50 });
      log('Senha preenchida (keyboard.type)');
    }

    log(`URL antes de submeter: ${page.url()}`);

    // Log botões e clica em Login direto (não Azure SSO)
    const botoesInfo = await page.evaluate(() =>
      Array.from(document.querySelectorAll('button')).map(b => ({ tag: 'BUTTON', type: b.type, text: b.textContent.trim(), id: b.id, cls: b.className }))
    );
    log(`Botões encontrados: ${JSON.stringify(botoesInfo)}`);

    const clicou = await page.evaluate(() => {
      const btn = document.getElementById('b-login');
      if (btn) { btn.click(); return `clicked:${btn.id}:${btn.textContent.trim()}`; }
      const btns = Array.from(document.querySelectorAll('button'));
      const login = btns.find(b => /^login$/i.test(b.textContent.trim()) && !b.id.includes('azure'));
      if (login) { login.click(); return `clicked:${login.id}:${login.textContent.trim()}`; }
      return 'nao-encontrado';
    });
    log(`Resultado clique JS: ${clicou}`);

    // Aguarda resposta do Hub
    await page.waitForTimeout(3000);

    // Verifica se apareceu modal de 2FA
    let modal2faTexto = '';
    try {
      await page.waitForSelector('text=Enviar código de autenticação', { timeout: 8000 });
      modal2faTexto = await page.evaluate(() => document.body.innerText);
    } catch {
      modal2faTexto = await page.evaluate(() => document.body.innerText).catch(() => '');
    }

    const tem2FA = modal2faTexto.includes('Enviar') && modal2faTexto.includes('digo');
    log(`Texto modal 2FA detectado: ${tem2FA} — preview: ${modal2faTexto.substring(0, 80).replace(/\n/g, ' ')}`);

    if (tem2FA) {
      log('Modal 2FA detectado! Selecionando opção email...');
      await updateHubStatus(apiUrl, apiKey, false, 'aguardando_2fa', 'Informe o código 2FA no sistema MoskoGás');

      // Encontra o iframe do 2FA
      await page.waitForTimeout(1000);
      let mfaFrame = null;
      for (const frame of page.frames()) {
        if (frame.url().includes('user-mfa') || frame.url().includes('mfa')) {
          mfaFrame = frame;
          log(`Frame 2FA encontrado: ${frame.url()}`);
          break;
        }
      }
      if (!mfaFrame) {
        const iframeEl = await page.$('iframe[src*="mfa"]');
        if (iframeEl) mfaFrame = await iframeEl.contentFrame();
      }
      if (!mfaFrame) throw new Error('Frame do modal 2FA não encontrado');

      await mfaFrame.waitForLoadState('domcontentloaded').catch(() => {});
      await page.waitForTimeout(1000);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-modal.png' }).catch(() => {});

      // Seleciona radio email
      const emailRadioClicked = await mfaFrame.evaluate(() => {
        const radios = Array.from(document.querySelectorAll('input[type="radio"]'));
        const info = radios.map(r => {
          const lbl = document.querySelector(`label[for="${r.id}"]`);
          return r.id + '|' + (lbl ? lbl.textContent.trim() : '');
        }).join(' || ');
        const emailRadio = radios.find(r => {
          const label = document.querySelector(`label[for="${r.id}"]`);
          return /mail/i.test(r.value) || (label && /mail/i.test(label.textContent));
        });
        if (emailRadio) {
          emailRadio.click(); emailRadio.checked = true;
          emailRadio.dispatchEvent(new Event('change', { bubbles: true }));
          return 'email:' + emailRadio.id + ' | todos: ' + info;
        }
        const ultimo = radios[radios.length - 1];
        if (ultimo) { ultimo.click(); ultimo.checked = true; return 'ultimo:' + ultimo.id + ' | todos: ' + info; }
        return 'nao-encontrado | ' + info;
      });
      log(`Radio email selecionado: ${emailRadioClicked}`);
      await page.waitForTimeout(800);

      // Clica em Enviar código
      const enviarClicked = await mfaFrame.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        const enviar = btns.find(el => /enviar/i.test(el.textContent) || /enviar/i.test(el.value));
        if (enviar) { enviar.click(); return 'OK:' + (enviar.textContent || enviar.value).trim().substring(0, 30); }
        return 'nao-encontrado';
      });
      log(`Botão enviar clicado: ${enviarClicked}`);
      await page.waitForTimeout(2000);
      await page.screenshot({ path: '/tmp/ultragaz-2fa-enviado.png' }).catch(() => {});

      // ── AGUARDA OPERADOR INSERIR O CÓDIGO NO APP ──
      log('Aguardando operador inserir código 2FA no painel MoskoGás...');
      let codigo2fa = null;
      const inicio = Date.now();
      const maxWait = 10 * 60 * 1000; // 10 minutos

      // Limpa código anterior no Worker
      await fetch(`${apiUrl}/api/ultragaz/2fa-code`, {
        method: 'DELETE',
        headers: { 'X-API-Key': apiKey }
      }).catch(() => {});

      while (!codigo2fa && Date.now() - inicio < maxWait) {
        await page.mouse.move(200, 200).catch(() => {}); // keepalive
        try {
          const r = await fetch(`${apiUrl}/api/ultragaz/2fa-code`, {
            headers: { 'X-API-Key': apiKey }
          });
          if (r.ok) {
            const data = await r.json();
            if (data.codigo) { codigo2fa = data.codigo; break; }
          }
        } catch {}
        const elapsed = Math.round((Date.now() - inicio) / 1000);
        if (elapsed % 30 === 0) log(`Aguardando código 2FA do operador... (${elapsed}s)`);
        await new Promise(res => setTimeout(res, 5000));
      }

      if (!codigo2fa) throw new Error('Timeout aguardando código 2FA do operador (10min)');
      log(`Código 2FA recebido do operador: ${codigo2fa}`);

      // Digita o código no iframe
      await mfaFrame.waitForSelector('input', { timeout: 10000 }).catch(() => {});
      const codigoField = await mfaFrame.$('input[maxlength]') || await mfaFrame.$('input[type="number"]') || await mfaFrame.$('input[type="text"]') || await mfaFrame.$('input');
      if (!codigoField) throw new Error('Campo de código 2FA não encontrado no iframe');
      await codigoField.fill('');
      await codigoField.fill(codigo2fa);
      log(`Código ${codigo2fa} digitado no iframe`);
      await page.waitForTimeout(500);

      // Confirma
      const confirmarClicked = await mfaFrame.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        const confirmar = btns.find(el => /confirmar|validar|entrar|verificar|ok|enviar/i.test(el.textContent || el.value));
        if (confirmar) { confirmar.click(); return confirmar.textContent || confirmar.value; }
        if (btns[0]) { btns[0].click(); return 'first:' + btns[0].textContent; }
        return 'nenhum';
      });
      log(`Confirmação 2FA: ${confirmarClicked}`);

      // Limpa código usado
      await fetch(`${apiUrl}/api/ultragaz/2fa-code`, { method: 'DELETE', headers: { 'X-API-Key': apiKey } }).catch(() => {});

      await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 20000 }).catch(() => {});
      await page.waitForTimeout(3000);
    }

    await page.screenshot({ path: '/tmp/ultragaz-login.png' }).catch(() => {});
    const currentUrl = page.url();
    log(`URL final: ${currentUrl}`);

    if (currentUrl.includes('login') || currentUrl.includes('P101') || currentUrl.includes('signin')) {
      await updateHubStatus(apiUrl, apiKey, false, 'erro', 'Login falhou — verifique credenciais');
      throw new Error('Login falhou — verifique as credenciais no config.html');
    }

    log(`✅ Login realizado! URL: ${currentUrl}`);
    await updateHubStatus(apiUrl, apiKey, true, 'conectado', `Conectado em ${new Date().toLocaleString('pt-BR')}`);
    return { page, context: contextInstance };

  } catch (e) {
    await page.screenshot({ path: '/tmp/ultragaz-error.png' }).catch(() => {});
    await updateHubStatus(apiUrl, apiKey, false, 'erro', e.message.substring(0, 100)).catch(() => {});
    if (contextInstance) { try { await contextInstance.close(); } catch {} contextInstance = null; }
    throw e;
  }
}

export function getContext() { return contextInstance; }

export async function getWebsocketInfo(page) {
  log('Buscando URL assinada do WebSocket...');
  const result = await page.evaluate(async () => {
    return new Promise((resolve, reject) => {
      if (typeof apex === 'undefined') { reject(new Error('APEX não disponível na página')); return; }
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

// Busca pedidos em aberto no Hub (varredura inicial ao conectar)
export async function getPendingOrders(page) {
  const log = (msg) => console.log(`[browser] ${new Date().toISOString()} ${msg}`);
  try {
    // Tenta via APEX process GET_ORDERS_OPEN ou similar
    const result = await page.evaluate(() => new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timeout GET_ORDERS_OPEN')), 10000);
      // Tenta GET_ORDERS_OPEN
      apex.server.process('GET_ORDERS_OPEN', {}, {
        success: (data) => { clearTimeout(timeout); resolve(data); },
        error: (err) => { clearTimeout(timeout); reject(new Error('GET_ORDERS_OPEN: ' + JSON.stringify(err))); }
      });
    })).catch(() => null);

    if (result) {
      log(`Pedidos em aberto via GET_ORDERS_OPEN: ${JSON.stringify(result).substring(0, 200)}`);
      return result;
    }

    // Fallback: lê o DOM da tabela de pedidos em aberto
    const orders = await page.evaluate(() => {
      const rows = document.querySelectorAll('table tr, .t-Report-wrap tr');
      const data = [];
      rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 3) {
          const text = Array.from(cells).map(c => c.innerText.trim());
          // Procura célula com ID numérico grande (ID do pedido Ultragaz)
          const idCell = text.find(t => /^\d{7,}$/.test(t));
          if (idCell) data.push({ raw: text, id: idCell });
        }
      });
      return data;
    });

    log(`Pedidos via DOM: ${orders.length} encontrados`);
    return orders.length > 0 ? orders : null;

  } catch (e) {
    log(`getPendingOrders falhou: ${e.message}`);
    return null;
  }
}

export async function closeBrowser() {
  if (contextInstance) { try { await contextInstance.close(); } catch {} contextInstance = null; }
  if (browserInstance) { try { await browserInstance.close(); } catch {} browserInstance = null; }
}
