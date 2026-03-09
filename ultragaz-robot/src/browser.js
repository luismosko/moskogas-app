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
  try {
    const result = await page.evaluate(async (id) => {
      return new Promise((resolve, reject) => {
        apex.server.process('GET_SELECTS', { x01: id }, {
          success: (data) => resolve(data),
          error: (err) => reject(new Error('GET_SELECTS falhou: ' + JSON.stringify(err))),
          dataType: 'json',
        });
      });
    }, String(orderId));
    // Log completo da resposta para mapear os campos corretamente
    log(`GET_SELECTS #${orderId} → ${JSON.stringify(result).substring(0, 500)}`);
    return result;
  } catch(e) {
    log(`GET_SELECTS #${orderId} falhou: ${e.message} — tentando via DOM...`);
    // Fallback: extrai dados diretamente do DOM da linha do pedido
    try {
      const domData = await page.evaluate((id) => {
        // Procura linha com o ID do pedido
        const allRows = document.querySelectorAll('tr, .a-IRR-table tbody tr');
        for (const row of allRows) {
          const rowText = row.textContent;
          if (rowText.includes(id)) {
            const cells = Array.from(row.querySelectorAll('td')).map(c => c.innerText.trim());
            return { cells, html: row.innerHTML.substring(0, 300) };
          }
        }
        return null;
      }, String(orderId));
      if (domData) log(`DOM fallback #${orderId} → cells: ${JSON.stringify(domData.cells)}`);
      return domData;
    } catch(e2) {
      log(`DOM fallback também falhou: ${e2.message}`);
      return null;
    }
  }
}

// Busca pedidos pendentes no Hub — varre abas: Agendados, Em Aberto, Em Andamento
export async function getPendingOrders(page) {
  const log = (msg) => console.log(`[browser] ${new Date().toISOString()} ${msg}`);
  const allOrders = [];
  const seen = new Set();

  // Recarrega a página para garantir dados atualizados
  try {
    log('Recarregando página do Hub para dados frescos...');
    await page.reload({ waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(1500);
    log('Página recarregada!');
  } catch(e) {
    log(`Aviso: reload falhou (${e.message}) — continuando com página atual`);
  }

  // Seletores das abas que contêm pedidos a processar
  const TABS = [
    { label: 'Pedidos Agendados',    selector: null },  // primeira aba ativa por padrão
    { label: 'Pedidos em Aberto',    selector: null },
    { label: 'Pedidos em Andamento', selector: null },
  ];

  try {
    // Encontra os botões de aba pelo texto
    const tabButtons = await page.evaluate(() =>
      Array.from(document.querySelectorAll('.t-Tabs__item, .t-TabsRegion-tab, [role="tab"], .t-Tabs a, .tabs a, button'))
        .filter(el => /Agendad|Em Aberto|Andamento/i.test(el.textContent))
        .map(el => ({ text: el.textContent.trim(), id: el.id, cls: el.className }))
    );
    log(`Abas encontradas: ${JSON.stringify(tabButtons)}`);

    // Função para extrair IDs de pedidos da tabela visível — tag com a aba de origem
    const extractOrdersFromDOM = async (tabLabel) => {
      // Debug: logar o que está visível no DOM
      const domDebug = await page.evaluate(() => {
        const allText = document.body.innerText || '';
        const pedidoNums = allText.match(/\b2\d{7}\b/g) || [];
        return {
          tables: document.querySelectorAll('table').length,
          trs: document.querySelectorAll('tr').length,
          pedidoNums: [...new Set(pedidoNums)]
        };
      });
      log(`DOM [${tabLabel}]: ${domDebug.tables} tabelas, ${domDebug.trs} linhas, pedidos visíveis: ${JSON.stringify(domDebug.pedidoNums)}`);

      const orders = await page.evaluate((tab) => {
        // Seletores amplos — Oracle APEX usa várias estruturas de tabela
        const rows = document.querySelectorAll([
          'tr.t-Report-wrap',
          'table tbody tr',
          '.a-IRR-table tbody tr',
          '.t-Report-tableWrap tbody tr',
          'tr[class*="report"]',
          'tr[id*="row"]',
          'tr',
        ].join(', '));

        const found = [];
        rows.forEach(row => {
          // Ignora linhas de cabeçalho
          if (row.querySelector('th')) return;
          if (row.closest('thead')) return;

          let orderId = null;

          // Procura por número de pedido nos links (ex: <a>21164275</a>)
          const links = row.querySelectorAll('a');
          links.forEach(a => {
            const txt = a.textContent.trim();
            if (/^\d{7,}$/.test(txt)) orderId = txt;
          });

          // Procura em qualquer célula td
          if (!orderId) {
            const cells = row.querySelectorAll('td');
            cells.forEach(td => {
              const txt = (td.innerText || td.textContent || '').trim();
              if (/^\d{7,}$/.test(txt)) orderId = txt;
            });
          }

          if (orderId) {
            const cells = Array.from(row.querySelectorAll('td')).map(c => (c.innerText || c.textContent || '').trim());
            found.push({ id: orderId, cells, tab });
          }
        });

        // Remove duplicatas por id
        const unique = [];
        const seenIds = new Set();
        found.forEach(o => { if (!seenIds.has(o.id)) { seenIds.add(o.id); unique.push(o); } });
        return unique;
      }, tabLabel);
      log(`Aba [${tabLabel}]: ${orders.length} pedido(s) encontrado(s)`);
      return orders;
    };

    // Primeiro extrai da aba atual (sem clicar)
    const current = await extractOrdersFromDOM('atual');
    current.forEach(o => { if (!seen.has(o.id)) { seen.add(o.id); allOrders.push(o); } });

    // Clica em cada aba e extrai
    for (const tabText of ['Pedidos em Aberto', 'Pedidos Agendados', 'Pedidos em Andamento']) {
      try {
        // Tenta clicar na aba pelo texto
        const clicked = await page.evaluate((text) => {
          const els = document.querySelectorAll('.t-Tabs__item a, [role="tab"], .t-TabsRegion-tab, a, button');
          for (const el of els) {
            if (el.textContent.trim().includes(text)) {
              el.click();
              return true;
            }
          }
          return false;
        }, tabText);

        if (clicked) {
          await page.waitForTimeout(800); // aguarda carregar
          const orders = await extractOrdersFromDOM(tabText);
          orders.forEach(o => { if (!seen.has(o.id)) { seen.add(o.id); allOrders.push(o); } });
        }
      } catch (e) {
        log(`Erro ao clicar aba ${tabText}: ${e.message}`);
      }
    }

    log(`Total geral varredura: ${allOrders.length} pedido(s) único(s)`);
    return allOrders.length > 0 ? allOrders : null;

  } catch (e) {
    log(`getPendingOrders falhou: ${e.message}`);
    return null;
  }
}


// Busca pedidos cancelados no Hub — aba "Pedidos Cancelados"
export async function getCanceledOrders(page) {
  const log = (msg) => console.log(`[browser] ${new Date().toISOString()} ${msg}`);
  const canceled = [];

  try {
    // Clica na aba "Pedidos Cancelados"
    const clicked = await page.evaluate(() => {
      const els = document.querySelectorAll('.t-Tabs__item a, [role="tab"], .t-TabsRegion-tab, a, button');
      for (const el of els) {
        if (/Cancelad/i.test(el.textContent)) {
          el.click();
          return true;
        }
      }
      return false;
    });

    if (!clicked) {
      log('Aba Cancelados não encontrada');
      return [];
    }

    await page.waitForTimeout(800);

    // Debug: ver o que está visível
    const domDebug = await page.evaluate(() => {
      const allText = document.body.innerText || '';
      const pedidoNums = allText.match(/\b2\d{7}\b/g) || [];
      return { pedidoNums: [...new Set(pedidoNums)] };
    });
    log(`DOM [Cancelados]: pedidos visíveis: ${JSON.stringify(domDebug.pedidoNums)}`);

    // Extrai IDs de pedidos cancelados
    const orders = await page.evaluate(() => {
      const rows = document.querySelectorAll([
        'tr.t-Report-wrap', 'table tbody tr', '.a-IRR-table tbody tr',
        '.t-Report-tableWrap tbody tr', 'tr',
      ].join(', '));
      const found = [];
      rows.forEach(row => {
        if (row.querySelector('th') || row.closest('thead')) return;
        let orderId = null;
        row.querySelectorAll('a, td').forEach(el => {
          const txt = (el.innerText || el.textContent || '').trim();
          if (/^\d{7,}$/.test(txt)) orderId = txt;
        });
        if (orderId) {
          const cells = Array.from(row.querySelectorAll('td')).map(c => (c.innerText || c.textContent || '').trim());
          found.push({ id: orderId, cells });
        }
      });
      const unique = [];
      const seen = new Set();
      found.forEach(o => { if (!seen.has(o.id)) { seen.add(o.id); unique.push(o); } });
      return unique;
    });

    log(`Aba [Cancelados]: ${orders.length} pedido(s) encontrado(s)`);
    return orders;

  } catch (e) {
    log(`getCanceledOrders falhou: ${e.message}`);
    return [];
  }
}

export async function closeBrowser() {
  if (contextInstance) { try { await contextInstance.close(); } catch {} contextInstance = null; }
  if (browserInstance) { try { await browserInstance.close(); } catch {} browserInstance = null; }
}
