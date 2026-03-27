// IZGLP — Hub Ultragaz Content Script v2.2.0
// Só lê o DOM — as chamadas à API são feitas pelo background (sem CSP)

(function () {
  'use strict';

  let scanning = false;

  const log  = (msg) => console.log(`[IZGLP-Hub] ${msg}`);
  const warn = (msg) => console.warn(`[IZGLP-Hub] ⚠️ ${msg}`);

  function isContextValid() {
    try { return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id); }
    catch (e) { return false; }
  }

  function mapProduto(p) {
    const pu = String(p).toUpperCase();
    if (/P45|45KG/.test(pu)) return 'P45';
    if (/P20|20KG/.test(pu)) return 'P20';
    if (/P13|13KG/.test(pu)) return 'P13';
    if (/ÁGUA|AGUA|20L|WATER/.test(pu)) return 'AGUA20L';
    return p || 'P13';
  }

  function mapPagamento(pgto) {
    const p = String(pgto).toLowerCase();
    if (/dinheiro|cash/.test(p))          return 'dinheiro';
    if (/débito|debito|debit/.test(p))    return 'debito';
    if (/crédito|credito|credit/.test(p)) return 'credito';
    if (/vale|voucher/.test(p))           return 'vale_gas_ultragaz';
    return 'dinheiro';
  }

  function parseValor(v) {
    return parseFloat(String(v).replace(/\./g, '').replace(',', '.')) || 0;
  }

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  // ── Extrai pedidos do DOM ──────────────────────────────────────────────────
  function extractOrdersFromDOM(tabLabel) {
    const rows = document.querySelectorAll([
      'tr.t-Report-wrap', 'table tbody tr', '.a-IRR-table tbody tr',
      '.t-Report-tableWrap tbody tr', 'tr[class*="report"]', 'tr[id*="row"]', 'tr',
    ].join(', '));

    const found = [], seenIds = new Set();
    rows.forEach(row => {
      if (row.querySelector('th') || row.closest('thead')) return;
      let orderId = null;
      row.querySelectorAll('a').forEach(a => {
        if (/^\d{7,}$/.test(a.textContent.trim())) orderId = a.textContent.trim();
      });
      if (!orderId) {
        row.querySelectorAll('td').forEach(td => {
          const txt = (td.innerText || td.textContent || '').trim();
          if (/^\d{7,}$/.test(txt)) orderId = txt;
        });
      }
      if (orderId && !seenIds.has(orderId)) {
        seenIds.add(orderId);
        const cells = Array.from(row.querySelectorAll('td')).map(c => (c.innerText || c.textContent || '').trim());
        found.push({ id: orderId, cells, tab: tabLabel });
      }
    });
    return found;
  }

  async function clickTab(tabText) {
    const els = document.querySelectorAll('.t-Tabs__item a, [role="tab"], .t-TabsRegion-tab, a, button');
    for (const el of els) {
      if (el.textContent.trim().includes(tabText)) { el.click(); await sleep(900); return true; }
    }
    return false;
  }

  function parseOrderToPayload(rawData) {
    const cells = rawData.cells || [], tab = rawData.tab || '';
    let domCliente, domProduto, domQtd, domPgto, domEndereco, domVlrUnit, domTotal;

    if (/Agendad/i.test(tab)) {
      domCliente = cells[11]||''; domProduto = cells[6]||''; domQtd = cells[7]||'1';
      domPgto = cells[2]||''; domEndereco = cells[5]||''; domVlrUnit = cells[8]||'0'; domTotal = cells[10]||'0';
    } else {
      domCliente = cells[3]||''; domProduto = cells[4]||''; domQtd = cells[5]||'1';
      domPgto = cells[6]||''; domEndereco = cells[7]||''; domVlrUnit = cells[8]||'0'; domTotal = cells[10]||'0';
    }

    const produto    = mapProduto(domProduto);
    const quantidade = parseInt(domQtd) || 1;
    const valorUnit  = parseValor(domVlrUnit);
    const total      = parseValor(domTotal);
    const endParts   = domEndereco.split(',').map(s => s.trim());

    return {
      ultragaz_order_id: String(rawData.id),
      event_type:        'pendingOrder',
      customer_name:     domCliente,
      address_line:      endParts.slice(0, 2).join(', ') || domEndereco,
      bairro:            endParts[2] || '',
      complemento:       '',
      referencia:        '',
      phone_digits:      '',
      total_value:       total,
      tipo_pagamento:    mapPagamento(domPgto),
      items_json:        JSON.stringify([{
        name: produto, qty: quantidade, price: valorUnit,
        produto, quantidade, valor_unit: valorUnit,
      }]),
    };
  }

  // ── Varredura — apenas lê o DOM e envia para o background ─────────────────
  async function scanHub() {
    if (!isContextValid()) { console.warn('[IZGLP-Hub] ⚠️ RECARREGUE A ABA (F5)'); return; }
    if (scanning) { log('Varredura já em andamento...'); return; }
    scanning = true;

    try {
      log('🔍 Lendo DOM do Hub...');
      const activeOrders = [], seenIds = new Set();

      extractOrdersFromDOM('atual').forEach(o => { if (!seenIds.has(o.id)) { seenIds.add(o.id); activeOrders.push(o); } });

      for (const tabText of ['Pedidos em Aberto', 'Pedidos Agendados', 'Pedidos em Andamento']) {
        if (await clickTab(tabText)) {
          extractOrdersFromDOM(tabText.replace('Pedidos ', ''))
            .forEach(o => { if (!seenIds.has(o.id)) { seenIds.add(o.id); activeOrders.push(o); } });
        }
      }

      // Coleta cancelados
      const canceledIds = [];
      const canceledSet = new Set();
      if (await clickTab('Cancelad')) {
        extractOrdersFromDOM('Cancelados').forEach(o => {
          if (!canceledSet.has(o.id)) { canceledSet.add(o.id); canceledIds.push(o.id); }
        });
      }

      // Remove da lista de ativos qualquer pedido que também está em Cancelados
      const canceledSet2 = new Set(canceledIds);
      const activeFiltered = activeOrders.filter(o => !canceledSet2.has(o.id));

      if (activeOrders.length !== activeFiltered.length) {
        const removidos = activeOrders.filter(o => canceledSet2.has(o.id)).map(o => o.id);
        log(`⚠️ Removidos ${removidos.length} cancelado(s) da lista de ativos: [${removidos.join(', ')}]`);
      }

      log(`📋 Ativos válidos: [${activeFiltered.map(o=>o.id).join(', ')||'nenhum'}] | Cancelados: [${canceledIds.join(', ')||'nenhum'}]`);

      // Monta payloads para o background
      const ordersToSend = activeFiltered.map(o => ({
        id: o.id,
        payload: parseOrderToPayload(o),
      }));

      // Envia para o background fazer as chamadas à API (sem CSP)
      if (isContextValid()) {
        chrome.runtime.sendMessage({
          type: 'PROCESS_ORDERS',
          activeOrders: ordersToSend,
          canceledIds,
        }, (response) => {
          if (response && response.novos > 0)
            log(`✅ ${response.novos} pedido(s) novo(s) criado(s)!`);
          else if (response && response.cancelamentos > 0)
            log(`🚫 ${response.cancelamentos} pedido(s) cancelado(s)`);
          else
            log('✔ Nenhuma alteração');
        });
      }

    } catch (e) {
      warn(`Falha: ${e.message}`);
    } finally {
      scanning = false;
    }
  }

  // ── Listener ───────────────────────────────────────────────────────────────
  if (isContextValid()) {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (msg.type === 'SCAN') {
        scanHub().then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
        return true;
      }
      if (msg.type === 'PING') {
        sendResponse({ ok: true, url: location.href });
      }
    });
  }

  log('🟢 IZGLP Hub v2.2.0 — DOM reader ativo');
  setTimeout(() => {
    if (isContextValid()) scanHub();
    else console.warn('[IZGLP-Hub] ⚠️ Contexto inválido — pressione F5');
  }, 3000);

})();
