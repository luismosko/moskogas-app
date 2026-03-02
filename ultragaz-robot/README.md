# Robô Ultragaz × MoskoGás

Captura pedidos em tempo real do Hub Ultragaz via WebSocket e envia automaticamente para o MoskoGás.

## Fluxo

```
Hub Ultragaz (WebSocket AWS)
        ↓ evento newOrder
  GET_SELECTS (detalhes)
        ↓
POST /api/ultragaz/pedido
        ↓
MoskoGás D1 (pedido NOVO)
        ↓
WhatsApp → atendentes
```

## Credenciais

As credenciais do Hub Ultragaz ficam **no painel config.html** (Configurações → Ultragaz Hub).
O robô busca automaticamente — não precisa de .env para login/senha.

## Instalação no VPS (DigitalOcean)

```bash
# 1. Clonar repositório
git clone https://github.com/luismosko/moskogas-app.git
cd moskogas-app/ultragaz-robot

# 2. Instalar dependências
npm install

# 3. Instalar Chromium do Playwright
npx playwright install chromium
npx playwright install-deps chromium

# 4. Configurar .env
cp .env.example .env
nano .env
# Preencher: MOSKOGAS_API_KEY

# 5. Instalar PM2 (gerenciador de processo)
npm install -g pm2

# 6. Iniciar robô
pm2 start src/index.js --name ultragaz-robot

# 7. Auto-start no boot
pm2 startup
pm2 save
```

## Comandos úteis (PM2)

```bash
pm2 logs ultragaz-robot          # Ver logs em tempo real
pm2 status                        # Ver status
pm2 restart ultragaz-robot        # Reiniciar
pm2 stop ultragaz-robot           # Parar
```

## .env

```env
MOSKOGAS_API_URL=https://api.moskogas.com.br
MOSKOGAS_API_KEY=sua_app_api_key_aqui
SESSION_RENEWAL_MS=21600000       # 6 horas
LOG_LEVEL=info
```
