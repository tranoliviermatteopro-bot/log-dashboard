# Comment envoyer des logs depuis un site vers Log Dashboard

## 1. Obtenir une clé API

Dans le dashboard → onglet "Sites" → "Ajouter le site"  
Copie la clé API affichée (elle n'est montrée qu'une seule fois).

## 2. Ajouter dans ton site Node.js

```js
// logger.js — à placer dans n'importe quel projet
const LOG_URL = 'https://TON-LOG-DASHBOARD.onrender.com/api/ingest';
const API_KEY = process.env.LOG_DASHBOARD_KEY; // clé API dans les env vars Render

async function log(level, message, meta = null, source = null) {
  try {
    await fetch(LOG_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
      },
      body: JSON.stringify({ level, message, meta, source })
    });
  } catch {} // silencieux si le dashboard est indisponible
}

module.exports = {
  debug: (msg, meta, src) => log('debug', msg, meta, src),
  info:  (msg, meta, src) => log('info',  msg, meta, src),
  warn:  (msg, meta, src) => log('warn',  msg, meta, src),
  error: (msg, meta, src) => log('error', msg, meta, src),
  critical: (msg, meta, src) => log('critical', msg, meta, src),
};
```

## 3. Utilisation dans ton code

```js
const logger = require('./logger');

// Exemples
logger.info('Serveur démarré', { port: 3000 }, 'server.js');
logger.warn('Tentative de connexion échouée', { email: 'test@test.com' }, 'auth');
logger.error('Erreur base de données', { message: err.message, stack: err.stack }, 'db');
logger.critical('Crash inattendu', { error: err.message }, 'process');
```

## 4. Variables d'environnement à ajouter sur Render (pour chaque site)

```
LOG_DASHBOARD_KEY=ta_cle_api_ici
```

## Niveaux disponibles
- `debug` — développement, verbose
- `info` — événements normaux (démarrage, connexion, etc.)
- `warn` — avertissements non bloquants
- `error` — erreurs récupérables
- `critical` — erreurs graves, crash
