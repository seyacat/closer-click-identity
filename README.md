# @seyacat/closer-click-identity

Identidad de usuario y rating de peers compartidos entre las apps de Closer Click. Funciona aunque las apps vivan en orígenes distintos: usa un **vault iframe** alojado en un origin estable que guarda la información en su propio `localStorage` y expone una API por `postMessage`.

## Cómo funciona

```
┌────────────────────┐    postMessage    ┌──────────────────────┐
│  app (cualquier    │ ◀───────────────▶ │  vault iframe        │
│  origin: chat,     │                   │  origin: id.closer   │
│  qrshare, chess…)  │                   │  .click              │
│                    │                   │  - keypair P-256     │
│  import {Identity} │                   │  - peers (ratings)   │
└────────────────────┘                   └──────────────────────┘
```

Como todas las apps cargan el vault desde el mismo origin, comparten el mismo `localStorage` aunque ellas estén en orígenes distintos. La clave privada nunca sale del vault.

## Instalación

```bash
npm install @seyacat/closer-click-identity
```

## Uso

```js
import { Identity } from '@seyacat/closer-click-identity'

const id = await Identity.connect({
  vaultUrl: 'https://seyacat.github.io/closer-click-identity/'   // por defecto
})

console.log('my publickey JWK:', id.me.publickey)

// Identificar a un peer (handshake challenge/response)
const { nonce } = await id.makeChallenge()
// envía nonce al peer por el canal que sea (proxy, postMessage, etc.)
// el peer ejecuta await id.signChallenge(nonce) y te devuelve { nonce, publickey, signature }
const verification = await id.verifyResponse(response)
if (verification.ok) {
  console.log('peer verificado:', verification.publickey)
  await id.setNickname(verification.publickey, 'Bob de chess')
  await id.setRating(verification.publickey, 4, 'buen rival')
}

const peers = await id.listPeers()
```

## Hosting del vault

Para que distintas apps compartan datos, todas deben apuntar al **mismo `vaultUrl`**. La carpeta `vault/` de este paquete es un sitio estático (HTML + JS) listo para subir a:

- Un dominio dedicado: `id.closer.click`
- O temporalmente: `https://seyacat.github.io/closer-click-identity/vault/`

Importante: subir vía HTTPS y configurar `Content-Security-Policy: frame-ancestors *` (o lista de orígenes permitidos) para permitir que las apps lo embeban.

## API

### `Identity.connect(options?)`
Inicializa el iframe y resuelve cuando el vault está listo.

| opción       | tipo     | default                       |
|--------------|----------|-------------------------------|
| `vaultUrl`   | string   | `https://seyacat.github.io/closer-click-identity/` |
| `timeoutMs`  | number   | `5000`                        |

### Identidad propia

- `id.me`                            → `{ publickey, nickname? }`
- `id.setMyNickname(nickname)`

### Handshake

- `id.makeChallenge()`               → `{ nonce }`
- `id.signChallenge(nonce)`          → `{ nonce, publickey, signature }`
- `id.verifyResponse(response)`      → `{ ok, publickey?, peer? }`

### Peer book

- `id.getPeer(publickey)`
- `id.setNickname(publickey, nickname)`
- `id.setRating(publickey, rating, notes?)` (rating 0–5)
- `id.listPeers()`
- `id.forgetPeer(publickey)`

## Diseño

- **Una sola identidad por navegador**, persistente entre apps que apuntan al mismo vault.
- **Sin servidor**: todo en `localStorage` del vault.
- **Replay protection**: cada `makeChallenge` registra el nonce; `verifyResponse` exige que el nonce sea reciente (≤ 5 min).
- **Privacidad**: la clave privada vive solo en el vault, las apps nunca la ven.

## Licencia

MIT
