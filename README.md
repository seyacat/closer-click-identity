# @gatoseya/closer-click-identity

Identidad de usuario y rating de peers compartidos entre las apps de Closer Click. Funciona aunque las apps vivan en orígenes distintos: usa un **vault iframe** alojado en un origin estable que guarda la información en su propio `localStorage` y expone una API por `postMessage`.

## Cómo funciona

```
┌────────────────────┐    postMessage    ┌────────────────────────┐
│  app (cualquier    │ ◀───────────────▶ │  vault iframe          │
│  origin: chat,     │                   │  origin: id.closer     │
│  qrshare, chess…)  │                   │  .click                │
│                    │                   │  - keypair ECDSA P-256 │
│  import {Identity} │                   │  - keypair ECDH P-256  │
└────────────────────┘                   │  - peers + ratings     │
                                         └────────────────────────┘
```

Como todas las apps cargan el vault desde el mismo origin, comparten el mismo `localStorage` aunque ellas estén en orígenes distintos. **Las claves privadas nunca salen del vault** — las apps reciben firmas (de la ECDSA) y plaintext descifrado (de la ECDH) pero nunca las llaves.

## Instalación

```bash
npm install @gatoseya/closer-click-identity
```

## Uso

```js
import { Identity } from '@gatoseya/closer-click-identity'

const id = await Identity.connect({
  vaultUrl: 'https://id.closer.click/'   // por defecto
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
- O temporalmente: `https://id.closer.click/vault/`

Importante: subir vía HTTPS y configurar `Content-Security-Policy: frame-ancestors *` (o lista de orígenes permitidos) para permitir que las apps lo embeban.

## API

### `Identity.connect(options?)`
Inicializa el iframe y resuelve cuando el vault está listo.

| opción       | tipo     | default                       |
|--------------|----------|-------------------------------|
| `vaultUrl`   | string   | `https://id.closer.click/` |
| `timeoutMs`  | number   | `5000`                        |

### Identidad propia

- `id.me`                            → `{ publickey, nickname? }`
- `id.setMyNickname(nickname)`

### Handshake

- `id.makeChallenge()`               → `{ nonce }`
- `id.signChallenge(nonce)`          → `{ nonce, publickey, encryptionPubkey, signature }`
- `id.verifyResponse(response)`      → `{ ok, publickey?, encryptionPubkey?, peer? }`

### Peer book

- `id.getPeer(publickey)`
- `id.setNickname(publickey, nickname)`
- `id.setRating(publickey, rating, notes?)` — produce un envelope firmado y lo guarda como `peer.myRating` (rating 0–5).
- `id.mergeEndorsements(subject, [signedRatings], askerPubkey?)` — para web-of-trust: valida firmas, dedupea por `(ratedBy, subject)`, cap 50.
- `id.getRatingsForSubject(subject)` → `{ mine, endorsements }` para responder a un `RATING_QUERY`.
- `id.recordQuery(askerPubkey, subject?)` — contabiliza consultas para el suspicion modifier.
- `id.listPeers()`, `id.forgetPeer(publickey)`

### Encripción E2E (0.5.0+)

- `id.getEncryptionPubkey()` → JWK string del propio peer.
- `id.encrypt(recipients, plaintext)` → `{v:1, iv, ct, wrap}` envelope. `recipients` = `[{token, encryptionPubkey}]`. AES-256-GCM con clave efímera por mensaje, envuelta para cada destinatario vía ECDH(P-256).
- `id.decrypt(senderEncryptionPubkey, myToken, envelope)` → `{ plaintext }`. Forward-secrecy por mensaje (clave simétrica nueva cada vez).

### Backup / migración

- `id.exportIdentity()` → blob JSON con `privateJwk` (ECDSA), `encPrivateJwk` (ECDH), `me`, `peers`. **Sensible** — el host app es responsable de guardarlo de manera segura.
- `id.importIdentity(blob)` → reemplaza la identidad local. Soporta blobs v1 (sin ECDH) y v2 (con ambas keys).

## Diseño

- **Una sola identidad por navegador**, persistente entre apps que apuntan al mismo vault.
- **Sin servidor**: todo en `localStorage` del vault.
- **Replay protection**: cada `makeChallenge` registra el nonce; `verifyResponse` exige que el nonce sea reciente (≤ 5 min).
- **Privacidad**: la clave privada vive solo en el vault, las apps nunca la ven.

## Licencia

MIT
