/**
 * Closer Click Identity Vault.
 *
 * Loaded inside a hidden iframe by apps. Holds the user's ECDSA P-256 keypair
 * and a peer book (nicknames + ratings) in localStorage. Communicates with
 * its embedders via postMessage. The private key never leaves this page.
 */

const KEY_STORAGE = 'closer-click.identity.keypair'
const ME_STORAGE  = 'closer-click.identity.me'
const PEERS_STORAGE = 'closer-click.identity.peers'
const NONCE_STORAGE = 'closer-click.identity.nonces' // recently signed nonces (replay window)

// ----- crypto helpers -----

function canonicalStringify (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(canonicalStringify).join(',') + ']'
  const ks = Object.keys(v).sort()
  return '{' + ks.map(k => JSON.stringify(k) + ':' + canonicalStringify(v[k])).join(',') + '}'
}

function bufToBase64 (buf) {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

function base64ToBuf (b64) {
  const s = atob(b64)
  const bytes = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i)
  return bytes.buffer
}

async function loadOrCreateKeypair () {
  const raw = localStorage.getItem(KEY_STORAGE)
  if (raw) {
    try {
      const { privateJwk, publicJwk } = JSON.parse(raw)
      const privateKey = await crypto.subtle.importKey(
        'jwk', privateJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['sign']
      )
      const publicKey = await crypto.subtle.importKey(
        'jwk', publicJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['verify']
      )
      return { privateKey, publicKey, publicJwk }
    } catch (_) {}
  }
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ['sign', 'verify']
  )
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  localStorage.setItem(KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }))
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
}

async function signBytes (privateKey, bytes) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    bytes
  )
  return bufToBase64(sig)
}

async function verifyBytes (publicJwkStr, bytes, signatureBase64) {
  let publicKey
  try {
    const jwk = JSON.parse(publicJwkStr)
    publicKey = await crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify']
    )
  } catch (_) {
    return false
  }
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    publicKey,
    base64ToBuf(signatureBase64),
    bytes
  )
}

// ----- peer storage -----

function loadPeers () {
  try {
    const raw = localStorage.getItem(PEERS_STORAGE)
    if (!raw) return {}
    return JSON.parse(raw) || {}
  } catch (_) {
    return {}
  }
}

function savePeers (peers) {
  localStorage.setItem(PEERS_STORAGE, JSON.stringify(peers))
}

function upsertPeer (publickey, patch) {
  const peers = loadPeers()
  const existing = peers[publickey] || { publickey, firstSeen: Date.now() }
  peers[publickey] = { ...existing, ...patch, publickey, lastSeen: Date.now() }
  savePeers(peers)
  return peers[publickey]
}

// ----- nonce replay protection -----

const NONCE_TTL_MS = 5 * 60 * 1000

function loadNonces () {
  try {
    const raw = localStorage.getItem(NONCE_STORAGE)
    if (!raw) return {}
    const obj = JSON.parse(raw) || {}
    const now = Date.now()
    for (const k of Object.keys(obj)) if (now - obj[k] > NONCE_TTL_MS) delete obj[k]
    return obj
  } catch (_) {
    return {}
  }
}

function saveNonces (obj) {
  localStorage.setItem(NONCE_STORAGE, JSON.stringify(obj))
}

function rememberNonce (nonce) {
  const obj = loadNonces()
  obj[nonce] = Date.now()
  saveNonces(obj)
}

function isFreshNonce (nonce) {
  const obj = loadNonces()
  return Object.prototype.hasOwnProperty.call(obj, nonce)
}

// ----- me -----

function loadMe () {
  try {
    const raw = localStorage.getItem(ME_STORAGE)
    return raw ? JSON.parse(raw) : null
  } catch (_) { return null }
}

function saveMe (me) {
  localStorage.setItem(ME_STORAGE, JSON.stringify(me))
}

// ----- handlers -----

let keypair = null
let publickeyJwkStr = null

const handlers = {
  async makeChallenge () {
    const nonce = crypto.randomUUID()
    rememberNonce(nonce)
    return { nonce }
  },

  async signChallenge ({ nonce }) {
    if (!nonce || typeof nonce !== 'string') throw new Error('nonce required')
    const bytes = new TextEncoder().encode(nonce)
    const signature = await signBytes(keypair.privateKey, bytes)
    return { nonce, publickey: publickeyJwkStr, signature }
  },

  async verifyResponse ({ nonce, publickey, signature }) {
    if (!nonce || !publickey || !signature) return { ok: false }
    if (!isFreshNonce(nonce)) return { ok: false, reason: 'nonce expired or unknown' }
    const bytes = new TextEncoder().encode(nonce)
    const ok = await verifyBytes(publickey, bytes, signature)
    if (!ok) return { ok: false }
    const peer = upsertPeer(publickey, {})
    return { ok: true, publickey, peer }
  },

  async getPeer ({ publickey }) {
    const peers = loadPeers()
    return peers[publickey] || null
  },

  async setNickname ({ publickey, nickname }) {
    return upsertPeer(publickey, { nickname: String(nickname || '').slice(0, 40) })
  },

  async setRating ({ publickey, rating, notes }) {
    const r = Math.max(0, Math.min(5, Number(rating) || 0))
    const patch = { rating: r }
    if (typeof notes === 'string') patch.notes = notes.slice(0, 500)
    return upsertPeer(publickey, patch)
  },

  async listPeers () {
    return Object.values(loadPeers()).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
  },

  async forgetPeer ({ publickey }) {
    const peers = loadPeers()
    delete peers[publickey]
    savePeers(peers)
  },

  async setMyNickname ({ nickname }) {
    const me = { publickey: publickeyJwkStr, nickname: String(nickname || '').slice(0, 40) }
    saveMe(me)
    return { me }
  },

  async exportIdentity () {
    const raw = localStorage.getItem(KEY_STORAGE)
    if (!raw) throw new Error('No keypair to export')
    const keys = JSON.parse(raw)
    return {
      version: 1,
      privateJwk: keys.privateJwk,
      publicJwk: keys.publicJwk,
      me: loadMe(),
      peers: loadPeers(),
      exportedAt: new Date().toISOString()
    }
  },

  async importIdentity ({ privateJwk, publicJwk, me, peers }) {
    if (!privateJwk || !publicJwk) throw new Error('privateJwk and publicJwk required')
    // Validate by importing
    await crypto.subtle.importKey(
      'jwk', privateJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['sign']
    )
    await crypto.subtle.importKey(
      'jwk', publicJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify']
    )
    localStorage.setItem(KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }))
    if (peers && typeof peers === 'object') savePeers(peers)
    const newPubKeyStr = JSON.stringify(publicJwk)
    const newMe = me && me.publickey === newPubKeyStr
      ? me
      : { publickey: newPubKeyStr, ...(me?.nickname ? { nickname: me.nickname } : {}) }
    saveMe(newMe)
    // Reload runtime keypair
    keypair = await loadOrCreateKeypair()
    publickeyJwkStr = JSON.stringify(keypair.publicJwk)
    return { me: newMe }
  }
}

// ----- bootstrap -----

;(async () => {
  keypair = await loadOrCreateKeypair()
  publickeyJwkStr = JSON.stringify(keypair.publicJwk)
  const persistedMe = loadMe()
  const me = persistedMe && persistedMe.publickey === publickeyJwkStr
    ? persistedMe
    : { publickey: publickeyJwkStr }
  if (me !== persistedMe) saveMe(me)

  window.addEventListener('message', async (event) => {
    const msg = event.data
    if (!msg || msg._cci !== true || msg.type !== 'request') return
    const { id, method, params } = msg
    const reply = (payload) => event.source?.postMessage(
      { _cci: true, type: 'response', id, ...payload },
      event.origin
    )
    const handler = handlers[method]
    if (!handler) return reply({ error: `Unknown method: ${method}` })
    try {
      const result = await handler(params || {})
      reply({ result })
    } catch (e) {
      reply({ error: e?.message || String(e) })
    }
  })

  // Tell every parent that the vault is ready.
  if (window.parent && window.parent !== window) {
    window.parent.postMessage(
      { _cci: true, type: 'ready', me },
      '*'
    )
  }
})()
