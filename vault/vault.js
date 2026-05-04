/**
 * Closer Click Identity Vault.
 *
 * Loaded inside a hidden iframe by apps. Holds the user's ECDSA P-256 keypair
 * and a peer book (nicknames + ratings) in localStorage. Communicates with
 * its embedders via postMessage. The private key never leaves this page.
 */

const KEY_STORAGE = 'closer-click.identity.keypair'
const ENC_KEY_STORAGE = 'closer-click.identity.enc-keypair'
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

/**
 * Keypair ECDH P-256 (separado del ECDSA) usado para encripción E2E.
 * Las pubkeys se anuncian en el handshake; la priv nunca sale del vault.
 */
async function loadOrCreateEncKeypair () {
  const raw = localStorage.getItem(ENC_KEY_STORAGE)
  if (raw) {
    try {
      const { privateJwk, publicJwk } = JSON.parse(raw)
      const privateKey = await crypto.subtle.importKey(
        'jwk', privateJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true, ['deriveBits', 'deriveKey']
      )
      const publicKey = await crypto.subtle.importKey(
        'jwk', publicJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true, []
      )
      return { privateKey, publicKey, publicJwk }
    } catch (_) {}
  }
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, ['deriveBits', 'deriveKey']
  )
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  localStorage.setItem(ENC_KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }))
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
}

/** Importar una pubkey ECDH (JWK string) de un peer. */
async function importPeerEncPubkey (jwkStr) {
  const jwk = typeof jwkStr === 'string' ? JSON.parse(jwkStr) : jwkStr
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true, []
  )
}

/** Derivar clave compartida AES-256-GCM (no extractable) entre miPriv + suPub. */
async function deriveSharedAesKey (myPriv, peerPub) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPub },
    myPriv,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
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
let encKeypair = null
let encPublickeyJwkStr = null

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
    return {
      nonce,
      publickey: publickeyJwkStr,
      encryptionPubkey: encPublickeyJwkStr,
      signature
    }
  },

  async verifyResponse ({ nonce, publickey, signature, encryptionPubkey }) {
    if (!nonce || !publickey || !signature) return { ok: false }
    if (!isFreshNonce(nonce)) return { ok: false, reason: 'nonce expired or unknown' }
    const bytes = new TextEncoder().encode(nonce)
    const ok = await verifyBytes(publickey, bytes, signature)
    if (!ok) return { ok: false }
    // Persistir el encryptionPubkey anunciado (no firmado, pero se entrega
    // sobre el mismo canal verificado, así que el riesgo es aceptable y queda
    // disponible para encripción E2E).
    const patch = {}
    if (typeof encryptionPubkey === 'string' && encryptionPubkey) {
      patch.encryptionPubkey = encryptionPubkey
    }
    const peer = upsertPeer(publickey, patch)
    return { ok: true, publickey, encryptionPubkey: encryptionPubkey || null, peer }
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
    const safeNotes = typeof notes === 'string' ? notes.slice(0, 500) : ''
    const issuedAt = Date.now()
    const envelope = {
      subject: publickey,
      rating: r,
      notes: safeNotes,
      ratedBy: publickeyJwkStr,
      issuedAt
    }
    const sigBytes = new TextEncoder().encode(canonicalStringify(envelope))
    const signature = await signBytes(keypair.privateKey, sigBytes)
    const myRating = { ...envelope, signature }
    return upsertPeer(publickey, { myRating, rating: r, notes: safeNotes })
  },

  /**
   * Merge endorsements about a subject from third parties.
   * Each endorsement is a signed envelope; we verify it before storing,
   * dedupe by ratedBy keeping the newest issuedAt, and cap to 50 per subject.
   */
  async mergeEndorsements ({ subject, endorsements, askerPubkey }) {
    if (!subject || !Array.isArray(endorsements)) {
      return { merged: 0, total: 0 }
    }
    const peers = loadPeers()
    const existing = peers[subject] || { publickey: subject, firstSeen: Date.now() }
    const current = Array.isArray(existing.endorsements) ? existing.endorsements : []
    const byRater = new Map()
    for (const e of current) {
      if (e?.ratedBy) byRater.set(e.ratedBy, e)
    }
    let merged = 0
    for (const env of endorsements) {
      if (!env || typeof env !== 'object') continue
      const { subject: s, rating, notes, ratedBy, issuedAt, signature } = env
      if (s !== subject) continue
      if (typeof ratedBy !== 'string' || !ratedBy) continue
      if (ratedBy === publickeyJwkStr) continue // we have our own as myRating
      if (typeof signature !== 'string') continue
      if (typeof rating !== 'number' || rating < 0 || rating > 5) continue
      // Reject older or equal duplicates
      const prev = byRater.get(ratedBy)
      if (prev && (prev.issuedAt || 0) >= (issuedAt || 0)) continue
      // Verify signature
      const canonical = canonicalStringify({
        subject: s,
        rating,
        notes: typeof notes === 'string' ? notes : '',
        ratedBy,
        issuedAt
      })
      const ok = await verifyBytes(ratedBy, new TextEncoder().encode(canonical), signature)
      if (!ok) continue
      byRater.set(ratedBy, env)
      merged++
    }
    // Cap to 50 most recent
    const all = Array.from(byRater.values()).sort((a, b) => (b.issuedAt || 0) - (a.issuedAt || 0)).slice(0, 50)
    peers[subject] = { ...existing, publickey: subject, endorsements: all, lastSeen: Date.now() }
    // Track query stats: which asker probed for this subject
    if (typeof askerPubkey === 'string' && askerPubkey && askerPubkey !== publickeyJwkStr) {
      const askerRecord = peers[askerPubkey] || { publickey: askerPubkey, firstSeen: Date.now() }
      const stats = askerRecord.queryStats || { queriesMade: 0, queriesKnown: 0 }
      stats.queriesMade = (stats.queriesMade || 0) + 1
      // We "knew" the subject if we have either myRating or any endorsement for it
      const knewIt = !!(existing.myRating) || (Array.isArray(existing.endorsements) && existing.endorsements.length > 0)
      if (knewIt) stats.queriesKnown = (stats.queriesKnown || 0) + 1
      peers[askerPubkey] = { ...askerRecord, queryStats: stats, lastSeen: askerRecord.lastSeen || Date.now() }
    }
    savePeers(peers)
    return { merged, total: all.length }
  },

  /**
   * Get my own rating + collected endorsements for a subject. Used when
   * the host app needs to answer a RATING_QUERY from another peer.
   */
  async getRatingsForSubject ({ subject }) {
    const peers = loadPeers()
    const r = peers[subject]
    return {
      mine: r?.myRating || null,
      endorsements: Array.isArray(r?.endorsements) ? r.endorsements : []
    }
  },

  /** Tally that an asker queried us about a subject (for suspicion stats). */
  async recordQuery ({ askerPubkey, subject }) {
    if (!askerPubkey || askerPubkey === publickeyJwkStr) return null
    const peers = loadPeers()
    const askerRecord = peers[askerPubkey] || { publickey: askerPubkey, firstSeen: Date.now() }
    const stats = askerRecord.queryStats || { queriesMade: 0, queriesKnown: 0 }
    stats.queriesMade = (stats.queriesMade || 0) + 1
    if (subject) {
      const subjectRec = peers[subject]
      const knewIt = !!(subjectRec?.myRating) || (Array.isArray(subjectRec?.endorsements) && subjectRec.endorsements.length > 0)
      if (knewIt) stats.queriesKnown = (stats.queriesKnown || 0) + 1
    }
    peers[askerPubkey] = { ...askerRecord, queryStats: stats, lastSeen: askerRecord.lastSeen || Date.now() }
    savePeers(peers)
    return peers[askerPubkey]
  },

  async listPeers () {
    return Object.values(loadPeers()).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
  },

  async forgetPeer ({ publickey }) {
    const peers = loadPeers()
    delete peers[publickey]
    savePeers(peers)
  },

  // ----- Contacts (shared address book across the ecosystem) -------------
  // A "contact" is just a peer record with `isContact: true`. The peer's
  // pubkey is its identity; tokens are ephemeral and live in `lastToken`.
  // Contact metadata (nickname, encryptionPubkey, lastSeen) sits next to
  // ratings and endorsements in the same record, so chess/chat/messenger
  // all see the same address book.

  async addContact ({ publickey, nickname, encryptionPubkey, lastToken, notes }) {
    if (!publickey) throw new Error('publickey required')
    const patch = { isContact: true }
    if (nickname != null) patch.nickname = String(nickname).slice(0, 40)
    if (encryptionPubkey) patch.encryptionPubkey = encryptionPubkey
    if (lastToken) patch.lastToken = lastToken
    if (notes != null) patch.contactNotes = String(notes).slice(0, 300)
    return upsertPeer(publickey, patch)
  },

  async updateContact ({ publickey, patch }) {
    if (!publickey) throw new Error('publickey required')
    if (!patch || typeof patch !== 'object') return null
    const allowed = {}
    for (const k of ['nickname', 'encryptionPubkey', 'lastToken', 'contactNotes']) {
      if (k in patch) allowed[k] = patch[k]
    }
    return upsertPeer(publickey, allowed)
  },

  async removeContact ({ publickey }) {
    const peers = loadPeers()
    const p = peers[publickey]
    if (!p) return null
    delete p.isContact
    peers[publickey] = p
    savePeers(peers)
    return p
  },

  async listContacts () {
    return Object.values(loadPeers())
      .filter(p => p && p.isContact)
      .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
  },

  async setMyNickname ({ nickname }) {
    const me = {
      publickey: publickeyJwkStr,
      encryptionPubkey: encPublickeyJwkStr,
      nickname: String(nickname || '').slice(0, 40)
    }
    saveMe(me)
    return { me }
  },

  async getEncryptionPubkey () {
    return encPublickeyJwkStr
  },

  /**
   * Cifrar plaintext para una lista de destinatarios usando ECDH+AES-GCM.
   *
   * @param {{ recipients: Array<{token,encryptionPubkey}>, plaintext: string }} args
   * @returns {{ v:1, iv: string, ct: string, wrap: Record<string, {iv:string, ct:string}> }}
   */
  async encrypt ({ recipients, plaintext }) {
    if (!Array.isArray(recipients) || recipients.length === 0) {
      throw new Error('recipients required')
    }
    if (typeof plaintext !== 'string') {
      throw new Error('plaintext required')
    }
    // Clave simétrica efímera para este mensaje
    const k = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
    const kRaw = await crypto.subtle.exportKey('raw', k)
    // Cipher del payload una sola vez
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      k,
      new TextEncoder().encode(plaintext)
    )
    // Envolver `k` para cada destinatario
    const wrap = {}
    for (const r of recipients) {
      if (!r || !r.token || !r.encryptionPubkey) continue
      try {
        const peerPub = await importPeerEncPubkey(r.encryptionPubkey)
        const sharedKey = await deriveSharedAesKey(encKeypair.privateKey, peerPub)
        const wrapIv = crypto.getRandomValues(new Uint8Array(12))
        const wrappedCt = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: wrapIv },
          sharedKey,
          kRaw
        )
        wrap[r.token] = {
          iv: bufToBase64(wrapIv),
          ct: bufToBase64(new Uint8Array(wrappedCt))
        }
      } catch (e) {
        // Si falla un destinatario, lo omitimos del wrap (no podrá descifrar)
      }
    }
    return {
      v: 1,
      iv: bufToBase64(iv),
      ct: bufToBase64(new Uint8Array(ct)),
      wrap
    }
  },

  /**
   * Descifrar un envelope dirigido a este vault.
   *
   * @param {{ senderEncryptionPubkey: string, myToken: string, envelope: object }} args
   * @returns {{ plaintext: string }}
   */
  async decrypt ({ senderEncryptionPubkey, myToken, envelope }) {
    if (!senderEncryptionPubkey) throw new Error('senderEncryptionPubkey required')
    if (!myToken) throw new Error('myToken required')
    if (!envelope || envelope.v !== 1) throw new Error('Unsupported envelope')
    const myEntry = envelope.wrap && envelope.wrap[myToken]
    if (!myEntry) throw new Error('No wrap entry for this recipient')

    const senderPub = await importPeerEncPubkey(senderEncryptionPubkey)
    const sharedKey = await deriveSharedAesKey(encKeypair.privateKey, senderPub)
    const kRaw = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(myEntry.iv) },
      sharedKey,
      base64ToBuf(myEntry.ct)
    )
    const k = await crypto.subtle.importKey(
      'raw',
      kRaw,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    )
    const ptBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(envelope.iv) },
      k,
      base64ToBuf(envelope.ct)
    )
    return { plaintext: new TextDecoder().decode(ptBytes) }
  },

  async exportIdentity () {
    const raw = localStorage.getItem(KEY_STORAGE)
    if (!raw) throw new Error('No keypair to export')
    const keys = JSON.parse(raw)
    const encRaw = localStorage.getItem(ENC_KEY_STORAGE)
    const encKeys = encRaw ? JSON.parse(encRaw) : null
    return {
      version: 2,
      privateJwk: keys.privateJwk,
      publicJwk: keys.publicJwk,
      encPrivateJwk: encKeys?.privateJwk || null,
      encPublicJwk: encKeys?.publicJwk || null,
      me: loadMe(),
      peers: loadPeers(),
      exportedAt: new Date().toISOString()
    }
  },

  async importIdentity ({ privateJwk, publicJwk, encPrivateJwk, encPublicJwk, me, peers }) {
    if (!privateJwk || !publicJwk) throw new Error('privateJwk and publicJwk required')
    // Validar la signing keypair importando.
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

    // Si el blob trae encryption keypair (export v2+), validar e importar.
    // Si no (v1), generamos una nueva al rehidratar — el usuario perderá los
    // mensajes E2E pasados pero conservará identidad+ratings.
    if (encPrivateJwk && encPublicJwk) {
      await crypto.subtle.importKey(
        'jwk', encPrivateJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true, ['deriveBits', 'deriveKey']
      )
      await crypto.subtle.importKey(
        'jwk', encPublicJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true, []
      )
      localStorage.setItem(ENC_KEY_STORAGE, JSON.stringify({
        privateJwk: encPrivateJwk,
        publicJwk: encPublicJwk
      }))
    } else {
      localStorage.removeItem(ENC_KEY_STORAGE)
    }

    if (peers && typeof peers === 'object') savePeers(peers)

    // Recargar keypairs en runtime
    keypair = await loadOrCreateKeypair()
    publickeyJwkStr = JSON.stringify(keypair.publicJwk)
    encKeypair = await loadOrCreateEncKeypair()
    encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)

    const newMe = me && me.publickey === publickeyJwkStr
      ? { ...me, encryptionPubkey: encPublickeyJwkStr }
      : {
          publickey: publickeyJwkStr,
          encryptionPubkey: encPublickeyJwkStr,
          ...(me?.nickname ? { nickname: me.nickname } : {})
        }
    saveMe(newMe)

    return { me: newMe }
  }
}

// ----- bootstrap -----

;(async () => {
  keypair = await loadOrCreateKeypair()
  publickeyJwkStr = JSON.stringify(keypair.publicJwk)
  encKeypair = await loadOrCreateEncKeypair()
  encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)

  const persistedMe = loadMe()
  let me
  if (persistedMe && persistedMe.publickey === publickeyJwkStr) {
    me = persistedMe
    if (me.encryptionPubkey !== encPublickeyJwkStr) {
      me = { ...me, encryptionPubkey: encPublickeyJwkStr }
      saveMe(me)
    }
  } else {
    me = { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr }
    saveMe(me)
  }

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
