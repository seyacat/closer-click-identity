/**
 * Closer Click Identity client.
 *
 * Loads a hidden iframe pointing at the vault origin and exchanges
 * postMessage requests. The vault holds the user's keypair and the
 * peer ratings/nicknames in its own localStorage, so all apps that
 * use this library share identity even across different origins.
 */

const DEFAULT_VAULT_URL = 'https://id.closer.click/'

let singleton = null

export class Identity {
  constructor (options = {}) {
    this.vaultUrl = options.vaultUrl || DEFAULT_VAULT_URL
    this.timeoutMs = options.timeoutMs ?? 5000
    this._iframe = null
    this._ready = null
    this._readyResolve = null
    this._nextId = 1
    this._pending = new Map()
    this._handler = null
    this._me = null
  }

  static async connect (options = {}) {
    if (singleton) return singleton
    singleton = new Identity(options)
    await singleton.ready()
    return singleton
  }

  static current () {
    return singleton
  }

  ready () {
    if (this._ready) return this._ready

    this._ready = new Promise((resolve, reject) => {
      this._readyResolve = resolve

      const iframe = document.createElement('iframe')
      iframe.src = this.vaultUrl
      iframe.style.display = 'none'
      iframe.setAttribute('aria-hidden', 'true')
      iframe.setAttribute('title', 'Closer Click identity vault')
      iframe.referrerPolicy = 'origin'
      this._iframe = iframe

      const timeout = setTimeout(() => {
        reject(new Error(`Vault did not respond within ${this.timeoutMs}ms`))
      }, this.timeoutMs)

      this._handler = (event) => {
        if (event.source !== iframe.contentWindow) return
        const msg = event.data
        if (!msg || msg._cci !== true) return

        if (msg.type === 'ready') {
          clearTimeout(timeout)
          this._me = msg.me
          this._readyResolve(this)
          return
        }

        if (msg.type === 'response') {
          const pending = this._pending.get(msg.id)
          if (!pending) return
          this._pending.delete(msg.id)
          clearTimeout(pending.timer)
          if (msg.error) pending.reject(new Error(msg.error))
          else pending.resolve(msg.result)
          return
        }

        if (msg.type === 'event') {
          this._emit(msg.event, msg.payload)
        }
      }

      window.addEventListener('message', this._handler)
      document.body.appendChild(iframe)
    })

    return this._ready
  }

  destroy () {
    if (this._handler) window.removeEventListener('message', this._handler)
    if (this._iframe && this._iframe.parentNode) this._iframe.parentNode.removeChild(this._iframe)
    this._iframe = null
    this._handler = null
    if (singleton === this) singleton = null
  }

  // ----- public API -----

  get me () { return this._me }

  /**
   * Identify a peer by token: the peer must respond to our challenge by
   * signing it with their private key. The vault holds and applies the rating.
   *
   * The host app is responsible for delivering the challenge to the peer
   * and bringing back the signed response — see makeChallenge / verifyResponse.
   */
  async makeChallenge () {
    return this._call('makeChallenge')
  }

  async signChallenge (nonce) {
    return this._call('signChallenge', { nonce })
  }

  async verifyResponse ({ nonce, publickey, signature }) {
    return this._call('verifyResponse', { nonce, publickey, signature })
  }

  async getPeer (publickey) {
    return this._call('getPeer', { publickey })
  }

  async setNickname (publickey, nickname) {
    return this._call('setNickname', { publickey, nickname })
  }

  async setRating (publickey, rating, notes) {
    return this._call('setRating', { publickey, rating, notes })
  }

  async listPeers () {
    return this._call('listPeers')
  }

  async forgetPeer (publickey) {
    return this._call('forgetPeer', { publickey })
  }

  /** Update own nickname (broadcast to the vault, not to other apps automatically) */
  async setMyNickname (nickname) {
    const result = await this._call('setMyNickname', { nickname })
    if (result?.me) this._me = result.me
    return result
  }

  on (event, handler) {
    if (!this._listeners) this._listeners = new Map()
    if (!this._listeners.has(event)) this._listeners.set(event, new Set())
    this._listeners.get(event).add(handler)
    return () => this._listeners.get(event)?.delete(handler)
  }

  _emit (event, payload) {
    const set = this._listeners?.get(event)
    if (!set) return
    for (const h of set) {
      try { h(payload) } catch (e) { console.error(e) }
    }
  }

  _call (method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this._iframe?.contentWindow) {
        return reject(new Error('Vault not ready'))
      }
      const id = `req_${this._nextId++}`
      const timer = setTimeout(() => {
        this._pending.delete(id)
        reject(new Error(`Vault timeout for ${method}`))
      }, this.timeoutMs)
      this._pending.set(id, { resolve, reject, timer })

      const targetOrigin = new URL(this.vaultUrl).origin
      this._iframe.contentWindow.postMessage(
        { _cci: true, type: 'request', id, method, params },
        targetOrigin
      )
    })
  }
}
