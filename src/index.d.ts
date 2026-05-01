export interface IdentityOptions {
  vaultUrl?: string
  timeoutMs?: number
}

export interface Me {
  publickey: string
  nickname?: string
}

export interface PeerInfo {
  publickey: string
  nickname?: string
  rating?: number
  notes?: string
  firstSeen?: number
  lastSeen?: number
}

export interface Challenge {
  nonce: string
}

export interface ChallengeResponse {
  nonce: string
  publickey: string
  signature: string
}

export interface VerifyResult {
  ok: boolean
  publickey?: string
  peer?: PeerInfo
}

export class Identity {
  static connect (options?: IdentityOptions): Promise<Identity>
  static current (): Identity | null
  constructor (options?: IdentityOptions)
  ready (): Promise<Identity>
  destroy (): void
  readonly me: Me | null
  makeChallenge (): Promise<Challenge>
  signChallenge (nonce: string): Promise<ChallengeResponse>
  verifyResponse (response: ChallengeResponse): Promise<VerifyResult>
  getPeer (publickey: string): Promise<PeerInfo | null>
  setNickname (publickey: string, nickname: string): Promise<PeerInfo>
  setRating (publickey: string, rating: number, notes?: string): Promise<PeerInfo>
  listPeers (): Promise<PeerInfo[]>
  forgetPeer (publickey: string): Promise<void>
  setMyNickname (nickname: string): Promise<{ me: Me }>
  on (event: 'peer_updated' | 'me_updated', handler: (payload: any) => void): () => void
}
