export interface IdentityOptions {
  vaultUrl?: string
  timeoutMs?: number
}

export interface Me {
  publickey: string
  encryptionPubkey?: string
  nickname?: string
}

export interface EnvelopeV1 {
  v: 1
  iv: string
  ct: string
  wrap: Record<string, { iv: string; ct: string }>
}

export interface EncryptRecipient {
  token: string
  encryptionPubkey: string
}

export interface SignedRating {
  subject: string
  rating: number
  notes: string
  ratedBy: string
  issuedAt: number
  signature: string
}

export interface QueryStats {
  queriesMade: number
  queriesKnown: number
}

export interface PeerInfo {
  publickey: string
  encryptionPubkey?: string
  nickname?: string
  rating?: number
  notes?: string
  myRating?: SignedRating | null
  endorsements?: SignedRating[]
  queryStats?: QueryStats
  firstSeen?: number
  lastSeen?: number
}

export interface Challenge {
  nonce: string
}

export interface ChallengeResponse {
  nonce: string
  publickey: string
  encryptionPubkey?: string
  signature: string
}

export interface VerifyResult {
  ok: boolean
  publickey?: string
  encryptionPubkey?: string | null
  peer?: PeerInfo
}

export interface IdentityExport {
  version: number
  privateJwk: Record<string, any>
  publicJwk: Record<string, any>
  me: Me | null
  peers: Record<string, PeerInfo>
  exportedAt: string
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
  getEncryptionPubkey (): Promise<string>
  encrypt (recipients: EncryptRecipient[], plaintext: string): Promise<EnvelopeV1>
  decrypt (
    senderEncryptionPubkey: string,
    myToken: string,
    envelope: EnvelopeV1
  ): Promise<{ plaintext: string }>
  mergeEndorsements (
    subject: string,
    endorsements: SignedRating[],
    askerPubkey?: string
  ): Promise<{ merged: number; total: number }>
  getRatingsForSubject (
    subject: string
  ): Promise<{ mine: SignedRating | null; endorsements: SignedRating[] }>
  recordQuery (askerPubkey: string, subject?: string): Promise<PeerInfo | null>
  exportIdentity (): Promise<IdentityExport>
  importIdentity (blob: IdentityExport | Record<string, any>): Promise<{ me: Me }>
  on (event: 'peer_updated' | 'me_updated', handler: (payload: any) => void): () => void
}
