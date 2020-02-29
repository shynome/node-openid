export interface AllParams {
  'openid.assoc_handle': string
  'openid.op_endpoint': string
  /**
   * `aaaa,xxxxx`
   */
  'openid.signed': string
  'openid.sig': string
  'openid.claimed_id': string
  'openid.identity': string
}

export type Params = Partial<AllParams>

export interface Provider {
  version: string
  endpoint: string
  claimedIdentifier: string
  localIdentifier: string | null
}

export interface Association {
  type: string
  secret: string
  provider: Provider
}

export interface AssociationRequestParams {
  'openid.mode':
    | 'associate'
    | 'error'
    | 'cancel'
    | 'checkid_immediate'
    | 'checkid_setup'
  'openid.error'?: any
  'openid.ns'?: 'http://specs.openid.net/auth/2.0'
  'openid.assoc_type': string
  'openid.session_type': string
  'openid.dh_modulus': string
  'openid.dh_gen': string
  'openid.dh_consumer_public': string

  'openid.return_to': string
  'openid.realm': string
  'openid.trust_root': string

  is_valid?: 'true'
  'openid.invalidate_handle': string

  'openid.response_nonce': string

  'openid.ns.sreg': string
  'openid.sreg.policy_url': string
  'openid.sreg.required': string
  'openid.sreg.optional': string

  'openid.ns.ui': string

  'openid.ns.ax': string
  'openid.ax.mode': string
  'openid.ax.required': string
  'openid.ax.if_available': string

  'openid.ns.oauth': string
  'openid.oauth.consumer': string
  'openid.oauth.scope': string
}

export type RequsetParams = Partial<AssociationRequestParams & AllParams>
