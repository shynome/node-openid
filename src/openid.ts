/* OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2010 by Håvard Stranden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *
 */

import crypto from 'crypto'
import axios from 'axios'
import querystring from 'querystring'
import * as xrds from './xrds'
import url from 'url'
import { hasOwnProperty } from './utils'

var _associations: { [k: string]: Association } = {}
var _discoveries: { [k: string]: Provider } = {}
var _nonces: { [k: string]: Date } = {}

export class RelyingParty {
  public constructor(
    public readonly returnUrl: string,
    public readonly realm: string | null,
    public readonly stateless: boolean,
    public readonly strict: boolean,
    public readonly extensions: any[],
  ) {}
  authenticate(identifier: string, immediate: boolean) {
    return authenticate(
      identifier,
      this.returnUrl,
      this.realm,
      immediate,
      this.stateless,
      this.extensions,
      this.strict,
    )
  }
  verifyAssertion(requestOrUrl: string) {
    return verifyAssertion(
      requestOrUrl,
      this.returnUrl,
      this.stateless,
      this.extensions,
      this.strict,
    )
  }
}

const authenticate = async (
  identifier: string,
  returnUrl: string,
  realm: string | null,
  immediate: boolean,
  stateless: boolean,
  extensions: Provider[],
  strict: boolean,
) => {
  const providers = await discover(identifier, strict)
  if (!providers || providers.length === 0) {
    throw new Error('No providers found for the given identifier')
  }

  var providerIndex = -1
  const chooseProvider = async (
    error?: Error,
    authUrl?: string,
  ): Promise<string> => {
    if (!error && authUrl) {
      var provider = providers[providerIndex]

      if (provider.claimedIdentifier) {
        var useLocalIdentifierAsKey =
          provider.version.indexOf('2.0') === -1 &&
          provider.localIdentifier &&
          provider.claimedIdentifier != provider.localIdentifier

        await saveDiscoveredInformation(
          useLocalIdentifierAsKey
            ? (provider.localIdentifier as string)
            : provider.claimedIdentifier,
          provider,
        )
        return authUrl
      } else if (provider.version.indexOf('2.0') !== -1) {
        return authUrl
      } else {
        return chooseProvider(
          new Error(
            'OpenID 1.0/1.1 provider cannot be used without a claimed identifier',
          ),
        )
      }
    }
    if (++providerIndex >= providers.length) {
      throw new Error('No usable providers found for the given identifier')
    }

    var currentProvider = providers[providerIndex]
    if (stateless) {
      return _requestAuthentication(
        currentProvider,
        null,
        returnUrl,
        realm,
        immediate,
        extensions || [],
      ).then(
        r => chooseProvider(undefined, r),
        e => chooseProvider(e),
      )
    } else {
      return associate(currentProvider, strict).then(function(answer) {
        if (!answer || answer.error) {
          return chooseProvider(error || answer.error)
        } else {
          return _requestAuthentication(
            currentProvider,
            answer.assoc_handle,
            returnUrl,
            realm,
            immediate,
            extensions || [],
          ).then(
            r => chooseProvider(undefined, r),
            e => chooseProvider(e),
          )
        }
      })
    }
  }
  return chooseProvider(undefined, '')
}

var _btwoc = function(i: string) {
  if (i.charCodeAt(0) > 127) {
    return String.fromCharCode(0) + i
  }
  return i
}

var _unbtwoc = function(i: string) {
  if (i[0] === String.fromCharCode(0)) {
    return i.substr(1)
  }

  return i
}

function _isDef(e: any) {
  var undefined
  return e !== undefined
}

var _base64encode = function(str: string) {
  return Buffer.from(str, 'binary').toString('base64')
}

var _base64decode = function(str: string) {
  return Buffer.from(str, 'base64').toString('binary')
}

var _bigIntToBase64 = function(binary: string) {
  return _base64encode(_btwoc(binary))
}

var _bigIntFromBase64 = function(str: string) {
  return _unbtwoc(_base64decode(str))
}

var _xor = function(a: string, b: string) {
  if (a.length != b.length) {
    throw new Error('Length must match for xor')
  }

  var r = ''
  for (var i = 0; i < a.length; ++i) {
    r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i))
  }

  return r
}

async function saveAssociation(
  provider: Provider,
  type: string,
  handle: string,
  secret: string,
  expiry_time_in_seconds: number,
) {
  setTimeout(function() {
    removeAssociation(handle)
  }, expiry_time_in_seconds * 1000)
  _associations[handle] = { provider: provider, type: type, secret: secret }
}

async function loadAssociation(handle: string) {
  return _associations[handle] || null
}

function removeAssociation(handle: string) {
  delete _associations[handle]
  return true
}

const saveDiscoveredInformation = function(key: string, provider: Provider) {
  _discoveries[key] = provider
}
const loadDiscoveredInformation = async function(key: string) {
  return _discoveries[key] || null
}

const _buildUrl = (endpoint: string, params: object) => {
  const theUrl = url.parse(endpoint, true)
  delete theUrl['search']
  theUrl.query = Object.assign({}, theUrl.query, params)
  return url.format(theUrl)
}

const _get = (getUrl: string, params: object = {}, redirects = 5) => {
  return axios.get(getUrl, {
    params: params,
    maxRedirects: redirects,
    headers: {
      Accept: 'application/xrds+xml,text/html,text/plain,*/*;q=0.9',
    },
  })
}

var _post = (postUrl: string, data: object, redirects = 5) => {
  return axios.post(postUrl, data, {
    maxRedirects: redirects,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
}

var _decodePostData = function(data: string) {
  var lines = data.split('\n')
  var result: any = {}
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i]
    if (line.length > 0 && line[line.length - 1] == '\r') {
      line = line.substring(0, line.length - 1)
    }
    var colon = line.indexOf(':')
    if (colon === -1) {
      continue
    }
    var key = line.substr(0, line.indexOf(':'))
    var value = line.substr(line.indexOf(':') + 1)
    result[key] = value
  }

  return result
}

var _normalizeIdentifier = function(identifier: string) {
  identifier = identifier.replace(/^\s+|\s+$/g, '')
  if (!identifier) {
    throw new Error('identifier is required')
  }
  if (identifier.indexOf('xri://') === 0) {
    identifier = identifier.substring(6)
  }

  if (/^[(=@\+\$!]/.test(identifier)) {
    return identifier
  }

  if (identifier.indexOf('http') === 0) {
    return identifier
  }
  return 'http://' + identifier
}

var _parseXrds = function(
  xrdsUrl: string,
  xrdsData: string,
): Provider[] | null {
  var services = xrds.parse(xrdsData)
  if (services == null) {
    return null
  }

  var providers: Provider[] = []
  for (var i = 0, len = services.length; i < len; ++i) {
    var service = services[i]
    var provider: Provider = {} as any

    provider.endpoint = service.uri
    if (/https?:\/\/xri./.test(xrdsUrl)) {
      provider.claimedIdentifier = service.id
    }
    if (service.type == 'http://specs.openid.net/auth/2.0/signon') {
      provider.version = 'http://specs.openid.net/auth/2.0'
      provider.localIdentifier = service.id
    } else if (service.type == 'http://specs.openid.net/auth/2.0/server') {
      provider.version = 'http://specs.openid.net/auth/2.0'
    } else if (
      service.type == 'http://openid.net/signon/1.0' ||
      service.type == 'http://openid.net/signon/1.1'
    ) {
      provider.version = service.type
      provider.localIdentifier = service.delegate
    } else {
      continue
    }
    providers.push(provider)
  }

  return providers
}

var _matchMetaTag = function(html: string) {
  var metaTagMatches = /<meta\s+.*?http-equiv="x-xrds-location"\s+(.*?)>/gi.exec(
    html,
  )
  if (!metaTagMatches || metaTagMatches.length < 2) {
    return null
  }

  var contentMatches = /content="(.*?)"/gi.exec(metaTagMatches[1])
  if (!contentMatches || contentMatches.length < 2) {
    return null
  }

  return contentMatches[1]
}

var _matchLinkTag = function(html: string, rel: string) {
  var providerLinkMatches = new RegExp(
    '<link\\s+.*?rel=["\'][^"\']*?' + rel + '[^"\']*?["\'].*?>',
    'ig',
  ).exec(html)

  if (!providerLinkMatches || providerLinkMatches.length < 1) {
    return null
  }

  var href = /href=["'](.*?)["']/gi.exec(providerLinkMatches[0])

  if (!href || href.length < 2) {
    return null
  }
  return href[1]
}

async function _parseHtml(
  htmlUrl: string,
  html: string,
  hops: number,
): Promise<Provider[] | null> {
  var metaUrl = _matchMetaTag(html)
  if (metaUrl != null) {
    return _resolveXri(metaUrl, hops + 1)
  }

  var provider = _matchLinkTag(html, 'openid2.provider')
  if (provider == null) {
    provider = _matchLinkTag(html, 'openid.server')
    if (provider == null) {
      return null
    } else {
      var localId = _matchLinkTag(html, 'openid.delegate')
      return [
        {
          version: 'http://openid.net/signon/1.1',
          endpoint: provider,
          claimedIdentifier: htmlUrl,
          localIdentifier: localId,
        },
      ]
    }
  } else {
    var localId = _matchLinkTag(html, 'openid2.local_id')
    return [
      {
        version: 'http://specs.openid.net/auth/2.0/signon',
        endpoint: provider,
        claimedIdentifier: htmlUrl,
        localIdentifier: localId,
      },
    ]
  }
}

async function _parseHostMeta(hostMeta: string): Promise<Provider[] | null> {
  var match = /^Link: <([^\n\r]+?)>;/.exec(hostMeta)
  if (match != null && match.length > 0) {
    var xriUrl = match[1]
    return _resolveXri(xriUrl)
  } else {
    return null
  }
}

async function _resolveXri(
  xriUrl: string,
  hops = 1,
): Promise<Provider[] | null> {
  if (hops >= 5) {
    return null
  }

  const { headers, data, status: statusCode } = await _get(xriUrl)
  if (statusCode != 200) {
    return null
  }

  var xrdsLocation = headers['x-xrds-location']
  if (_isDef(xrdsLocation)) {
    return _get(xrdsLocation).then(({ status, data }) => {
      if (status != 200 || data == null) {
        return null
      } else {
        return _parseXrds(xrdsLocation, data)
      }
    })
  } else if (data != null) {
    var contentType = headers['content-type']
    // text/xml is not compliant, but some hosting providers refuse header
    // changes, so text/xml is encountered
    if (
      contentType &&
      (contentType.indexOf('application/xrds+xml') === 0 ||
        contentType.indexOf('text/xml') === 0)
    ) {
      return _parseXrds(xriUrl, data)
    } else {
      return _resolveHtml(xriUrl, hops + 1, data)
    }
  }
  return null
}

async function _resolveHtml(
  identifier: string,
  hops: number = 1,
  data: string = '',
): Promise<Provider[] | null> {
  if (hops >= 5) {
    return null
  }

  if (data == null) {
    return _get(identifier).then(({ data, status }) => {
      if (status != 200 || data == null) {
        return null
      } else {
        return _parseHtml(identifier, data, hops + 1)
      }
    })
  } else {
    return _parseHtml(identifier, data, hops)
  }
}

async function _resolveHostMeta(
  identifier: string,
  strict: boolean,
  fallBackToProxy: boolean = false,
): Promise<Provider[] | null> {
  var host = url.parse(identifier)
  var hostMetaUrl
  if (fallBackToProxy && !strict) {
    hostMetaUrl =
      'https://www.google.com/accounts/o8/.well-known/host-meta?hd=' + host.host
  } else {
    hostMetaUrl = host.protocol + '//' + host.host + '/.well-known/host-meta'
  }
  if (!hostMetaUrl) {
    return null
  } else {
    return _get(hostMetaUrl).then(async ({ data, status: statusCode }) => {
      if (statusCode != 200 || data == null) {
        if (!fallBackToProxy && !strict) {
          return _resolveHostMeta(identifier, strict, true)
        } else {
          return null
        }
      } else {
        //Attempt to parse the data but if this fails it may be because
        //the response to hostMetaUrl was some other http/html resource.
        //Therefore fallback to the proxy if no providers are found.
        const providers = await _parseHostMeta(data)
        if (
          (providers == null || providers.length == 0) &&
          !fallBackToProxy &&
          !strict
        ) {
          return _resolveHostMeta(identifier, strict, true)
        } else {
          return providers
        }
      }
    })
  }
}

const discover = async (
  identifier: string,
  strict: boolean,
): Promise<Provider[]> => {
  identifier = _normalizeIdentifier(identifier)
  if (!identifier) {
    throw new Error('Invalid identifier')
  }
  if (identifier.indexOf('http') !== 0) {
    // XRDS
    identifier =
      'https://xri.net/' + identifier + '?_xrd_r=application/xrds%2Bxml'
  }

  // Try XRDS/Yadis discovery
  return _resolveXri(identifier).then(function(providers) {
    if (providers == null || providers.length == 0) {
      // Fallback to HTML discovery
      return _resolveHtml(identifier).then(function(providers) {
        if (providers == null || providers.length == 0) {
          return _resolveHostMeta(identifier, strict) as any
        } else {
          return providers
        }
      })
    } else {
      // Add claimed identifier to providers with local identifiers
      // and OpenID 1.0/1.1 providers to ensure correct resolution
      // of identities and services
      for (var i = 0, len = providers.length; i < len; ++i) {
        var provider = providers[i]
        if (
          !provider.claimedIdentifier &&
          (provider.localIdentifier || provider.version.indexOf('2.0') === -1)
        ) {
          provider.claimedIdentifier = identifier
        }
      }
      return providers
    }
  })
}

var _createDiffieHellmanKeyExchange = function(algorithm: string) {
  var defaultPrime =
    'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr'

  var dh = crypto.createDiffieHellman(defaultPrime, 'base64')

  dh.generateKeys()

  return dh
}

async function associate(
  provider: Provider,
  strict: boolean,
  algorithm: string = 'DH-SHA256',
): Promise<any> {
  var params = _generateAssociationRequestParameters(
    provider.version,
    algorithm,
  )
  let dh: crypto.DiffieHellman
  if (algorithm.indexOf('no-encryption') === -1) {
    dh = _createDiffieHellmanKeyExchange(algorithm)
    params['openid.dh_modulus'] = _bigIntToBase64(dh.getPrime().toString())
    params['openid.dh_gen'] = _bigIntToBase64(dh.getGenerator().toString())
    params['openid.dh_consumer_public'] = _bigIntToBase64(
      dh.getPublicKey().toString(),
    )
  }

  return _post(provider.endpoint, params).then(
    async ({ data, status: statusCode }) => {
      if ((statusCode != 200 && statusCode != 400) || data === null) {
        throw new Error(
          `HTTP request failed. code: ${statusCode}. ns: http://specs.openid.net/auth/2.0`,
        )
      }

      data = _decodePostData(data)

      if (data.error_code == 'unsupported-type' || !_isDef(data.ns)) {
        if (algorithm == 'DH-SHA1') {
          if (
            strict &&
            provider.endpoint.toLowerCase().indexOf('https:') !== 0
          ) {
            throw new Error(
              'Channel is insecure and no encryption method is supported by provider',
            )
          } else {
            return associate(provider, strict, 'no-encryption-256')
          }
        } else if (algorithm == 'no-encryption-256') {
          if (
            strict &&
            provider.endpoint.toLowerCase().indexOf('https:') !== 0
          ) {
            throw new Error(
              'Channel is insecure and no encryption method is supported by provider',
            )
          } else {
            /*else if(provider.version.indexOf('2.0') === -1)
        {
          // 2011-07-22: This is an OpenID 1.0/1.1 provider which means
          // HMAC-SHA1 has already been attempted with a blank session
          // type as per the OpenID 1.0/1.1 specification.
          // (See http://openid.net/specs/openid-authentication-1_1.html#mode_associate)
          // However, providers like wordpress.com don't follow the 
          // standard and reject these requests, but accept OpenID 2.0
          // style requests without a session type, so we have to give
          // those a shot as well.
          callback({ message: 'Provider is OpenID 1.0/1.1 and does not support OpenID 1.0/1.1 association.' });
        }*/
            return associate(provider, strict, 'no-encryption')
          }
        } else if (algorithm == 'DH-SHA256') {
          return associate(provider, strict, 'DH-SHA1')
        }
      }

      if (data.error) {
        throw new Error(data.error)
        // callback({ message:  }, data)
      } else {
        var secret = null

        var hashAlgorithm = algorithm.indexOf('256') !== -1 ? 'sha256' : 'sha1'

        if (algorithm.indexOf('no-encryption') !== -1) {
          secret = data.mac_key
        } else {
          var serverPublic = Buffer.from(data.dh_server_public, 'base64')
          var sharedSecret = _btwoc(dh.computeSecret(serverPublic).toString())
          var hash = crypto.createHash(hashAlgorithm)
          hash.update(Buffer.from(sharedSecret, 'binary'))
          sharedSecret = hash.digest().toString()
          var encMacKey = _base64decode(data.enc_mac_key)
          secret = _base64encode(_xor(encMacKey, sharedSecret))
        }

        if (!_isDef(data.assoc_handle)) {
          throw new Error(
            'OpenID provider does not seem to support association; you need to use stateless mode',
          )
        }

        await saveAssociation(
          provider,
          hashAlgorithm,
          data.assoc_handle,
          secret,
          data.expires_in * 1,
        )
        return data
      }
    },
  )
}

function _generateAssociationRequestParameters(
  version: string,
  algorithm: string,
) {
  var params: AssociationRequestParams = {
    'openid.mode': 'associate',
  } as any

  if (version.indexOf('2.0') !== -1) {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0'
  }

  if (algorithm == 'DH-SHA1') {
    params['openid.assoc_type'] = 'HMAC-SHA1'
    params['openid.session_type'] = 'DH-SHA1'
  } else if (algorithm == 'no-encryption-256') {
    if (version.indexOf('2.0') === -1) {
      params['openid.session_type'] = '' // OpenID 1.0/1.1 requires blank
      params['openid.assoc_type'] = 'HMAC-SHA1'
    } else {
      params['openid.session_type'] = 'no-encryption'
      params['openid.assoc_type'] = 'HMAC-SHA256'
    }
  } else if (algorithm == 'no-encryption') {
    if (version.indexOf('2.0') !== -1) {
      params['openid.session_type'] = 'no-encryption'
    }
    params['openid.assoc_type'] = 'HMAC-SHA1'
  } else {
    params['openid.assoc_type'] = 'HMAC-SHA256'
    params['openid.session_type'] = 'DH-SHA256'
  }

  return params
}

const _requestAuthentication = async (
  provider: Provider,
  assoc_handle: string | null,
  returnUrl: string,
  realm: string | null,
  immediate: boolean,
  extensions: any[],
) => {
  var params: RequsetParams = {
    'openid.mode': immediate ? 'checkid_immediate' : 'checkid_setup',
  } as any

  if (provider.version.indexOf('2.0') !== -1) {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0'
  }

  for (var i in extensions) {
    if (!hasOwnProperty(extensions, i)) {
      continue
    }

    var extension = extensions[i]
    for (var key in extension.requestParams) {
      if (!hasOwnProperty(extension.requestParams, key)) {
        continue
      }
      // @ts-ignore
      params[key] = extension.requestParams[key]
    }
  }

  if (provider.claimedIdentifier) {
    params['openid.claimed_id'] = provider.claimedIdentifier
    if (provider.localIdentifier) {
      params['openid.identity'] = provider.localIdentifier
    } else {
      params['openid.identity'] = provider.claimedIdentifier
    }
  } else if (provider.version.indexOf('2.0') !== -1) {
    params['openid.claimed_id'] = params['openid.identity'] =
      'http://specs.openid.net/auth/2.0/identifier_select'
  } else {
    throw new Error(
      'OpenID 1.0/1.1 provider cannot be used without a claimed identifier',
    )
  }

  if (assoc_handle) {
    params['openid.assoc_handle'] = assoc_handle
  }

  if (returnUrl) {
    // Value should be missing if RP does not want
    // user to be sent back
    params['openid.return_to'] = returnUrl
  }

  if (realm) {
    if (provider.version.indexOf('2.0') !== -1) {
      params['openid.realm'] = realm
    } else {
      params['openid.trust_root'] = realm
    }
  } else if (!returnUrl) {
    throw new Error('No return URL or realm specified')
  }

  return _buildUrl(provider.endpoint, params)
}

function verifyAssertion(
  requestOrUrl: string,
  originalReturnUrl: string,
  stateless: boolean,
  extensions: any[],
  strict: boolean,
) {
  extensions = extensions || {}

  const assertionUrl = url.parse(requestOrUrl, true)
  var params = assertionUrl.query

  if (!_verifyReturnUrl(assertionUrl, originalReturnUrl)) {
    throw new Error('Invalid return URL')
  }
  return _verifyAssertionData(params, stateless, extensions, strict)
}

var _verifyReturnUrl = function(
  assertionUrl: url.UrlWithParsedQuery,
  _originalReturnUrl: string,
) {
  var _receivedReturnUrl = assertionUrl.query['openid.return_to']
  if (!_isDef(_receivedReturnUrl)) {
    return false
  }

  const receivedReturnUrl = url.parse(_receivedReturnUrl as string, true)
  if (!receivedReturnUrl) {
    return false
  }
  const originalReturnUrl = url.parse(_originalReturnUrl, true)
  if (!originalReturnUrl) {
    return false
  }

  if (
    originalReturnUrl.protocol !== receivedReturnUrl.protocol || // Verify scheme against original return URL
    originalReturnUrl.host !== receivedReturnUrl.host || // Verify authority against original return URL
    originalReturnUrl.pathname !== receivedReturnUrl.pathname
  ) {
    // Verify path against current request URL
    return false
  }

  // Any query parameters that are present in the "openid.return_to" URL MUST also be present
  // with the same values in the URL of the HTTP request the RP received
  for (var param in receivedReturnUrl.query) {
    if (
      hasOwnProperty(receivedReturnUrl.query, param) &&
      receivedReturnUrl.query[param] !== assertionUrl.query[param]
    ) {
      return false
    }
  }

  return true
}

function _verifyAssertionData(
  params: any,
  stateless: boolean,
  extensions: any[],
  strict: boolean,
) {
  var assertionError = _getAssertionError(params)
  if (assertionError) {
    throw new Error(assertionError)
  }

  if (!_invalidateAssociationHandleIfRequested(params)) {
    throw new Error('Unable to invalidate association handle')
  }

  if (!_checkNonce(params)) {
    throw new Error('Invalid or replayed nonce')
  }

  return _verifyDiscoveredInformation(params, stateless, extensions, strict)
}

var _getAssertionError = function(params: AssociationRequestParams) {
  if (!_isDef(params)) {
    return 'Assertion request is malformed'
  } else if (params['openid.mode'] == 'error') {
    return params['openid.error']
  } else if (params['openid.mode'] == 'cancel') {
    return 'Authentication cancelled'
  }

  return null
}

var _invalidateAssociationHandleIfRequested = function(
  params: AssociationRequestParams,
) {
  if (
    params['is_valid'] == 'true' &&
    _isDef(params['openid.invalidate_handle'])
  ) {
    if (!removeAssociation(params['openid.invalidate_handle'])) {
      return false
    }
  }

  return true
}

var _checkNonce = function(params: AssociationRequestParams) {
  if (!_isDef(params['openid.ns'])) {
    return true // OpenID 1.1 has no nonce
  }
  if (!_isDef(params['openid.response_nonce'])) {
    return false
  }

  var nonce = params['openid.response_nonce']
  var timestampEnd = nonce.indexOf('Z')
  if (timestampEnd == -1) {
    return false
  }

  // Check for valid timestamp in nonce
  var timestamp = new Date(Date.parse(nonce.substring(0, timestampEnd + 1)))
  if (
    Object.prototype.toString.call(timestamp) !== '[object Date]' ||
    isNaN(timestamp as any)
  ) {
    return false
  }

  // Remove old nonces from our store (nonces that are more skewed than 5 minutes)
  _removeOldNonces()

  // Check if nonce is skewed by more than 5 minutes
  if (Math.abs(new Date().getTime() - timestamp.getTime()) > 300000) {
    return false
  }

  // Check if nonce is replayed
  if (_isDef(_nonces[nonce])) {
    return false
  }

  // Store the nonce
  _nonces[nonce] = timestamp
  return true
}

var _removeOldNonces = function() {
  for (var nonce in _nonces) {
    if (
      hasOwnProperty(_nonces, nonce) &&
      Math.abs(new Date().getTime() - _nonces[nonce].getTime()) > 300000
    ) {
      delete _nonces[nonce]
    }
  }
}

var _verifyDiscoveredInformation = function(
  params: RequsetParams,
  stateless: boolean,
  extensions: any[],
  strict: boolean,
) {
  var claimedIdentifier = params['openid.claimed_id'] as string
  var useLocalIdentifierAsKey = false
  if (!_isDef(claimedIdentifier)) {
    if (!_isDef(params['openid.ns'])) {
      // OpenID 1.0/1.1 response without a claimed identifier
      // We need to load discovered information using the
      // local identifier
      useLocalIdentifierAsKey = true
    } else {
      // OpenID 2.0+:
      // If there is no claimed identifier, then the
      // assertion is not about an identity
      return { authenticated: false }
    }
  }

  if (useLocalIdentifierAsKey) {
    claimedIdentifier = params['openid.identity'] as string
  }

  claimedIdentifier = _getCanonicalClaimedIdentifier(claimedIdentifier)
  return loadDiscoveredInformation(claimedIdentifier as string)
    .catch(err => {
      throw new Error(
        'An error occured when loading previously discovered information about the claimed identifier',
      )
    })
    .then(function(provider) {
      if (provider) {
        return _verifyAssertionAgainstProviders(
          [provider],
          params,
          stateless,
          extensions,
        )
      } else if (useLocalIdentifierAsKey) {
        throw new Error(
          'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.',
        )
      }

      return discover(claimedIdentifier, strict).then(function(providers) {
        if (!providers || !providers.length) {
          throw new Error(
            'No OpenID provider was discovered for the asserted claimed identifier',
          )
        }

        return _verifyAssertionAgainstProviders(
          providers,
          params,
          stateless,
          extensions,
        )
      })
    })
}

var _verifyAssertionAgainstProviders = function(
  providers: Provider[],
  params: RequsetParams,
  stateless: boolean,
  extensions: any[],
) {
  for (var i = 0; i < providers.length; ++i) {
    var provider = providers[i]
    if (
      !!params['openid.ns'] &&
      (!provider.version || provider.version.indexOf(params['openid.ns']) !== 0)
    ) {
      continue
    }

    if (!!provider.version && provider.version.indexOf('2.0') !== -1) {
      var endpoint = params['openid.op_endpoint']
      if (provider.endpoint != endpoint) {
        continue
      }
      if (provider.claimedIdentifier) {
        var claimedIdentifier = _getCanonicalClaimedIdentifier(
          params['openid.claimed_id'] as string,
        )
        if (provider.claimedIdentifier != claimedIdentifier) {
          throw new Error(
            'Claimed identifier in assertion response does not match discovered claimed identifier',
          )
        }
      }
    }

    if (
      !!provider.localIdentifier &&
      provider.localIdentifier != params['openid.identity']
    ) {
      throw new Error(
        'Identity in assertion response does not match discovered local identifier',
      )
    }

    return _checkSignature(params, provider, stateless).then(result => {
      if (extensions && result.authenticated) {
        for (var ext in extensions) {
          if (!hasOwnProperty(extensions, ext)) {
            continue
          }
          var instance = extensions[ext]
          instance.fillResult(params, result)
        }
      }

      return result
    })
  }

  throw new Error(
    'No valid providers were discovered for the asserted claimed identifier',
  )
}

const _checkSignature = function(
  params: RequsetParams,
  provider: Provider,
  stateless: boolean,
) {
  if (!_isDef(params['openid.signed']) || !_isDef(params['openid.sig'])) {
    throw new Error('No signature in response')
  }

  if (stateless) {
    return _checkSignatureUsingProvider(params, provider)
  } else {
    return _checkSignatureUsingAssociation(params)
  }
}

import {
  Params,
  Provider,
  Association,
  AssociationRequestParams,
  AllParams,
  RequsetParams,
} from './type'

function _checkSignatureUsingAssociation(params: Params) {
  if (!_isDef(params['openid.assoc_handle'])) {
    throw new Error(
      'No association handle in provider response. Find out whether the provider supports associations and/or use stateless mode.',
    )
  }
  return loadAssociation(params['openid.assoc_handle'] as string).then(function(
    association,
  ) {
    if (!association) {
      throw new Error('Invalid association handle')
    }
    if (
      association.provider.version.indexOf('2.0') !== -1 &&
      association.provider.endpoint !== params['openid.op_endpoint']
    ) {
      throw new Error('Association handle does not match provided endpoint')
    }

    var message = ''
    var signedParams = (params['openid.signed'] as string).split(',')
    for (var i = 0; i < signedParams.length; i++) {
      var param = signedParams[i]
      var value = params[('openid.' + param) as keyof Params]
      if (!_isDef(value)) {
        throw new Error(
          'At least one parameter referred in signature is not present in response',
        )
      }
      message += param + ':' + value + '\n'
    }

    var hmac = crypto.createHmac(
      association.type,
      Buffer.from(association.secret, 'base64'),
    )
    hmac.update(message, 'utf8')
    var ourSignature = hmac.digest('base64')

    if (ourSignature == params['openid.sig']) {
      return {
        authenticated: true,
        claimedIdentifier:
          association.provider.version.indexOf('2.0') !== -1
            ? params['openid.claimed_id']
            : association.provider.claimedIdentifier,
      }
    } else {
      throw new Error('Invalid signature')
    }
  })
}

function _checkSignatureUsingProvider(
  params: RequsetParams,
  provider: Provider,
) {
  var requestParams = {
    'openid.mode': 'check_authentication',
  }
  for (var key in params) {
    if (hasOwnProperty(params, key) && key != 'openid.mode') {
      // @ts-ignore
      requestParams[key] = params[key]
    }
  }

  return _post(
    _isDef(params['openid.ns'])
      ? params['openid.op_endpoint'] || provider.endpoint
      : provider.endpoint,
    requestParams,
  ).then(function({ data, status: statusCode }) {
    if (statusCode != 200 || data == null) {
      throw new Error('Invalid assertion response from provider')
    } else {
      data = _decodePostData(data)
      if (data['is_valid'] == 'true') {
        return {
          authenticated: true,
          claimedIdentifier:
            provider.version.indexOf('2.0') !== -1
              ? params['openid.claimed_id']
              : params['openid.identity'],
        }
      } else {
        throw new Error('Invalid signature')
      }
    }
  })
}

var _getCanonicalClaimedIdentifier = function(claimedIdentifier: string) {
  if (!claimedIdentifier) {
    return claimedIdentifier
  }

  var index = claimedIdentifier.indexOf('#')
  if (index !== -1) {
    return claimedIdentifier.substring(0, index)
  }

  return claimedIdentifier
}
