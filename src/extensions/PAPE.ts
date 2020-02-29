import { _getExtensionAlias } from './utils'
import { hasOwnProperty } from '../utils'

/*
 * Provider Authentication Policy Extension (PAPE)
 * http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
 *
 * Note that this extension does not validate that the provider is obeying the
 * authentication request, it only allows the request to be made.
 *
 * TODO: verify requested 'max_auth_age' against response 'auth_time'
 * TODO: verify requested 'auth_level.ns.<cust>' (etc) against response 'auth_level.ns.<cust>'
 * TODO: verify requested 'preferred_auth_policies' against response 'auth_policies'
 *
 */

/* Just the keys that aren't open to customisation */
var pape_request_keys = [
  'max_auth_age',
  'preferred_auth_policies',
  'preferred_auth_level_types',
]
var pape_response_keys = ['auth_policies', 'auth_time']

/* Some short-hand mappings for auth_policies */

var papePolicyNameMap: { [k: string]: string } = {
  'phishing-resistant':
    'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant',
  'multi-factor':
    'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
  'multi-factor-physical':
    'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical',
  none: 'http://schemas.openid.net/pape/policies/2007/06/none',
}

export class PAPE {
  requestParams: { [k: string]: string }
  constructor(options: { [k: string]: string }) {
    this.requestParams = {
      'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0',
    }
    for (var k in options) {
      if (k === 'preferred_auth_policies') {
        this.requestParams['openid.pape.' + k] = _getLongPolicyName(options[k])
      } else {
        this.requestParams['openid.pape.' + k] = options[k]
      }
    }
  }
  fillResult(params: any, result: any) {
    var extension =
      _getExtensionAlias(
        params,
        'http://specs.openid.net/extensions/pape/1.0',
      ) || 'pape'
    var paramString = 'openid.' + extension + '.'
    var thisParam
    for (var p in params) {
      if (hasOwnProperty(params, p)) {
        if (p.substr(0, paramString.length) === paramString) {
          thisParam = p.substr(paramString.length)
          if (thisParam === 'auth_policies') {
            result[thisParam] = _getShortPolicyName(params[p])
          } else {
            result[thisParam] = params[p]
          }
        }
      }
    }
  }
}

/* you can express multiple pape 'preferred_auth_policies', so replace each
 * with the full policy URI as per papePolicyNameMapping.
 */
var _getLongPolicyName = function(policyNames: string) {
  var policies = policyNames.split(' ')
  for (var i = 0; i < policies.length; i++) {
    if (policies[i] in papePolicyNameMap) {
      policies[i] = papePolicyNameMap[policies[i]]
    }
  }
  return policies.join(' ')
}

var _getShortPolicyName = function(policyNames: string) {
  var policies = policyNames.split(' ')
  let shortName: string
  for (var i = 0; i < policies.length; i++) {
    for (shortName in papePolicyNameMap) {
      if (papePolicyNameMap[shortName] === policies[i]) {
        policies[i] = shortName
      }
    }
  }
  return policies.join(' ')
}
