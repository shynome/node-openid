import { _getExtensionAlias } from './utils'

/*
 * Simple Registration Extension
 * http://openid.net/specs/openid-simple-registration-extension-1_1-01.html
 */

var sreg_keys = [
  'nickname',
  'email',
  'fullname',
  'dob',
  'gender',
  'postcode',
  'country',
  'language',
  'timezone',
]

export class SimpleRegistration {
  requestParams: { [k: string]: string }
  constructor(options: { [k: string]: any; policy_url?: string }) {
    this.requestParams = {
      'openid.ns.sreg': 'http://openid.net/extensions/sreg/1.1',
    }
    if (options.policy_url)
      this.requestParams['openid.sreg.policy_url'] = options.policy_url
    var required = []
    var optional = []
    for (var i = 0; i < sreg_keys.length; i++) {
      var key = sreg_keys[i]
      if (options[key]) {
        if (options[key] == 'required') {
          required.push(key)
        } else {
          optional.push(key)
        }
      }
      if (required.length) {
        this.requestParams['openid.sreg.required'] = required.join(',')
      }
      if (optional.length) {
        this.requestParams['openid.sreg.optional'] = optional.join(',')
      }
    }
  }
  fillResult(params: any, result: any) {
    var extension =
      _getExtensionAlias(params, 'http://openid.net/extensions/sreg/1.1') ||
      'sreg'
    for (var i = 0; i < sreg_keys.length; i++) {
      var key = sreg_keys[i]
      if (params['openid.' + extension + '.' + key]) {
        result[key] = params['openid.' + extension + '.' + key]
      }
    }
  }
}
