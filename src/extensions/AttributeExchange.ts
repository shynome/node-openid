import { _getExtensionAlias } from './utils'
import { hasOwnProperty } from '../utils'

var AX_MAX_VALUES_COUNT = 1000

/*
 * Attribute Exchange Extension
 * http://openid.net/specs/openid-attribute-exchange-1_0.html
 * Also see:
 *  - http://www.axschema.org/types/
 *  - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
 */

var attributeMapping: { [k: string]: string } = {
  'http://axschema.org/contact/country/home': 'country',
  'http://axschema.org/contact/email': 'email',
  'http://axschema.org/namePerson/first': 'firstname',
  'http://axschema.org/pref/language': 'language',
  'http://axschema.org/namePerson/last': 'lastname',
  // The following are not in the Google document:
  'http://axschema.org/namePerson/friendly': 'nickname',
  'http://axschema.org/namePerson': 'fullname',
}

export class AttributeExchange {
  requestParams: { [k: string]: string }
  constructor(options: { [k: string]: any }) {
    this.requestParams = {
      'openid.ns.ax': 'http://openid.net/srv/ax/1.0',
      'openid.ax.mode': 'fetch_request',
    }
    var required = []
    var optional = []
    for (var ns in options) {
      if (!hasOwnProperty(options, ns)) {
        continue
      }
      if (options[ns] == 'required') {
        required.push(ns)
      } else {
        optional.push(ns)
      }
    }
    var self = this
    required = required.map((ns, i) => {
      var attr = attributeMapping[ns] || 'req' + i
      // @ts-ignore
      this.requestParams['openid.ax.type.' + attr] = ns
      return attr
    })
    optional = optional.map((ns, i) => {
      var attr = attributeMapping[ns] || 'opt' + i
      // @ts-ignore
      this.requestParams['openid.ax.type.' + attr] = ns
      return attr
    })
    if (required.length) {
      this.requestParams['openid.ax.required'] = required.join(',')
    }
    if (optional.length) {
      this.requestParams['openid.ax.if_available'] = optional.join(',')
    }
  }
  fillResult(params: any, result: any) {
    var extension =
      _getExtensionAlias(params, 'http://openid.net/srv/ax/1.0') || 'ax'
    var regex = new RegExp(
      '^openid\\.' +
        extension +
        '\\.(value|type|count)\\.(\\w+)(\\.(\\d+)){0,1}$',
    )
    var aliases: { [k: string]: string } = {}
    var counters: { [k: string]: number } = {}
    var values: { [k: string]: any } = {}
    for (var k in params) {
      if (!hasOwnProperty(params, k)) {
        continue
      }
      var matches = k.match(regex)
      if (!matches) {
        continue
      }
      if (matches[1] == 'type') {
        aliases[params[k]] = matches[2]
      } else if (matches[1] == 'count') {
        //counter sanitization
        var count = parseInt(params[k], 10)

        // values number limitation (potential attack by overflow ?)
        counters[matches[2]] =
          count < AX_MAX_VALUES_COUNT ? count : AX_MAX_VALUES_COUNT
      } else {
        if (matches[3]) {
          //matches multi-value, aka "count" aliases

          //counter sanitization
          var count = parseInt(matches[4], 10)

          // "in bounds" verification
          if (
            count > 0 &&
            count <= (counters[matches[2]] || AX_MAX_VALUES_COUNT)
          ) {
            if (!values[matches[2]]) {
              values[matches[2]] = []
            }
            values[matches[2]][count - 1] = params[k]
          }
        } else {
          //matches single-value aliases
          values[matches[2]] = params[k]
        }
      }
    }
    for (var ns in aliases) {
      if (aliases[ns] in values) {
        result[aliases[ns]] = values[aliases[ns]]
        result[ns] = values[aliases[ns]]
      }
    }
  }
}

export class OAuthHybrid {
  requestParams: { [k: string]: string }
  constructor(options: { consumerKey: string; scope: string }) {
    this.requestParams = {
      'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0',
      'openid.oauth.consumer': options['consumerKey'],
      'openid.oauth.scope': options['scope'],
    }
  }
  fillResult(params: any, result: any) {
    var extension =
        _getExtensionAlias(
          params,
          'http://specs.openid.net/extensions/oauth/1.0',
        ) || 'oauth',
      token_attr = 'openid.' + extension + '.request_token'

    if (params[token_attr] !== undefined) {
      result['request_token'] = params[token_attr]
    }
  }
}
