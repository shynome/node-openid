/*
 * User Interface Extension
 * http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html
 */
class UserInterface {
  requestParams: { [k: string]: string }
  constructor(options: { mode: string; [k: string]: any } = { mode: 'popup' }) {
    this.requestParams = {
      'openid.ns.ui': 'http://specs.openid.net/extensions/ui/1.0',
    }
    for (var k in options) {
      this.requestParams['openid.ui.' + k] = options[k]
    }
  }
  fillResult(params: any, result: any) {}
}
