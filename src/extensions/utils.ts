export function _getExtensionAlias(
  params: { [k: string]: string },
  ns: string,
) {
  for (var k in params) {
    if (params[k as any] == ns) {
      return k.replace('openid.ns.', '')
    }
  }
}
