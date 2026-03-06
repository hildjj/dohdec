const IPV6_SERVER = 'http://ipv6.google.com/';

/**
 * Is the Internet reachable with IPv6?
 *
 * @returns {boolean} Reachable?
 */
export async function hasIPv6() {
  try {
    const res = await fetch(IPV6_SERVER, {
      method: 'head',
    });
    return res.ok;
  } catch (_ignored) {
    return false;
  }
}
