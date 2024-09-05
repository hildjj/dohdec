/**
 * @type {import('mock-dns-server').Zones}
 */
export const DNS = {
  'ietf.org': {
    A: ['104.16.44.99', '104.16.45.99'],
    AAAA: '2001:1900:3001:11::2c',
  },
  '_xmpp-server._tcp.jabber.org': {
    SRV: {
      priority: 30,
      weight: 30,
      port: 5269,
      target: 'hermes2.jabber.org',
    },
  },
  'chunky.example': {
    A: '192.168.1.1',
  },
  'badid.example': {
    A: '192.168.1.2',
  },
  '44.198.31.4.in-addr.arpa': {
    PTR: 'mail.ietf.org',
  },
  'c.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.0.1.0.0.3.0.0.9.1.1.0.0.2.ip6.arpa': {
    PTR: 'mail.ietf.org',
  },
};
