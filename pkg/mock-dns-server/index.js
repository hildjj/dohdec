import * as packet from 'dns-packet';
import * as rcodes from 'dns-packet/rcodes.js';
import {MockTLSServer} from 'mock-tls-server';
import {NoFilter} from 'nofilter';

export {connect, plainConnect} from 'mock-tls-server';

const PAD_SIZE = 468; // See RFC 8467
const AA = 1 << 10;
const CONNECTION = Symbol('connection');

const DNS = {
  'ietf.org': {
    A: '4.31.198.44',
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

class Connection {
  constructor(sock) {
    this.sock = sock;
    this.size = -1;
    this.nof = new NoFilter();
    this.sock.on('data', this._data.bind(this));
  }

  _data(chunk) {
    this.nof.write(chunk);

    while (this.nof.length > 0) {
      if (this.size === -1) {
        if (this.nof.length < 2) {
          return;
        }
        this.size = this.nof.readUInt16BE();
      }
      if (this.nof.length < this.size) {
        return;
      }
      const buf = this.nof.read(this.size);
      this.size = -1;
      const pkt = packet.decode(buf);

      const [{name, type}] = pkt.questions;
      const domain = DNS[name];
      const id = /badid/i.test(name) ? (pkt.id + 1) % 65536 : pkt.id;

      if (domain) {
        const data = domain[type];
        if (data) {
          /** @type {packet.Packet} */
          const rp = {
            id,
            type: 'response',
            flags: AA,
            questions: pkt.questions,
            answers: [
              {
                name,
                type,
                class: 'IN',
                ttl: 1000,
                data,
              },
            ],
            additionals: [{
              name: '.',
              type: 'OPT',
              udpPayloadSize: 4096,
              flags: 0,
              options: [],
            }],
          };
          // Only pad if client said they support EDNS0
          if (pkt.additionals.find(a => a.type === 'OPT')) {
            const unpadded = packet.encodingLength(rp);
            rp.additionals[0].options.push({
              code: 'PADDING',
              length: (Math.ceil(unpadded / PAD_SIZE) * PAD_SIZE) -
                unpadded - 4,
            });
          }

          const reply = packet.streamEncode(rp);
          if (/chunky/.test(name)) {
            // Write in chunks, for testing reassembly
            // Avoid Nagle by going full-sync
            this.sock.write(reply.slice(0, 1), () => {
              this.sock.write(reply.slice(1, 2), () => {
                this.sock.write(reply.slice(2, 7), () => {
                  this.sock.write(reply.slice(7));
                });
              });
            });
          } else {
            this.sock.write(reply);
          }
          return;
        }
      }

      // Not found
      this.sock.write(packet.streamEncode({
        id,
        type: 'response',
        flags: AA | rcodes.toRcode('NXDOMAIN'),
        questions: pkt.questions,
      }));
    }
  }
}

/**
 * Create a mock DNS server.
 *
 * @param {object} [options] Any options for mock-tls-server.  Port defaults
 *   to 853.
 * @returns {MockTLSServer} The created server, already listening.
 */
export function createServer(options = {}) {
  const {port = 853, ...opts} = options;
  const server = new MockTLSServer(opts);
  server.listen(port, cli => {
    cli[CONNECTION] = new Connection(cli);
  });
  return server;
}
