import * as packet from 'dns-packet'
import * as rcodes from 'dns-packet/rcodes.js'
import {MockServerInstance, MockTLSserver} from './utils.js'
import {DNSoverTLS} from '../lib/dot.js'

const PAD_SIZE = 468 // See RFC 8467
const AA = 1 << 10

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
  '44.198.31.4.in-addr.arpa': {
    PTR: 'mail.ietf.org',
  },
  'c.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.0.1.0.0.3.0.0.9.1.1.0.0.2.ip6.arpa': {
    PTR: 'mail.ietf.org',
  },
}

class MockDNSserverInstance extends MockServerInstance {
  constructor(chain, opts = {}) {
    const {badId, ...superOpts} = opts
    super(chain, superOpts)
    this.badId = badId
  }

  _end() {
    setTimeout(() => {
      this.end()
    }, 20)
  }

  _data(chunk) {
    // Stupidest thing that lets me test.  No error handling.  Queries
    // have to come in as single chunks.
    const pkt = packet.streamDecode(chunk)
    const [{name, type}] = pkt.questions
    const domain = DNS[name]
    if (domain) {
      const data = domain[type]
      if (data) {
        const rp = {
          id: (this.badId == null) ? pkt.id : this.badId,
          type: 'response',
          flags: AA,
          questions: pkt.questions,
          answers: [
            {
              name,
              type,
              cliass: 'IN',
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
        }
        // Only pad if client said they support EDNS0
        if (pkt.additionals.find(a => a.type === 'OPT')) {
          const unpadded = packet.encodingLength(rp)
          rp.additionals[0].options.push({
            code: 'PADDING',
            length: (Math.ceil(unpadded / PAD_SIZE) * PAD_SIZE) - unpadded - 4,
          })
        }

        const reply = packet.streamEncode(rp)
        if (/chunky/.test(name)) {
          // Write in chunks, for testing reassembly
          this.write(reply.slice(0, 1))
          this.write(reply.slice(1, 2))
          this.write(reply.slice(2, 7))
          this.write(reply.slice(7))
        } else {
          this.write(reply)
        }
        return
      }
    }

    // Not found
    this.write(packet.streamEncode({
      id: (this.badId == null) ? pkt.id : this.badId,
      type: 'response',
      flags: AA | rcodes.toRcode('NXDOMAIN'),
      questions: pkt.questions,
    }))
  }
}

export class MockDNSserver extends MockTLSserver {
  constructor(...names) {
    super(MockDNSserverInstance, ...names)
    this.names = names
  }

  dnsOverTLS(cliOpts, duplexOpts) {
    const m = this.instance(duplexOpts)
    return new DNSoverTLS({
      socket: m.rawClientSocket,
      ca: m.chain.ca_pem,
      host: this.names[0],
      ...cliOpts,
    })
  }
}
