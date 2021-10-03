import * as packet from 'dns-packet'
import * as rcodes from 'dns-packet/rcodes.js'
import {MockServerInstance, MockTLSserver} from './utils.js'
import {DNSoverTLS} from '../lib/dot.js'

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
        const reply = packet.streamEncode({
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
        })
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
