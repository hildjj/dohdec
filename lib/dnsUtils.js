'use strict'

const packet = require('dns-packet')
const punycode = require('punycode/') // "/" at end to avoid deprecated internal version

class DNSutils {
  /**
   * Encode a DNS query packet to a buffer.
   *
   * @param {Object} opts - Options for the query
   * @param {Number} [opts.id=0] - ID for the query.  SHOULD be 0 for DOH.
   * @param {String} [opts.name] - The name to look up
   * @param {String} [opts.rrtype="A"] - The record type to look up
   * @param {Boolean} [opts.dnssec=false] - Request DNSSec information?
   * @returns {Buffer} The encoded packet
   */
  static makePacket (opts) {
    const dns = {
      type: 'query',
      id: opts.id || 0,
      flags: packet.RECURSION_DESIRED,
      questions: [{
        type: opts.rrtype || 'A',
        class: 'IN',
        name: opts.name
      }],
      additionals: [{
        name: '.',
        type: 'OPT',
        udpPayloadSize: 4096,
        flags: 0
      }]
    }
    if (opts.dnssec) {
      dns.flags |= packet.AUTHENTIC_DATA
      dns.additionals[0].flags |= packet.DNSSEC_OK
    }
    return packet.encode(dns)
  }
  static normalizeArgs (name, opts, defaults) {
    if (typeof name === 'object') {
      opts = name
      name = undefined
    } else if (typeof opts === 'string') {
      opts = {
        name,
        rrtype: opts
      }
      name = undefined
    }
    opts = Object.assign({}, defaults, opts)
    opts.name = punycode.toASCII(opts.name || name)
    opts.rrtype = opts.rrtype.toUpperCase()
    return opts
  }
}

module.exports = DNSutils
