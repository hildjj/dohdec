'use strict'

const packet = require('dns-packet')
const punycode = require('punycode/') // "/" at end to avoid deprecated internal version

function printableString (buf) {
  // Intent: each byte that is "printable" takes up one grapheme, and everything
  // else is replaced with '.'

  return buf.map(x => {
    if ((x < 0x20) ||
        ((x > 0x7e) && (x < 0xa1)) ||
        (x === 0xad)) {
      return 0x2e // "."
    }
    return x
  }).toString('binary')
}

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
    if (opts.ecs != null) {
      dns.additionals.options = [{
        code: 'CLIENT_SUBNET',
        sourcePrefixLength: opts.ecs
      }]
    }
    if (opts.verbose) {
      console.error('SEND', dns)
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
    opts.rrtype = (opts.rrtype || 'A').toUpperCase()
    return opts
  }

  /**
   * See [RFC 4648]{@link https://tools.ietf.org/html/rfc4648#section-5}.
   *
   * @param {Buffer} buf - Buffer to encode
   * @returns {String} The base64url string
   */
  static base64urlEncode (buf) {
    const s = buf.toString('base64')
    return s.replace(/[=+/]/g, c => {
      switch (c) {
        case '=': return ''
        case '+': return '-'
        case '/': return '_'
      }
    })
  }

  static hexDump (buf, stream = process.stdout) {
    let offset = 0
    for (const byte of buf.slice(0, buf.length)) {
      // 00000000  7b 0a 20 20 22 6e 61 6d  65 22 3a 20 22 64 6f 68  |{.  "name": "doh|
      if ((offset % 16) === 0) {
        if (offset !== 0) {
          stream.write(`  |${printableString(buf.slice(offset - 16, offset))}|`)
          stream.write('\n')
        }
        stream.write(offset.toString(16).padStart(8, '0'))
      }
      if ((offset % 8) === 0) {
        stream.write(' ')
      }
      stream.write(' ')
      stream.write(byte.toString(16).padStart(2, '0'))
      offset++
    }
    const left = offset % 16
    if (left !== 0) {
      let undone = 3 * (16 - left)
      if (left < 8) {
        undone++
      }
      stream.write(' '.padStart(undone, ' '))
    }
    stream.write(`  |${printableString(buf.slice(offset - 16, offset))}|`)

    stream.write('\n')
  }

  static buffersToB64 (o) {
    if (o && (typeof o === 'object')) {
      if (Buffer.isBuffer(o)) {
        return o.toString('base64')
      }
      if (Array.isArray(o)) {
        return o.map(v => this.buffersToB64(v))
      }
      // strip Symbols
      return Object.entries(o).reduce((prev, [k, v]) => {
        prev[k] = this.buffersToB64(v)
        return prev
      }, {})
    }
    return o
  }
}

module.exports = DNSutils
