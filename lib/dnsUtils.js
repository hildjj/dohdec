'use strict'

const net = require('net')
const util = require('util')
const packet = require('dns-packet')
const punycode = require('punycode/') // "/" at end to avoid deprecated internal version

const CIRCULAR_MARK = Symbol('CIRCULAR_REFERENCE_MARK')

// extracted from node source
function stylizeWithColor (str, styleType) {
  const style = util.inspect.styles[styleType]
  if (style !== undefined) {
    const color = util.inspect.colors[style]
    return `\u001b[${color[0]}m${str}\u001b[${color[1]}m`
  }
  return str
}

function styleStream (stream, str, styleType) {
  stream.write(stream.isTTY ? stylizeWithColor(str, styleType) : str)
}

function printableString (stream, buf) {
  // Intent: each byte that is "printable" takes up one grapheme, and everything
  // else is replaced with '.'

  for (const x of buf) {
    if ((x < 0x20) ||
        ((x > 0x7e) && (x < 0xa1)) ||
        (x === 0xad)) {
      stream.write('.')
    } else {
      styleStream(stream, String.fromCharCode(x), 'string')
    }
  }
  return buf.length
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
    if (opts.ecs != null || net.isIP(opts.subnet) !== 0) {
      // https://tools.ietf.org/html/rfc7871#section-11.1
      const prefix = opts.subnet && net.isIPv4(opts.subnet) ? 24 : 56
      dns.additionals[0].options = [{
        code: 'CLIENT_SUBNET',
        ip: opts.subnet || '0.0.0.0',
        sourcePrefixLength: opts.ecs != null ? opts.ecs : prefix
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
    if (buf.length > 0) {
      let offset = 0
      for (const byte of buf.slice(0, buf.length)) {
        // 00000000  7b 0a 20 20 22 6e 61 6d  65 22 3a 20 22 64 6f 68  |{.  "name": "doh|
        if ((offset % 16) === 0) {
          if (offset !== 0) {
            stream.write('  |')
            printableString(stream, buf.slice(offset - 16, offset))
            stream.write('|\n')
          }
          styleStream(stream, offset.toString(16).padStart(8, '0'), 'undefined')
        }
        if ((offset % 8) === 0) {
          stream.write(' ')
        }
        stream.write(' ')
        stream.write(byte.toString(16).padStart(2, '0'))
        offset++
      }
      let left = offset % 16
      if (left !== 0) {
        let undone = 3 * (16 - left)
        if (left <= 8) {
          undone++
        }
        stream.write(' '.padStart(undone, ' '))
      } else {
        left = 16
      }
      const start = offset > 16 ? offset - left : 0
      stream.write('  |')
      printableString(stream, buf.slice(start, offset))
      stream.write('|\n')
    }
    styleStream(stream, buf.length.toString(16).padStart(8, '0'), 'undefined')
    stream.write('\n')
  }

  static buffersToB64 (o) {
    if (o && (typeof o === 'object')) {
      if (o[CIRCULAR_MARK]) {
        return '[Circular reference]'
      }
      o[CIRCULAR_MARK] = true
      let ret = null
      if (Buffer.isBuffer(o)) {
        ret = o.toString('base64')
      } else if (Array.isArray(o)) {
        ret = o.map(v => this.buffersToB64(v))
      } else {
        ret = Object.entries(o).reduce((prev, [k, v]) => {
          prev[k] = this.buffersToB64(v)
          return prev
        }, {})
      }
      delete o[CIRCULAR_MARK]
      delete ret[CIRCULAR_MARK]
      return ret
    }
    return o
  }
}

module.exports = DNSutils
