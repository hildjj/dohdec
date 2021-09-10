'use strict'

const net = require('net')
const util = require('util')
const packet = require('dns-packet')
const {Writable} = require('stream')
const url = require('url')
const EventEmitter = require('events')
const {Buffer} = require('buffer')

// Extracted from node source
function stylizeWithColor(str, styleType) {
  const style = util.inspect.styles[styleType]
  if (style !== undefined) {
    const color = util.inspect.colors[style]
    return `\u001b[${color[0]}m${str}\u001b[${color[1]}m`
  }
  return str
}

function styleStream(stream, str, styleType) {
  stream.write(stream.isTTY ? stylizeWithColor(str, styleType) : str)
}

function printableString(stream, buf) {
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

class DNSutils extends EventEmitter {
  /**
   * Creates an instance of DNSutils.
   *
   * @param {object} [opts={}] Options.
   * @param {boolean} [opts.verbose=false] Turn on verbose output?
   * @param {Writable} [opts.verboseStream=process.stderr] Where to write
   *   verbose output.
   */
  constructor(opts = {}) {
    super()
    this._verbose = Boolean(opts.verbose)
    this.verboseStream = opts.verboseStream || process.stderr
  }

  /**
   * Output verbose logging information, if this.verbose is true.
   *
   * @param {any[]} args Same as onsole.log parameters.
   */
  verbose(...args) {
    if (this._verbose) {
      this.verboseStream.write(util.formatWithOptions({
        // Really, process.stderr is a tty.WriteStream, but this will work
        // fine in practice since isTTY will be undefined on other streams.
        // @ts-ignore TS2339
        colors: this.verboseStream.isTTY,
        depth: Infinity,
        sorted: true,
      }, ...args))
      this.verboseStream.write('\n')
    }
  }

  /**
   * Dump a nice hex representation of the given buffer to verboseStream,
   * if verbose is true.
   *
   * @param {Buffer} buf The buffer to dump.
   */
  hexDump(buf) {
    if (!this._verbose) {
      return
    }
    if (buf.length > 0) {
      let offset = 0
      for (const byte of buf.slice(0, buf.length)) {
        // eslint-disable-next-line multiline-comment-style, indent
/*
00000000  7b 0a 20 20 22 6e 61 6d  65 22 3a 20 22 64 6f 68  |{.  "name": "doh|
*/
        if ((offset % 16) === 0) {
          if (offset !== 0) {
            this.verboseStream.write('  |')
            printableString(this.verboseStream, buf.slice(offset - 16, offset))
            this.verboseStream.write('|\n')
          }
          styleStream(this.verboseStream, offset.toString(16).padStart(8, '0'), 'undefined')
        }
        if ((offset % 8) === 0) {
          this.verboseStream.write(' ')
        }
        this.verboseStream.write(' ')
        this.verboseStream.write(byte.toString(16).padStart(2, '0'))
        offset++
      }
      let left = offset % 16
      if (left === 0) {
        left = 16
      } else {
        let undone = 3 * (16 - left)
        if (left <= 8) {
          undone++
        }
        this.verboseStream.write(' '.padStart(undone, ' '))
      }

      const start = offset > 16 ? offset - left : 0
      this.verboseStream.write('  |')
      printableString(this.verboseStream, buf.slice(start, offset))
      this.verboseStream.write('|\n')
    }
    styleStream(this.verboseStream, buf.length.toString(16).padStart(8, '0'), 'undefined')
    this.verboseStream.write('\n')
  }

  /**
   * Encode a DNS query packet to a buffer.
   *
   * @param {object} opts Options for the query.
   * @param {number} [opts.id=0] ID for the query.  SHOULD be 0 for DOH.
   * @param {string} [opts.name] The name to look up.
   * @param {packet.RecordType} [opts.rrtype="A"] The record type to look up.
   * @param {boolean} [opts.dnssec=false] Request DNSSec information?
   * @param {string} [opts.subnet] Subnet to use for ECS.
   * @param {number} [opts.ecs] Number of ECS bits.  Defaults to 24 or 56
   *   (IPv4/IPv6).
   * @returns {Buffer} The encoded packet.
   */
  static makePacket(opts) {
    /** @type {packet.Packet} */
    const dns = {
      type: 'query',
      id: opts.id || 0,
      flags: packet.RECURSION_DESIRED,
      questions: [{
        type: opts.rrtype || 'A',
        class: 'IN',
        name: opts.name,
      }],
      additionals: [{
        name: '.',
        type: 'OPT',
        udpPayloadSize: 4096,
        flags: 0,
      }],
    }
    if (opts.dnssec) {
      dns.flags |= packet.AUTHENTIC_DATA
      // @ts-ignore TS2339: types not up to date
      dns.additionals[0].flags |= packet.DNSSEC_OK
    }
    if (opts.ecs != null || net.isIP(opts.subnet) !== 0) {
      // https://tools.ietf.org/html/rfc7871#section-11.1
      const prefix = (opts.subnet && net.isIPv4(opts.subnet)) ? 24 : 56
      dns.additionals[0].options = [{
        code: 'CLIENT_SUBNET',
        ip: opts.subnet || '0.0.0.0',
        sourcePrefixLength: (opts.ecs == null) ? prefix : opts.ecs,
      }]
    }
    return packet.encode(dns)
  }

  /**
   * @typedef {object} LookupOptions
   * @property {string} [name] Name to look up.
   * @property {packet.RecordType} [rrtype] The Resource Record type to retrive.
   * @property {number} [id] The 2-byte unsigned integer for the request.
   *   For DOH, should be 0 or undefined.
   * @property {boolean} [json] Force JSON lookups for DOH.  Ignored for DOT.
   */
  /**
   * Normalize parameters into the lookup functions.
   *
   * @param {string|LookupOptions} [name] If string, lookup this name,
   *   otherwise it is options.
   * @param {string|LookupOptions} [opts] If string, rrtype.  Otherwise
   *   options.
   * @param {object} [defaults] Defaults options.
   * @returns {LookupOptions} Normalized options, including punycode∑d
   *   options.name and upper-case options.rrtype.
   */
  static normalizeArgs(name, opts, defaults) {
    let nopts = null
    if (typeof name === 'object') {
      nopts = name
      name = undefined
    } else if (typeof opts === 'string') {
      nopts = {
        name,
        rrtype: opts,
      }
      name = undefined
    } else {
      nopts = opts || {}
      nopts.name = name || nopts.name
    }
    return {
      ...defaults,
      ...nopts,
      name: url.domainToASCII(nopts.name),
      rrtype: (nopts.rrtype || 'A').toUpperCase(),
    }
  }

  /**
   * See [RFC 4648]{@link https://tools.ietf.org/html/rfc4648#section-5}.
   *
   * @param {Buffer} buf Buffer to encode.
   * @returns {string} The base64url string.
   */
  static base64urlEncode(buf) {
    const s = buf.toString('base64')
    return s.replace(/[=+/]/g, c => ({
      '=': '',
      '+': '-',
      '/': '_',
    })[c])
  }

  /**
   * Recursively traverse an object, turning all of its properties that have
   * Buffer values into base64 representations of the buffer.
   *
   * @param {any} o The object to traverse.
   * @param {WeakSet<object>} [circular] WeakMap to prevent circular
   *   dependencies.
   * @returns {any} The converted object.
   */
  static buffersToB64(o, circular = null) {
    if (!circular) {
      circular = new WeakSet()
    }
    if (o && (typeof o === 'object')) {
      if (circular.has(o)) {
        return '[Circular reference]'
      }
      circular.add(o)
      if (Buffer.isBuffer(o)) {
        return o.toString('base64')
      } else if (Array.isArray(o)) {
        return o.map(v => this.buffersToB64(v, circular))
      }
      return Object.entries(o).reduce((prev, [k, v]) => {
        prev[k] = this.buffersToB64(v, circular)
        return prev
      }, {})
    }
    return o
  }
}

module.exports = DNSutils
