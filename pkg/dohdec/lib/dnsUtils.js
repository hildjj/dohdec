// @ts-expect-error These types are private
import * as optioncodes from 'dns-packet/optioncodes.js';
import * as packet from 'dns-packet';
// @ts-expect-error These types are private
import * as rcodes from 'dns-packet/rcodes.js';
import {Buffer} from 'node:buffer';
import {EventEmitter} from 'node:events';
import ip from 'ip-address';
import net from 'node:net';
import url from 'node:url';
import util from 'node:util';

const PAD_SIZE = 128;

/**
 * @typedef {object} LookupOptions
 * @property {string} [name] Name to look up.
 * @property {packet.RecordType} [rrtype] The Resource Record type to retrive.
 * @property {number} [id] The 2-byte unsigned integer for the request.
 *   For DOH, should be 0 or undefined.
 * @property {boolean} [decode=true] Decode the response, either into JSON
 *   or an object representing the DNS format result.
 * @property {boolean} [stream=false] Encode for streaming, with the packet
 *   prefixed by a 2-byte big-endian integer of the number of bytes in the
 *   packet.
 * @property {boolean} [dnssec=false] Request DNSSec records.  Currently
 *   requires `json: false`.
 * @property {boolean} [dnssecCheckingDisabled=false] Disable DNSSEC
 */

/**
 * @typedef {import('stream').Writable & {isTTY?: boolean}} Writable
 */

/**
 * Extracted from node source.
 * Only exported for testing.
 *
 * @param {string} str
 * @param {util.Style} styleType
 * @returns {string}
 * @private
 */
export function stylizeWithColor(str, styleType) {
  const style = util.inspect.styles[styleType];
  if (style !== undefined) {
    const color = util.inspect.colors[style];
    return `\u001b[${color[0]}m${str}\u001b[${color[1]}m`;
  }
  return str;
}

/**
 * @param {Writable} stream
 * @param {string} str
 * @param {util.Style} styleType
 * @private
 */
function styleStream(stream, str, styleType) {
  stream.write(stream.isTTY ? stylizeWithColor(str, styleType) : str);
}

/**
 * Exported for testing only
 * @param {Writable} stream
 * @param {Buffer} buf
 * @returns {number}
 */
export function printableString(stream, buf) {
  // Intent: each byte that is "printable" takes up one grapheme, and everything
  // else is replaced with '.'

  for (const x of buf) {
    if ((x < 0x20) ||
        ((x > 0x7e) && (x < 0xa1)) ||
        (x === 0xad)) {
      stream.write('.');
    } else {
      styleStream(stream, String.fromCharCode(x), 'string');
    }
  }
  return buf.length;
}

export class DNSutils extends EventEmitter {
  /** @type {Writable} */
  verboseStream;

  /**
   * Creates an instance of DNSutils.
   *
   * @param {object} [opts={}] Options.
   * @param {number} [opts.verbose=0] How verbose do you want your logging?
   * @param {Writable} [opts.verboseStream=process.stderr]
   *   Where to write verbose output.
   */
  constructor(opts = {}) {
    super();
    if (opts.verbose && (typeof opts.verbose !== 'number')) {
      throw new Error('Bad verbose level');
    }

    this._verbose = opts.verbose || 0;
    this.verboseStream = opts.verboseStream || process.stderr;
  }

  /**
   * Output verbose logging information, if this.verbose is true.
   *
   * @param {number} level Print at this verbosity level or higher.
   * @param {any[]} args Same as onsole.log parameters.
   * @returns {boolean} True if output was written.
   */
  verbose(level, ...args) {
    if (this._verbose >= level) {
      // Defer expensive processing
      args = args.map(a => ((typeof a === 'function') ? a() : a));
      this.verboseStream.write(util.formatWithOptions({
        // Really, process.stderr is a tty.WriteStream, but this will work
        // fine in practice since isTTY will be undefined on other streams.
        // @ts-ignore TS2339
        colors: this.verboseStream.isTTY,
        depth: Infinity,
        sorted: true,
      }, ...args));
      this.verboseStream.write('\n');
      return true;
    }
    return false;
  }

  /**
   * Dump a nice hex representation of the given buffer to verboseStream,
   * if verbose is true.
   *
   * @param {number} level Print at this verbosity level or higher.
   * @param {Buffer} buf The buffer to dump.
   * @returns {boolean} True if output was written.
   */
  hexDump(level, buf) {
    if (this._verbose < level) {
      return false;
    }
    if (buf.length > 0) {
      let offset = 0;
      for (const byte of buf.slice(0, buf.length)) {
        // eslint-disable-next-line @stylistic/indent
/*
00000000  7b 0a 20 20 22 6e 61 6d  65 22 3a 20 22 64 6f 68  |{.  "name": "doh|
*/
        if ((offset % 16) === 0) {
          if (offset !== 0) {
            this.verboseStream.write('  |');
            printableString(this.verboseStream, buf.slice(offset - 16, offset));
            this.verboseStream.write('|\n');
          }
          styleStream(this.verboseStream, offset.toString(16).padStart(8, '0'), 'undefined');
        }
        if ((offset % 8) === 0) {
          this.verboseStream.write(' ');
        }
        this.verboseStream.write(' ');
        this.verboseStream.write(byte.toString(16).padStart(2, '0'));
        offset++;
      }
      let left = offset % 16;
      if (left === 0) {
        left = 16;
      } else {
        let undone = 3 * (16 - left);
        if (left <= 8) {
          undone++;
        }
        this.verboseStream.write(' '.padStart(undone, ' '));
      }

      const start = offset > 16 ? offset - left : 0;
      this.verboseStream.write('  |');
      printableString(this.verboseStream, buf.slice(start, offset));
      this.verboseStream.write('|\n');
    }
    styleStream(this.verboseStream, buf.length.toString(16).padStart(8, '0'), 'undefined');
    this.verboseStream.write('\n');
    return true;
  }

  /**
   * Encode a DNS query packet to a buffer.
   *
   * @param {object} opts Options for the query.
   * @param {string} [opts.name] The name to look up.
   * @param {number} [opts.id=0] ID for the query.  SHOULD be 0 for DOH.
   * @param {packet.RecordType} [opts.rrtype="A"] The record type to look up.
   * @param {boolean} [opts.dnssec=false] Request DNSSec information?
   * @param {boolean} [opts.dnssecCheckingDisabled=false] Disable DNSSec
   *   validation?
   * @param {string} [opts.ecsSubnet] Subnet to use for ECS.
   * @param {number} [opts.ecs] Number of ECS bits.  Defaults to 24 or 56
   *   (IPv4/IPv6).
   * @param {boolean} [opts.stream=false] Encode for streaming, with the packet
   *   prefixed by a 2-byte big-endian integer of the number of bytes in the
   *   packet.
   * @returns {Buffer} The encoded packet.
   */
  static makePacket(opts) {
    if (!opts?.name) {
      throw new TypeError('Name is required');
    }

    /** @type {packet.OptAnswer} */
    const opt = {
      name: '.',
      type: 'OPT',
      udpPayloadSize: 4096,
      extendedRcode: 0,
      flags: 0,
      flag_do: false, // Setting here has no effect
      ednsVersion: 0,
      options: [],
    };

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
      additionals: [opt],
    };
    if (opts.dnssec) {
      dns.flags |= packet.AUTHENTIC_DATA;
      opt.flags |= packet.DNSSEC_OK;
    }
    if (opts.dnssecCheckingDisabled) {
      dns.flags |= packet.CHECKING_DISABLED;
    }
    if (opts.ecs != null || net.isIP(opts.ecsSubnet) !== 0) {
      // https://tools.ietf.org/html/rfc7871#section-11.1
      const prefix = (opts.ecsSubnet && net.isIPv4(opts.ecsSubnet)) ? 24 : 56;
      opt.options.push({
        code: optioncodes.toCode('CLIENT_SUBNET'),
        ip: opts.ecsSubnet || '0.0.0.0',
        sourcePrefixLength: (opts.ecs == null) ? prefix : opts.ecs,
      });
    }
    const unpadded = packet.encodingLength(dns);
    opt.options.push({
      code: optioncodes.toCode('PADDING'),
      // Next pad size, minus what we already have, minus another 4 bytes for
      // the option header
      length: (Math.ceil(unpadded / PAD_SIZE) * PAD_SIZE) - unpadded - 4,
    });
    if (opts.stream) {
      return packet.streamEncode(dns);
    }
    return packet.encode(dns);
  }

  /**
   * Normalize parameters into the lookup functions.
   *
   * @param {string|LookupOptions} [name] If string, lookup this name,
   *   otherwise it is options.  Has precedence over opts.name if string.
   * @param {string|LookupOptions} [opts] If string, rrtype.
   *   Otherwise options.
   * @param {object} [defaults] Defaults options.
   * @returns {LookupOptions} Normalized options, including punycode∑d
   *   options.name and upper-case options.rrtype.
   * @throws {Error} Invalid type for name.
   */
  static normalizeArgs(name, opts, defaults) {
    /** @type {LookupOptions} */
    let nopts = Object.create(null);
    if (name != null) {
      switch (typeof name) {
        case 'object':
          nopts = name;
          break;
        case 'string':
          nopts.name = name;
          break;
        default:
          throw new Error('Invalid type for name');
      }
    }
    if (opts != null) {
      switch (typeof opts) {
        case 'object':
          nopts = {...opts, ...nopts};
          break;
        case 'string':
          nopts = {...nopts, rrtype: /** @type {packet.RecordType} */(opts)};
          break;
        default:
          throw new Error('Invalid type for opts');
      }
    }

    return {
      ...defaults,
      ...nopts,
      name: url.domainToASCII(nopts.name),
      rrtype: /** @type {packet.RecordType} */((nopts.rrtype || 'A').toUpperCase()),
    };
  }

  /**
   * See [RFC 4648]{@link https://tools.ietf.org/html/rfc4648#section-5}.
   *
   * @param {Buffer} buf Buffer to encode.
   * @returns {string} The base64url string.
   */
  static base64urlEncode(buf) {
    const s = buf.toString('base64');
    return s.replace(/[=+/]/g, c => ({
      '=': '',
      '+': '-',
      '/': '_',
    })[c]);
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
      circular = new WeakSet();
    }
    if (o && (typeof o === 'object')) {
      if (circular.has(o)) {
        return '[Circular reference]';
      }
      circular.add(o);
      if (Buffer.isBuffer(o)) {
        return o.toString('base64');
      } else if (Array.isArray(o)) {
        return o.map(v => this.buffersToB64(v, circular));
      }
      return Object.entries(o).reduce((prev, [k, v]) => {
        // @ts-expect-error Object.create(null) messes up output
        prev[k] = this.buffersToB64(v, circular);
        return prev;
      }, {});
    }
    return o;
  }

  /**
   * Calculate the reverse name to look up for an IP address.
   *
   * @param {string} addr The IPv[46] address to reverse.
   * @returns {string} Address ending in .in-addr.arpa or .ip6.arpa.
   * @throws {Error} Invalid IP Address.
   */
  static reverse(addr) {
    const ai = net.isIPv4(addr) ? new ip.Address4(addr) : new ip.Address6(addr);
    return ai.reverseForm();
  }
}

export class DNSError extends Error {
  /**
   * Create a DNS Error that wraps another error.
   * @param {Error} er
   * @param {packet.Packet} pkt
   */
  constructor(er, pkt) {
    super(`DNS error: ${er}`, {cause: er});
    this.packet = pkt;
    this.code = `dns.${er}`;
  }

  /**
   * Factory to extract DNS error from packet.
   *
   * @param {packet.Packet} pkt
   * @returns {DNSError}
   */
  static getError(pkt) {
    if (Object.prototype.hasOwnProperty.call(pkt, 'rcode')) {
      // @ts-expect-error Types don't include rcode
      if (pkt.rcode !== 'NOERROR') {
        // @ts-expect-error Types don't include rcode
        return new DNSError(pkt.rcode, pkt);
      }
    } else if (Object.prototype.hasOwnProperty.call(pkt, 'Status')) {
      // @ts-expect-error Types don't include Status
      if (pkt.Status !== 0) {
        // @ts-expect-error Types don't include Status
        return new DNSError(rcodes.toString(pkt.Status), pkt);
      }
    }
    return null;
  }
}

export default DNSutils;
