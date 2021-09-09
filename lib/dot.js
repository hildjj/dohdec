'use strict'

const {Buffer} = require('buffer')
const crypto = require('crypto')
const tls = require('tls')
const util = require('util')
const packet = require('dns-packet')
const NoFilter = require('nofilter')
const DNSutils = require('./dnsUtils')

const randomBytes = util.promisify(crypto.randomBytes)

const DEFAULT_SERVER = '1.1.1.1'

/**
 * A class that manages a connection to a DNS-over-TLS server.  The first time
 * [lookup]{@link DNSoverTLS#lookup} is called, a connection will be created.
 * If that connection is timed out by the server, a new connection will be
 * created as needed.
 *
 * If you want to do certificate pinning, make sure that the `hash` and
 * `hashAlg` options are set correctly to a hash of the DER-encoded
 * certificate that the server will offer.
 */
class DNSoverTLS extends DNSutils {
  /**
   * Construct a new DNSoverTLS.
   *
   * @param {object} opts Options.
   * @param {string} [opts.host='1.1.1.1'] Server to connect to.
   * @param {number} [opts.port=853] TCP port number for server.
   * @param {string} [opts.hash] Hex-encoded hash of the DER-encoded cert
   *   expected from the server.  If not specified, no pinning checks are
   *   performed.
   * @param {string} [opts.hashAlg='sha256'] Hash algorithm for cert pinning.
   * @param {boolean} [opts.rejectUnauthorized=true] Should the server
   *   certificate even be checked using the normal TLS approach?
   * @param {boolean} [opts.verbose=false] Print bytes sent and received.
   */
  constructor(opts = {}) {
    const {
      verbose,
      verboseStream,
      ...rest
    } = opts

    super({verbose, verboseStream})
    this.opts = {
      host: DNSoverTLS.server,
      port: 853,
      hashAlg: 'sha256',
      rejectUnauthorized: true,
      ...rest,
    }
    this.verbose('DNSoverTLS options:', this.opts)
    this._reset()
  }

  _reset() {
    this.socket = null
    this.pending = {}
    this.nof = null
    this.size = -1
    this.bufs = []
  }

  _connect() {
    return new Promise((resolve, reject) => {
      if (this.socket) {
        resolve()
        return
      }

      /**
       * Fired right before connection is attempted.
       *
       * @event DNSoverTLS#connect
       * @property {object} cert [lookup]{@link DNSoverTLS#lookup} options.
       */
      this.emit('connect', this.opts)
      this.verbose('CONNECT:', this.opts)

      this.socket = tls.connect(this.opts, () => {
        // Either we're authorized, or rejectUnauthorized was false
        const cert = this.socket.getPeerCertificate(true)
        cert.hash = DNSoverTLS.hashCert(cert, this.opts.hashAlg)

        /* eslint-disable max-len */
        /**
         * Fired on connection when the server sends a certificate.
         *
         * @event DNSoverTLS#certificate
         * @property {crypto.Certificate} cert
         *   A [crypto.Certificate]{@link https://nodejs.org/api/crypto.html#crypto_class_certificate}
         *   from the server.
         */
        this.emit('certificate', cert)
        /* eslint-enable max-len */

        this.verbose('CERTIFICATE:', DNSutils.buffersToB64(cert))

        if (this.socket.authorized) {
          if (this.opts.hash && (this.opts.hash !== cert.hash)) {
            reject(new Error(`Invalid cert hash for ${this.opts.host}:${this.opts.port}.
Expected: "${this.opts.hash}"
Received: "${cert.hash}"`))
            this.close()
          } else {
            resolve()
          }
        } else if (this.opts.hash === cert.hash) {
          // Allow unauthorized cert if it's pinned
          resolve()
        } else {
          reject(new Error(this.socket.authorizationError))
          this.close()
        }
      })
      this.nof = new NoFilter()
      this.socket.on('data', this._data.bind(this))
      this.socket.on('error', reject)
      this.socket.on('end', this._disconnected.bind(this))
    })
  }

  /**
   * Server socket was disconnected.  Clean up any pending requests.
   *
   * @private
   */
  _disconnected() {
    for (const { reject, opts } of Object.values(this.pending)) {
      reject(new Error(`Timeout looking up "${opts.name}":${opts.rrtype}`))
    }
    this._reset()

    /**
     * Server disconnected.  All pending requests will have failed.
     *
     * @event DNSoverTLS#disconnect
     */
    this.emit('disconnect')
    this.verbose('DISCONNECT')
  }

  /**
   * Parse data if enough is available.
   *
   * @private
   * @param {Buffer} b Data read from socket.
   */
  _data(b) {
    if (!b) {
      return
    }

    /**
     * A buffer of data has been received from the server.  Useful for
     * verbose logging, e.g.
     *
     * @event DNSoverTLS#receive
     */
    this.emit('receive', b)
    this.nof.write(b)
    if (this.size === -1) {
      if (this.nof.length < 2) {
        return
      }

      this.size = this.nof.readUInt16BE()
    }
    if (this.nof.length < this.size) {
      return
    }
    const buf = this.nof.read(this.size)
    this.verbose('RECV:')
    this.hexDump(buf)

    this.size = -1
    const pkt = packet.decode(buf)
    const pend = this.pending[pkt.id]
    if (!pend) {
      // Something bad happened.  abandon everything pending.
      this.close()
      return
    }
    pend.resolve(pend.opts.decode ? pkt : buf)
    this._data() // Any more?
  }

  /**
   * Generate a currently-unused random ID.
   *
   * @returns {number} A random 2-byte ID number.
   * @private
   */
  async _id() {
    let id = null
    do {
      id = (await randomBytes(2)).readUInt16BE()
    } while (this.pending[id])
    return id
  }

  /**
   * Hash a certificate using the given algorithm.
   *
   * @param {Buffer|crypto.Certificate} cert The cert to hash.
   * @param {string} [hashAlg="sha256"] The hash algorithm to use.
   * @returns {string} Hex string.
   * @throws {Error} Unknown certificate type.
   */
  static hashCert(cert, hashAlg = 'sha256') {
    const hash = crypto.createHash(hashAlg)
    if (Buffer.isBuffer(cert)) {
      hash.update(cert)
    } else if (cert.raw) {
      hash.update(cert.raw)
    } else {
      throw new Error('Unknown certificate type')
    }

    return hash.digest('hex')
  }

  /**
   * Look up a name in the DNS, over TLS.
   *
   * @param {object|string} name The DNS name to look up, or opts if this is
   *   an object.
   * @param {object|string} [opts={}] Options for the request.  If a string
   *   is given, it will be used as the rrtype.
   * @param {string} [opts.name] The DNS name to look up.
   * @param {string} [opts.rrtype='A'] The Resource Record type to retrive.
   * @param {boolean} [opts.decode=true] Decode the response, into an object
   *   representing the DNS format result.
   * @param {boolean} [opts.dnssec=false] Request DNSSec records.
   */
  async lookup(name, opts = {}) {
    opts = DNSutils.normalizeArgs(name, opts, {
      rrtype: 'A',
      dnsssec: false,
      decode: true,
    })
    this.verbose('DNSoverTLS.lookup options:', opts)

    await this._connect()
    if (!opts.id) {
      // eslint-disable-next-line require-atomic-updates
      opts.id = await this._id()
    }

    return new Promise((resolve, reject) => {
      const pkt = DNSutils.makePacket(opts)

      this.verbose('REQUEST:')
      this.hexDump(pkt)
      this.verbose(packet.decode(pkt))

      this.pending[opts.id] = { resolve, reject, opts }

      const sz = Buffer.allocUnsafe(2)
      sz.writeUInt16BE(pkt.length)

      /**
       * A buffer of data has been received from the server.  Useful for
       * verbose logging, e.g.
       *
       * @event DNSoverTLS#send
       */
      this.socket.write(sz)
      this.emit('send', sz)
      this.verbose('SIZE:')
      this.verbose(sz)

      this.socket.write(pkt)
      this.emit('send', pkt)
      this.verbose('REQUEST:')
      this.hexDump(pkt)
    })
  }

  /**
   * Close the socket.
   *
   * @returns {Promise} Resolved on socket close.
   */
  close() {
    return new Promise((resolve, reject) => {
      if (this.socket) {
        this.socket.end(null, resolve)
      } else {
        resolve()
      }
    })
  }
}
DNSoverTLS.server = DEFAULT_SERVER
module.exports = DNSoverTLS
