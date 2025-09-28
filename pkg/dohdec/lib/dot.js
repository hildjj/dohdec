import * as crypto from 'node:crypto';
import * as tls from 'node:tls';
import {DEFAULT_SERVER, DNSutils} from './dnsUtils.js';
import {Buffer} from 'node:buffer';
import {NoFilter} from 'nofilter';
import assert from 'node:assert';

/** @import {LookupOptions, Writable} from './dnsUtils.js' */

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
export class DNSoverTLS extends DNSutils {
  size = -1;

  /** @type {NoFilter|undefined} */
  nof = undefined;

  /** @type {Buffer[]} */
  bufs = [];

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
   * @param {number} [opts.verbose=0] How verbose do you want your logging?
   * @param {Writable} [opts.verboseStream=process.stderr] Where to write
   *   verbose output.
   */
  constructor(opts = {}) {
    const {
      verbose,
      verboseStream,
      ...rest
    } = opts;

    super({verbose, verboseStream});
    this.opts = {
      host: DNSoverTLS.server,
      port: DNSoverTLS.port,
      hashAlg: 'sha256',
      rejectUnauthorized: true,
      checkServerIdentity: this._checkServerIdentity.bind(this),
      ...rest,
    };
    this.verbose(1, 'DNSoverTLS options:', this.opts);
  }

  /**
   * Reset state.
   * @protected
   */
  _reset() {
    super._reset();
    this.size = -1;
    this.nof = undefined;
    this.bufs = [];
  }

  /**
   * Connect to server.
   *
   * @returns {Promise<void>}
   * @protected
   */
  _connect() {
    return new Promise((resolve, reject) => {
      if (this.socket) {
        resolve();
        return;
      }

      /**
       * Fired right before connection is attempted.
       *
       * @property {object} cert [lookup]{@link DNSoverTLS#lookup} options.
       * @event DNSoverTLS#connect
       */
      this.emit('connect', this.opts);
      this.verbose(1, 'CONNECT:', this.opts);

      this.nof = new NoFilter();
      this.socket = tls.connect(this.opts, resolve);
      this.socket.on('data', this._data.bind(this));
      this.socket.on('error', reject);
      this.socket.on('close', this._disconnected.bind(this));
    });
  }

  /**
   * @param {string} host Host name.
   * @param {tls.PeerCertificate} cert Certificate.
   * @returns {Error | undefined} Error, or undefined on success.
   * @private
   */
  _checkServerIdentity(host, cert) {
    // Same as cert.fingerprint256, but with hash agility
    const hash = DNSoverTLS.hashCert(cert, this.opts.hashAlg);

    /**
     * Fired on connection when the server sends a certificate.
     *
     * @property {crypto.Certificate} cert
     *   A [crypto.Certificate]{@link https://nodejs.org/api/crypto.html#crypto_class_certificate}
     *   from the server.
     * @property {string} host The hostname the client thinks it is
     *   connecting to.
     * @property {string} hash The hash computed over the cert.
     * @event DNSoverTLS#certificate
     */
    this.emit('certificate', cert, host, hash);

    this.verbose(2, 'CERTIFICATE:', () => DNSutils.buffersToB64(cert));
    const err = tls.checkServerIdentity(host, cert);
    if (!err) {
      if (this.opts.hash && (this.opts.hash !== hash)) {
        return new Error(`Invalid cert hash for ${this.opts.host}:${this.opts.port}.
Expected: "${this.opts.hash}"
Received: "${hash}"`);
      }
    } else if (this.opts.hash !== hash) {
      return err;
    }
    return undefined;
  }

  /**
   * Server socket was disconnected.  Clean up any pending requests.
   *
   * @private
   */
  _disconnected() {
    this._reset();

    /**
     * Server disconnected.  All pending requests will have failed.
     *
     * @event DNSoverTLS#disconnect
     */
    this.emit('disconnect');
    this.verbose(1, 'DISCONNECT');
  }

  /**
   * Parse data if enough is available.
   *
   * @param {Buffer} b Data read from socket.
   * @private
   */
  _data(b) {
    /**
     * A buffer of data has been received from the server.  Useful for
     * verbose logging, e.g.
     *
     * @event DNSoverTLS#receive
     */
    this.emit('receive', b);
    assert(this.nof);
    this.nof.write(b);

    // There might be multiple results in one read.
    while (this.nof.length > 0) {
      // No size read yet
      if (this.size === -1) {
        if (this.nof.length < 2) {
          return;
        }

        this.size = this.nof.readUInt16BE();
      }
      if (this.nof.length < this.size) {
        return;
      }

      const buf = /** @type {Buffer} */(this.nof.read(this.size));
      this._recv(buf);
      this.size = -1;
    }
  }

  /**
   * Hash a certificate using the given algorithm.
   *
   * @param {Buffer|tls.PeerCertificate} cert The cert to hash.
   * @param {string} [hashAlg="sha256"] The hash algorithm to use.
   * @returns {string} Hex string.
   * @throws {Error} Unknown certificate type.
   */
  static hashCert(cert, hashAlg = 'sha256') {
    const hash = crypto.createHash(hashAlg);
    if (Buffer.isBuffer(cert)) {
      hash.update(cert);
    } else if (cert.raw) {
      hash.update(cert.raw);
    } else {
      throw new Error('Unknown certificate type');
    }

    return hash.digest('hex');
  }

  /**
   * Send a packet.
   *
   * @param {Buffer} pkt Packet.
   * @protected
   */
  _send(pkt) {
    const ts = /** @type {tls.TLSSocket} */ (this.socket);
    ts.write(pkt);
  }
}
DNSoverTLS.server = DEFAULT_SERVER;
DNSoverTLS.port = 853;

export default DNSoverTLS;
