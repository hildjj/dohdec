import * as crypto from 'node:crypto';
import * as tls from 'node:tls';
import {DEFAULT_SERVER, DNSutils} from './dnsUtils.js';
import {Buffer} from 'node:buffer';
import {DNSoverTCP} from './tcp.js';
import {NoFilter} from 'nofilter';

/** @import {LookupOptions, Writable} from './dnsUtils.js' */
/** @import {TCPoptions} from './tcp.js' */

/**
 * @typedef {object} TLSoptions
 * @property {string} [hash] Hex-encoded hash of the DER-encoded cert
 *   expected from the server.
 * @property {string} hashAlg Hash algorithm.
 */

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
export class DNSoverTLS extends DNSoverTCP {
  /** @type {TCPoptions & TLSoptions & {[key: string]: unknown}} */
  tlsOpts;

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
    super({
      hashAlg: 'sha256',
      rejectUnauthorized: true,
      ...opts,
    });

    this.tlsOpts = {
      hashAlg: 'sha256',
      rejectUnauthorized: true,
      checkServerIdentity: this._checkServerIdentity.bind(this),
      ...this.opts,
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
      this.socket = tls.connect(this.tlsOpts, resolve);
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
    const hash = DNSoverTLS.hashCert(cert, this.tlsOpts.hashAlg);

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
      if (this.tlsOpts.hash && (this.tlsOpts.hash !== hash)) {
        return new Error(`Invalid cert hash for ${this.opts.host}:${this.opts.port}.
Expected: "${this.tlsOpts.hash}"
Received: "${hash}"`);
      }
    } else if (this.tlsOpts.hash !== hash) {
      return err;
    }
    return undefined;
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
}
DNSoverTLS.server = DEFAULT_SERVER;
DNSoverTLS.port = 853;

export default DNSoverTLS;
