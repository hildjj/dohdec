import * as net from 'node:net';
import {DEFAULT_SERVER, DNSutils} from './dnsUtils.js';
import {NoFilter} from 'nofilter';
import assert from 'node:assert';

/** @import {VerboseOptions, Writable} from './dnsUtils.js' */

/**
 * @typedef {VerboseOptions & Partial<net.NetConnectOpts>} TCPoptions
 */

/**
 * A class that manages a connection to a DNS-over-TCP server.  The first time
 * [lookup]{@link DNSoverTCP#lookup} is called, a connection will be created.
 * If that connection is timed out by the server, a new connection will be
 * created as needed.
 */
export class DNSoverTCP extends DNSutils {
  size = -1;

  /** @type {NoFilter|undefined} */
  nof = undefined;

  /** @type {Buffer[]} */
  bufs = [];

  /**
   * @type {net.NetConnectOpts}
   */
  opts;

  /**
   * Construct a new DNSoverTCP.
   *
   * @param {TCPoptions} [opts = {host: '1.1.1.1', port: 53}] Options.
   */
  constructor(opts = {}) {
    const {
      timeout,
      verbose,
      verboseStream,
      ...rest
    } = opts;

    super({timeout, verbose, verboseStream});
    this.opts = {
      host: /** @type {typeof DNSoverTCP} */(this.constructor).server,
      port: /** @type {typeof DNSoverTCP} */(this.constructor).port,
      ...rest,
    };
    this.verbose(1, 'DNSoverTCP options:', this.opts);
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
       * @property {object} cert [lookup]{@link DNSoverTCP#lookup} options.
       * @event DNSoverTCP#connect
       */
      this.emit('connect', this.opts);
      this.verbose(1, 'CONNECT:', this.opts);

      this.nof = new NoFilter();
      this.socket = net.connect(this.opts, resolve);
      this.socket.on('data', this._data.bind(this));
      this.socket.on('error', reject);
      this.socket.on('close', this._disconnected.bind(this));
    });
  }

  /**
   * Server socket was disconnected.  Clean up any pending requests.
   *
   * @protected
   */
  _disconnected() {
    this._reset();

    /**
     * Server disconnected.  All pending requests will have failed.
     *
     * @event DNSoverCP#disconnect
     */
    this.emit('disconnect');
    this.verbose(1, 'DISCONNECT');
  }

  /**
   * Parse data if enough is available.
   *
   * @param {Buffer} b Data read from socket.
   * @protected
   */
  _data(b) {
    /**
     * A buffer of data has been received from the server.  Useful for
     * verbose logging, e.g.
     *
     * @event DNSoverTCP#receive
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
   * Send a packet.
   *
   * @param {Buffer} pkt Packet.
   * @protected
   */
  _send(pkt) {
    const ts = /** @type {net.Socket} */ (this.socket);
    ts.write(pkt);
  }
}
DNSoverTCP.server = DEFAULT_SERVER;
DNSoverTCP.port = 53;

export default DNSoverTCP;
