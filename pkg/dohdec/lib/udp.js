import * as dgram from 'node:dgram';
import * as net from 'node:net';
import {DEFAULT_SERVER, DNSutils} from './dnsUtils.js';

/** @import {Buffer} from 'node:buffer' */
/** @import {VerboseOptions} from './dnsUtils.js' */

/**
 * @typedef {object} ConnectOptions
 * @property {string} [host] Hostname.
 * @property {number} [port] Port number.
 */

/**
 * @typedef {VerboseOptions &
 *   ConnectOptions & Partial<dgram.SocketOptions>} UDPoptions
 */

export class DNSoverUDP extends DNSutils {
  /** @type {dgram.SocketOptions} */
  opts;

  host;
  port;

  /**
   * Construct a new DNSoverUDP.
   *
   * @param {UDPoptions} [opts = {host: '1.1.1.1', port: 53}] Options.
   */
  constructor(opts = {}) {
    const {
      verbose,
      verboseStream,
      host = DNSoverUDP.server,
      port = DNSoverUDP.port,
      ...rest
    } = opts;

    super({verbose, verboseStream});

    this.host = host;
    this.port = port;
    this.opts = {
      type: (net.isIP(host) === 6) ? 'udp6' : 'udp4',
      ...rest,
    };
    this.stream = false;
    this.verbose(1, 'DNSoverUDP options:', this.opts);
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
       * Fired right before connect is attempted.
       * @event DNSoverUDP#connect
       */
      this.emit('connect', this.opts);
      this.verbose(1, 'CONNECT:', this.opts);

      try {
        this.socket = dgram.createSocket(this.opts);
        this.socket.connect(this.port, this.host, resolve);
        this.socket.on('message', this._message.bind(this));
        this.socket.on('error', reject);
        this.socket.on('close', this._close.bind(this));
      } catch (er) {
        reject(er);
      }
    });
  }

  /**
   * Send packet.
   *
   * @param {Buffer} pkt Packet.
   * @protected
   */
  _send(pkt) {
    const us = /** @type {dgram.Socket} */ (this.socket);
    us.send(pkt);
  }

  /**
   * @param {Buffer} msg Message.
   * @param {dgram.RemoteInfo} _rinfo Remote info.
   * @private
   */
  _message(msg, _rinfo) {
    this._recv(msg);
  }

  /**
   * @private
   */
  _close() {
    // Could happen by .close() or with AbortSignal.
    this._reset();
  }
}
DNSoverUDP.server = DEFAULT_SERVER;
DNSoverUDP.port = 53;
