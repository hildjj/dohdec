import * as dgram from 'node:dgram';
import * as net from 'node:net';
import {DEFAULT_SERVER, DNSutils} from './dnsUtils.js';

/** @import {Buffer} from 'node:buffer' */
/** @import {LookupOptions, Writable} from './dnsUtils.js' */

export class DNSoverUDP extends DNSutils {
  /**
   * Construct a new DNSoverUDP.
   *
   * @param {object} opts Options.
   * @param {string} [opts.host='1.1.1.1'] Server to connect to.
   * @param {number} [opts.port=53] TCP port number for server.
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
      host: DNSoverUDP.server,
      port: DNSoverUDP.port,
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
        const typ = net.isIP(this.opts.host);
        switch (typ) {
          case 4:
            this.socket = dgram.createSocket('udp4');
            break;
          case 6:
            this.socket = dgram.createSocket('udp6');
            break;
          default:
            reject(new TypeError(`Invalid server, not v4 or v6: ${this.opts.host}`));
            return;
        }
        this.socket.connect(this.opts.port, this.opts.host, resolve);
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
