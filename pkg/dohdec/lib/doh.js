import * as packet from 'dns-packet';
import * as pkg from './pkg.js';
import * as tls from 'node:tls';
import {Agent} from './agent.js';
import {Buffer} from 'node:buffer';
import DNSutils from './dnsUtils.js';
import assert from 'node:assert';
import cryptoRandomString from 'crypto-random-string';

const PAD_SIZE = 128;
const WF_DNS = 'application/dns-message';
const WF_JSON = 'application/dns-json';
const CLOUDFLARE_API = 'https://cloudflare-dns.com/dns-query';
const USER_AGENT = `${pkg.name} v${pkg.version}`;

/**
 * @import {
 *   GenericPacket, JSONPacket, LookupOptions, Writable
 * } from './dnsUtils.js'
 */

/** @import {Dispatcher} from 'undici-types' */

/**
 * Options for doing DOH lookups.
 *
 * @typedef {object} DOH_SpecificLookupOptions
 * @property {boolean} [preferPost=true] For DNS format requests, should
 *   the HTTP POST verb be used?  If false, uses GET.
 * @property {string} [url=CLOUDFLARE_API] What DoH endpoint should be
 *   used?
 * @property {boolean} [json=true] Force JSON lookups for DOH.
 */

/**
 * @typedef {DOH_SpecificLookupOptions & LookupOptions} DOH_LookupOptions
 */

/**
 * Request DNS information over HTTPS.  The [lookup]{@link DNSoverHTTPS#lookup}
 * function provides the easiest-to-use defaults.
 */
export class DNSoverHTTPS extends DNSutils {
  /**
   * The user-agent used in HTTPS requests.
   * @type {string}
   */
  static userAgent = USER_AGENT;

  /**
   * The running version of dohdec.
   * @type {string}
   */
  static version = pkg.version;

  /**
   * Default URL for DNSoverHTTPS requests.
   * @type {string}
   */
  static defaultURL = CLOUDFLARE_API;

  /**
   * Create a DNSoverHTTPS instance.
   *
   * @param {object} opts Options for all requests.
   * @param {string} [opts.userAgent="packageName version"] User Agent for
   *   HTTP request.
   * @param {string} [opts.url="https://cloudflare-dns.com/dns-query"] Base URL
   *   for all HTTP requests.
   * @param {boolean} [opts.preferPost=true] Should POST be preferred to Get
   *   for DNS-format queries?
   * @param {string} [opts.contentType="application/dns-udpwireformat"]
   *   MIME type for POST.
   * @param {number} [opts.verbose=0] How verbose do you want your logging?
   * @param {Writable} [opts.verboseStream=process.stderr] Where to write
   *   verbose output.
   * @param {boolean} [opts.http2=true] Use http/2 if it is available.
   * @param {typeof fetch} [opts.customFetch=fetch] Custom `fetch`
   *   implementation.  Defaults to fetch.
   * @param {Dispatcher} [opts.agent] Undici agent for HTTPS requests.  If used,
   *   the http2 option is ignored, and the certificate information is never
   *   output, unless the specified agent makes that happen.
   */
  constructor(opts = {}) {
    const {
      verbose,
      verboseStream,
      ...rest
    } = opts;
    super({verbose, verboseStream});
    this.opts = {
      userAgent: DNSoverHTTPS.userAgent,
      url: DNSoverHTTPS.defaultURL,
      preferPost: true,
      contentType: WF_DNS,
      http2: true,
      customFetch: fetch,
      agent: undefined,
      ...rest,
    };

    this.opts.agent ??= new Agent({
      allowH2: this.opts.http2,
      connect: {
        checkServerIdentity: this._checkServerIdentity.bind(this),
      },
    });

    this.hooks = (this._verbose > 0) ?
      {
        beforeRequest: [(/** @type {Request} */options) => {
          this.verbose(1, `HTTP ${options.method} headers:`, options.headers);
          assert(options.url);
          this.verbose(1, `HTTP ${options.method} URL: ${options.url.toString()}`);
        }],
      } :
      undefined;

    this.verbose(1, 'DNSoverHTTPS options:', this.opts);
  }

  /**
   * Output certificate information in verbose mode.
   *
   * @param {string} host Host name.
   * @param {tls.PeerCertificate} cert Certificate.
   * @returns {Error | undefined} Error, or undefined on success.
   * @private
   */
  _checkServerIdentity(host, cert) {
    this.verbose(3, 'CERTIFICATE:', () => DNSutils.buffersToB64(cert));
    return tls.checkServerIdentity(host, cert);
  }

  /**
   * Get a DNS-format response.
   *
   * @param {DOH_LookupOptions} opts Options for the request.
   * @returns {Promise<Buffer|packet.DecodedPacket>} DNS result.
   */
  async getDNS(opts) {
    this.verbose(1, 'DNSoverHTTPS.getDNS options:', opts);

    const pkt = DNSutils.makePacket(opts);
    let url = opts.url || this.opts.url;

    /** @type {Buffer|undefined} */
    let body = pkt;

    this.verbose(1, 'REQUEST:', () => packet.decode(pkt));
    this.hexDump(2, pkt);

    if (!this.opts.preferPost) {
      url += `?dns=${DNSutils.base64urlEncode(pkt)}`;
      body = undefined;
    }
    const r = await this.#fetch(url, {
      // @ts-expect-error Node RequestInit (with dispatcher) != Web RequestInit
      dispatcher: this.opts.agent,
      method: this.opts.preferPost ? 'POST' : 'GET',
      headers: {
        'Content-Type': this.opts.contentType,
        'User-Agent': this.opts.userAgent,
        'Accept': this.opts.contentType,
      },
      body: body ? new Uint8Array(body) : undefined,
    });

    const response = Buffer.from(await r.bytes());
    this.hexDump(2, response);
    this.verbose(1, 'RESPONSE:', () => packet.decode(response));

    return opts.decode ? packet.decode(response) : response;
  }

  /**
   * Make a HTTPS GET request for JSON DNS.
   *
   * @param {object} opts Options for the request.
   * @param {string} [opts.name] The name to look up.
   * @param {string} [opts.rrtype="A"] The record type to look up.
   * @param {boolean} [opts.decode=true] Parse the returned JSON?
   * @param {boolean} [opts.dnssec=false] Request DNSSEC records.
   * @param {boolean} [opts.dnssecCheckingDisabled=false] Disable DNSSEC
   *   validation.
   * @returns {Promise<string|JSONPacket>} DNS result.
   */
  async getJSON(opts) {
    this.verbose(1, 'DNSoverHTTPS.getJSON options: ', opts);

    const rrtype = opts.rrtype || 'A';
    let req = `${this.opts.url}?name=${opts.name}&type=${rrtype}`;
    if (opts.dnssec) {
      req += '&do=1';
    }
    if (opts.dnssecCheckingDisabled) {
      req += '&cd=1';
    }
    req += '&random_padding=';
    req += cryptoRandomString({
      length: (Math.ceil(req.length / PAD_SIZE) * PAD_SIZE) - req.length,
      type: 'url-safe',
    });
    this.verbose(1, 'REQUEST:', req);

    const r = await this.#fetch(req, {
      // @ts-expect-error Node RequestInit (with dispatcher) != Web RequestInit
      dispatcher: this.opts.agent,
      headers: {
        'User-Agent': this.opts.userAgent,
        'Accept': WF_JSON,
      },
    });

    const decode = Object.prototype.hasOwnProperty.call(opts, 'decode') ?
      opts.decode :
      true;
    return decode ? r.json() : r.text();
  }

  /**
   * Look up a DNS entry using DNS-over-HTTPS (DoH).
   *
   * @param {string|DOH_LookupOptions} name The DNS name to look up, or opts
   *   if this is an object.
   * @param {DOH_LookupOptions|string} [opts={}] Options for the
   *   request.  If a string is given, it will be used as the rrtype.
   * @returns {Promise<GenericPacket|Buffer|string>} DNS result.
   */
  lookup(name, opts = {}) {
    const nopts = /** @type {Required<DOH_LookupOptions>} */ (
      DNSutils.normalizeArgs(name, opts, {
        rrtype: 'A',
        json: true,
        decode: true,
        dnssec: false,
        dnssecCheckingDisabled: false,
      })
    );
    this.verbose(1, 'DNSoverHTTPS.lookup options:', nopts);

    return nopts.json ? this.getJSON(nopts) : this.getDNS(nopts);
  }

  /**
   * Close any remaining keep-alive sockets.
   *
   * @returns {Promise<void>}
   */
  close() {
    assert(this.opts.agent);
    return this.opts.agent.close().then(() => this._reset());
  }

  /**
   * Internal call to fetch a buffer.
   *
   * @param {string} url URL.
   * @param {RequestInit} opts Options.
   * @returns {Promise<Response>} The fetch response.
   */
  #fetch(url, opts) {
    const request = new Request(url, opts);
    for (const hook of this.hooks?.beforeRequest ?? []) {
      hook(request);
    }
    return this.opts.customFetch(request);
  }
}

export default DNSoverHTTPS;
