'use strict'

const https = require('https')
const {Writable} = require('stream')
const tls = require('tls')
const packet = require('dns-packet')
const fetch = require('node-fetch')
const pkg = require('../package.json')
const DNSutils = require('./dnsUtils')

const WF_DNS = 'application/dns-message'
const WF_JSON = 'application/dns-json'
const CLOUDFLARE_API = 'https://cloudflare-dns.com/dns-query'
const USER_AGENT = `${pkg.name} v${pkg.version}`

/**
 * Options for doing DOH lookups.
 *
 * @typedef {object} DOH_LookupOptions
 * @property {string} [name] The DNS name to look up.
 * @property {packet.RecordType} [rrtype='A'] The Resource Record type
 *   to retrive.
 * @property {boolean} [json=true] Retrieve a JSON response.  If false,
 *   retrieve using DNS format.
 * @property {boolean} [decode=true] Decode the response, either into JSON
 *   or an object representing the DNS format result.
 * @property {boolean} [preferPost=true] For DNS format requests, should
 *   the HTTP POST verb be used?  If false, uses GET.
 * @property {boolean} [dnssec=false] Request DNSSec records.  Currently
 *   requires `json: false`.
 * @property {string} [url=CLOUDFLARE_API] What DoH endpoint should be
 *   used?
 */

/**
 * Request DNS information over HTTPS.  The [lookup]{@link DNSoverHTTPS#lookup}
 * function provides the easiest-to-use defaults.
 */
class DNSoverHTTPS extends DNSutils {
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
   * @param {boolean} [opts.verbose=false] Turn on verbose output?
   * @param {Writable} [opts.verboseStream=process.stderr] Where to write
   *   verbose output.
   */
  constructor(opts = {}) {
    const {
      verbose,
      verboseStream,
      ...rest
    } = opts
    super({verbose, verboseStream})
    this.opts = {
      userAgent: DNSoverHTTPS.userAgent,
      url: DNSoverHTTPS.url,
      preferPost: true,
      contentType: WF_DNS,
      ...rest,
    }

    this.verbose('DNSoverHTTPS options:', this.opts)
  }

  /**
   * Get a DNS-format response.
   *
   * @param {DOH_LookupOptions} opts Options for the request.
   * @returns {Promise<Buffer|object>} DNS result.
   */
  async getDNS(opts) {
    this.verbose('DNSoverHTTPS.getDNS options:', opts)

    const pkt = DNSutils.makePacket(opts)
    let url = opts.url || this.opts.url
    let method = 'POST'
    let body = pkt
    let agent = null

    if (this._verbose) {
      this.verbose('REQUEST:')
      this.hexDump(pkt)
      this.verbose(packet.decode(pkt))
      if (url.startsWith('https:')) {
        agent = new https.Agent({
          checkServerIdentity: (host, cert) => {
            this.verbose('CERTIFICATE:', DNSutils.buffersToB64(cert))
            return tls.checkServerIdentity(host, cert)
          },
        })
      }
    }

    if (!this.opts.preferPost) {
      method = 'GET'
      url += `?dns=${DNSutils.base64urlEncode(pkt)}`
      body = undefined
    }
    const r = await fetch(url, {
      method,
      headers: {
        'Content-Type': this.opts.contentType,
        'User-Agent': this.opts.userAgent,
        Accept: this.opts.contentType,
      },
      body,
      agent,
    })
    const response = await r.buffer()
    this.verbose('RESULT:')
    this.hexDump(response)

    return opts.decode ? packet.decode(response) : response
  }

  /**
   * Make a HTTPS GET request for JSON DNS.
   *
   * @param {object} opts Options for the request.
   * @param {string} [opts.name] The name to look up.
   * @param {packet.RecordType} [opts.rrtype="A"] The record type to look up.
   * @param {boolean} [opts.decode=true] Parse the returned JSON?
   * @returns {Promise<string|object>} DNS result.
   */
  async getJSON(opts) {
    this.verbose('DNSoverHTTPS.getJSON options: ', opts)

    const rrtype = opts.rrtype || 'A'
    const req = `${this.opts.url}?name=${opts.name}&type=${rrtype}`
    let agent = null

    if (this._verbose) {
      this.verbose('REQUEST:', req)
      if (this.opts.url.startsWith('https:')) {
        agent = new https.Agent({
          checkServerIdentity: (host, cert) => {
            this.verbose('CERTIFICATE:', DNSutils.buffersToB64(cert))
            return tls.checkServerIdentity(host, cert)
          },
        })
      }
    }

    const r = await fetch(
      req, {
        headers: {
          'User-Agent': this.opts.userAgent,
          Accept: WF_JSON,
        },
        agent,
      }
    )
    const decode = Object.prototype.hasOwnProperty.call(opts, 'decode') ?
      opts.decode :
      true
    return decode ? r.json() : r.text()
  }

  /**
   * Look up a DNS entry using DNS-over-HTTPS (DoH).
   *
   * @param {object|DOH_LookupOptions} name The DNS name to look up, or opts if
   *   this is an object.
   * @param {DOH_LookupOptions|string} [opts={}] Options for the request.  If a
   *   string is given, it will be used as the rrtype.
   * @returns {Promise<Buffer|string|object>} DNS result.
   */
  lookup(name, opts = {}) {
    const nopts = DNSutils.normalizeArgs(name, opts, {
      rrtype: 'A',
      json: true,
      decode: true,
      dnssec: false,
    })
    this.verbose('DNSoverHTTPS.lookup options:', nopts)

    return nopts.json ? this.getJSON(nopts) : this.getDNS(nopts)
  }
}

DNSoverHTTPS.version = pkg.version
DNSoverHTTPS.userAgent = USER_AGENT
DNSoverHTTPS.url = CLOUDFLARE_API
module.exports = DNSoverHTTPS
