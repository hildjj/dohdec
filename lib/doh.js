'use strict'

const https = require('https')
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
 * HTTPS Agent that logs to stdout certificate information from connections.
 *
 * @private
 */
class CertAgent extends https.Agent {
  constructor(parent) {
    super()
    this.parent = parent
  }

  createConnection(options, cb) {
    const csi = options.checkServerIdentity
    options.checkServerIdentity = (name, cert) => {
      this.parent.verbose('CERTIFICATE:', DNSutils.buffersToB64(cert))
      return (typeof csi === 'function') ?
        csi(name, cert) :
        tls.checkServerIdentity(name, cert)
    }
    return super.createConnection(options, cb)
  }
}

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
   * @param {boolean} [opts.verbose=false] Print bytes for DNS-style queries.
   * @param {string} [opts.contentType="application/dns-udpwireformat"]
   *   MIME type for POST.
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

  createAgent(parsedUrl) {
    this.verbose('CREATING AGENT for:', parsedUrl)
    return (parsedUrl.protocol === 'https:') ? new CertAgent(this) : undefined
  }

  /**
   * Get a DNS-format response.
   *
   * @param {object} opts Options for the request.
   * @param {string} [opts.name] The name to look up.
   * @param {string} [opts.rrtype="A"] The record type to look up.
   * @param {boolean} [opts.decode=true] Parse the returned DNS packet?
   * @param {boolean} [opts.dnssec=false] Request DNSSec information?
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
      agent = this.createAgent.bind(this)
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
        'User-Agent': this.userAgent,
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
   * @param {string} [opts.rrtype="A"] The record type to look up.
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
      agent = this.createAgent.bind(this)
    }

    const r = await fetch(
      req, {
        headers: {
          'User-Agent': this.userAgent,
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
   * @param {object|string} name The DNS name to look up, or opts if this is
   *   an object.
   * @param {object|string} [opts={}] Options for the request.  If a string
   *   is given, it will be used as the rrtype.
   * @param {string} [opts.name] The DNS name to look up.
   * @param {string} [opts.rrtype='A'] The Resource Record type to retrive.
   * @param {boolean} [opts.json=true] Retrieve a JSON response.  If false,
   *   retrieve using DNS format.
   * @param {boolean} [opts.decode=true] Decode the response, either into JSON
   *   or an object representing the DNS format result.
   * @param {boolean} [opts.preferPost=true] For DNS format requests, should
   *   the HTTP POST verb be used?  If false, uses GET.
   * @param {boolean} [opts.dnssec=false] Request DNSSec records.  Currently
   *   requires `json: false`.
   * @param {string} [opts.url=CLOUDFLARE_API] What DoH endpoint should be
   *   used?
   * @returns {Promise<Buffer|string|object>} DNS result.
   */
  lookup(name, opts = {}) {
    opts = DNSutils.normalizeArgs(name, opts, {
      rrtype: 'A',
      json: true,
      decode: true,
      dnssec: false,
    })
    this.verbose('DNSoverHTTPS.lookup options:', opts)

    return opts.json ? this.getJSON(opts) : this.getDNS(opts)
  }
}

DNSoverHTTPS.version = pkg.version
DNSoverHTTPS.userAgent = USER_AGENT
DNSoverHTTPS.url = CLOUDFLARE_API
module.exports = DNSoverHTTPS
