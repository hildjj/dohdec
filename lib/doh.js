'use strict'

const https = require('https')
const tls = require('tls')
const util = require('util')
const packet = require('dns-packet')
const fetch = require('node-fetch')
const pkg = require('../package.json')
const DNSutils = require('./dnsUtils')

const WF_DNS = 'application/dns-udpwireformat'
const WF_JSON = 'application/dns-json'
const CLOUDFLARE_API = 'https://cloudflare-dns.com/dns-query'
const USER_AGENT = `${pkg.name} v${pkg.version}`

/**
 * HTTPS Agent that logs to stdout certificate information from connections.
 *
 * @extends {https.Agent}
 * @private
 */
class CertAgent extends https.Agent {
  createConnection (options, cb) {
    const csi = options.checkServerIdentity
    options.checkServerIdentity = (name, cert) => {
      console.log('CERTIFICATE:', util.inspect(DNSutils.buffersToB64(cert), {
        depth: Infinity,
        colors: process.stdout.isTTY,
        sorted: true
      }))
      return (typeof csi === 'function')
        ? csi(name, cert)
        : tls.checkServerIdentity(name, cert)
    }
    return super.createConnection(options, cb)
  }

  static createAgent (parsedUrl) {
    return (parsedUrl.protocol === 'https:') ? new CertAgent() : undefined
  }
}

/**
 * Request DNS information over HTTPS.  The [lookup]{@link DNSoverHTTPS#lookup}
 * function provides the easiest-to-use defaults.
 */
class DNSoverHTTPS {
  /**
   * Create a DNSoverHTTPS instance
   *
   * @param {Object} opts - Options for all requests
   * @param {String} [opts.userAgent="packageName version"] - User Agent for HTTP request
   * @param {String} [opts.url="https://cloudflare-dns.com/dns-query"] - Base URL
   *   for all HTTP requests
   * @param {Boolean} [opts.preferPost=true] - Should POST be preferred to Get
   *   for DNS-format queries?
   * @param {Boolean} [opts.verbose=false] - Print bytes for DNS-style queries
   */
  constructor (opts = {}) {
    this.opts = Object.assign({
      userAgent: DNSoverHTTPS.userAgent,
      url: DNSoverHTTPS.url,
      preferPost: true,
      verbose: false
    }, opts)
  }

  /**
   * Get a DNS-format response.
   *
   * @param {Object} opts - Options for the request
   * @param {String} [opts.name] - The name to look up
   * @param {String} [opts.rrtype="A"] - The record type to look up
   * @param {Boolean} [opts.decode=true] - Parse the returned DNS packet?
   * @param {Boolean} [opts.dnssec=false] - Request DNSSec information?
   * @returns {Promise<Object|Buffer>} result
   */
  async getDNS (opts) {
    const pkt = DNSutils.makePacket(opts)
    let url = opts.url || this.opts.url
    let method = 'POST'
    let body = pkt
    let agent

    if (this.opts.verbose) {
      console.log('REQUEST:')
      DNSutils.hexDump(pkt)
      agent = CertAgent.createAgent
    }

    if (!this.opts.preferPost) {
      method = 'GET'
      url += `?dns=${DNSutils.base64urlEncode(pkt)}`
      body = undefined
    }
    const r = await fetch(url, {
      method,
      headers: {
        'Content-Type': WF_DNS,
        'User-Agent': this.userAgent,
        Accept: WF_DNS
      },
      body,
      agent
    })
    const response = await r.buffer()
    if (this.opts.verbose) {
      console.log('RESULT:')
      DNSutils.hexDump(response)
    }

    return opts.decode ? packet.decode(response) : response
  }

  /**
   * Make a HTTPS GET request for JSON DNS.
   *
   * @param {Object} opts - Options for the request
   * @param {String} [opts.name] - The name to look up
   * @param {String} [opts.rrtype="A"] - The record type to look up
   * @param {Boolean} [opts.decode=true] - Parse the returned JSON?
   * @returns {Promise<Object|String>} result
   */
  async getJSON (opts) {
    const rrtype = opts.rrtype || 'A'
    const agent = this.opts.verbose ? CertAgent.createAgent : undefined
    const r = await fetch(
      `${this.opts.url}?name=${opts.name}&type=${rrtype}`, {
        headers: {
          'User-Agent': this.userAgent,
          Accept: WF_JSON
        },
        agent
      })
    const decode = Object.prototype.hasOwnProperty.call(opts, 'decode')
      ? opts.decode
      : true
    return decode ? r.json() : r.text()
  }

  /**
   * Look up a DNS entry using DNS-over-HTTPS (DoH).
   *
   * @param {Object|String} name - The DNS name to look up, or opts if this is an object.
   * @param {Object|String} [opts={}] - Options for the request.  If a string
   *   is given, it will be used as the rrtype.
   * @param {String} [opts.name] - The DNS name to look up.
   * @param {String} [opts.rrtype='A'] The Resource Record type to retrive
   * @param {Boolean} [opts.json=true] Retrieve a JSON response.  If false,
   *   retrieve using DNS format.
   * @param {Boolean} [opts.decode=true] Decode the response, either into JSON
   *   or an object representing the DNS format result.
   * @param {Boolean} [opts.preferPost=true] For DNS format requests, should
   *   the HTTP POST verb be used?  If false, uses GET.
   * @param {Boolean} [opts.dnssec=false] Request DNSSec records.  Currently
   *   requires `json: false`
   * @param {String} [opts.url=CLOUDFLARE_API] What DoH endpoint should be used?
   * @returns {Promise<Object|Buffer|String>} result
   */
  lookup (name, opts = {}) {
    opts = DNSutils.normalizeArgs(name, opts, {
      rrtype: 'A',
      json: true,
      decode: true,
      dnssec: false
    })
    return opts.json ? this.getJSON(opts) : this.getDNS(opts)
  }
}

DNSoverHTTPS.version = pkg.version
DNSoverHTTPS.userAgent = USER_AGENT
DNSoverHTTPS.url = CLOUDFLARE_API
module.exports = DNSoverHTTPS
