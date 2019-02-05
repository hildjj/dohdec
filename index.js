'use strict'

const qs = require('querystring')
const fetch = require('node-fetch')
const packet = require('dns-packet')
const pkg = require('./package.json')

const WF_DNS = 'application/dns-udpwireformat'
const WF_JSON = 'application/dns-json'
const CLOUDFLARE_API = 'https://cloudflare-dns.com/dns-query'
const USER_AGENT = `${pkg.name} v${pkg.version}`

async function postDNS (url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': WF_DNS,
      'Accept': WF_DNS,
      'User-Agent': USER_AGENT
    },
    body
  })
  return r.buffer()
}

function base64urlEncode (buf) {
  const s = buf.toString('base64')
  return s.replace(/[=+/]/g, c => {
    switch (c) {
      case '=': return ''
      case '+': return '-'
      case '/': return '_'
    }
  })
}

async function getDNS (url, body) {
  body = base64urlEncode(body)
  const r = await fetch(`${url}?dns=${body}`, {
    headers: {
      'Accept': WF_DNS,
      'User-Agent': USER_AGENT
    }
  })
  return r.buffer()
}

async function requestDNS (opts) {
  const dns = {
    type: 'query',
    id: 0, // by spec, for cacheability
    flags: packet.RECURSION_DESIRED,
    questions: [{
      type: opts.rrtype,
      class: 'IN',
      name: opts.name
    }],
    additionals: [{
      name: '.',
      type: 'OPT',
      udpPayloadSize: 4096,
      flags: 0
    }]
  }
  if (opts.dnssec) {
    dns.flags |= packet.AUTHENTIC_DATA
    dns.additionals[0].flags |= packet.DNSSEC_OK
  }
  const pkt = packet.encode(dns)
  const method = opts.preferPost ? postDNS : getDNS
  const response = await method(opts.url, pkt)
  return opts.decode ? packet.decode(response) : response
}

async function getJSON (opts) {
  const r = await fetch(
    `${opts.url}?name=${opts.name}&type=${opts.rrtype}`, {
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': WF_JSON
      }
    })
  return opts.decode ? r.json() : r.text()
}

/**
 * Look up a DNS entry using DNS-over-HTTPS (DoH).
 *
 * @param {String} name The DNS name to look up
 * @param {Object|String} [opts={}] Options for the request.  If a string
 *   is given, it will be used as the rrtype.
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
 * @returns {Promise<Object|Buffer>} result
 */
function lookup (name, opts = {}) {
  if (typeof opts === 'string') {
    opts = {
      rrtype: opts
    }
  }
  opts = Object.assign({}, {
    rrtype: 'A',
    json: true,
    decode: true,
    preferPost: true,
    url: lookup.url,
    dnssec: false,
    name: qs.escape(name)
  }, opts)
  opts.rrtype = opts.rrtype.toUpperCase()
  return opts.json ? getJSON(opts) : requestDNS(opts)
}
lookup.version = pkg.version
lookup.url = CLOUDFLARE_API
module.exports = lookup
