#!/usr/bin/env node

import { DNSoverHTTPS, DNSoverTLS } from '../lib/index.js'
import DNSutils from '../lib/dnsUtils.js'
import { hideBin } from 'yargs/helpers'
import readline from 'readline'
import util from 'util'
import yargs from 'yargs'

const argv = yargs()
  .version(DNSoverHTTPS.version)
  .usage('$0 [name] [rrtype]', 'Look up DNS name using DNS-over-HTTPS (DoH)', y => {
    y.positional('name', {
      desc: 'The name to look up.  If not specified, use a readline loop to look up multiple names.',
      type: 'string',
    })
    y.positional('rrtype', {
      desc: 'Resource Record type to look up',
      default: 'A',
      type: 'string',
    })
  })
  .alias('h', 'help')
  .options({
    contentType: {
      desc: 'MIME type for POST',
      alias: 'c',
      default: 'application/dns-message',
    },
    dns: {
      desc: 'Use DNS format instead of JSON',
      alias: 'd',
      boolean: true,
    },
    dnssec: {
      alias: 's',
      desc: 'Request DNSsec records',
      boolean: true,
    },
    ecs: {
      desc: 'Use this many bits for EDNS Client Subnet (ECS)',
      alias: 'e',
      number: true,
    },
    ecsSubnet: {
      desc: 'Use this IP address for EDNS Client Subnet (ECS)',
      alias: 'b',
      string: true,
    },
    full: {
      desc: 'Full response, not just answers',
      alias: 'f',
      boolean: true,
    },
    get: {
      desc: 'Force http GET for DNS-format lookups',
      alias: 'g',
      boolean: true,
    },
    'no-decode': {
      alias: 'n',
      desc: 'Do not decode JSON or DNS wire format',
      boolean: true,
    },
    'no-http2': {
      desc: 'Disable http2 support',
      alias: '2',
      boolean: true,
    },
    tls: {
      desc: 'Use DNS-over-TLS instead of DNS-over-HTTPS',
      alias: 't',
      boolean: true,
    },
    tlsServer: {
      desc: 'Connect to this DNS-over-TLS server',
      alias: 'i',
      default: DNSoverTLS.server,
    },
    tlsPort: {
      desc: 'Connect to this TCP port for DNS-over-TLS',
      alias: 'p',
      default: 853,
    },
    url: {
      desc: 'The URL of the DoH service',
      alias: 'u',
      default: DNSoverHTTPS.defaultURL,
      string: true,
      requiresArg: true,
    },
    verbose: {
      desc: 'Print debug info',
      alias: 'v',
      count: true,
    },
  })
  .epilog(`\
For more debug information:

  $ NODE_DEBUG=http,https,http2 dohdec -v [arguments]`)
  .parse(hideBin(process.argv))

async function get(over, name, rrtype) {
  const opts = {
    name,
    rrtype,
    json: !argv.dns,
    decode: !argv.noDecode,
    ecsSubnet: argv.ecsSubnet,
    ecs: argv.ecs,
    dnssec: argv.dnssec,
  }
  let resp = await over.lookup(opts)
  if (argv.noDecode) {
    process.stdout.write(resp)
    if (!argv.dns) {
      process.stdout.write('\n')
    }
  } else {
    if (!argv.full) {
      if (Object.prototype.hasOwnProperty.call(resp, 'rcode')) {
        if (resp.rcode !== 'NOERROR') {
          console.log(resp.rcode)
          return
        }
      } else if (Object.prototype.hasOwnProperty.call(resp, 'Status')) {
        if (resp.Status !== 0) {
          console.log(`Error: ${resp.Status}`)
          return
        }
      }
      resp = resp.answers || resp.Answer || resp
    }
    console.log(util.inspect(DNSutils.buffersToB64(resp), {
      depth: Infinity,
      colors: process.stdout.isTTY,
    }))
  }
}

function create() {
  return argv.tls ?
    new DNSoverTLS({
      host: argv.tlsServer,
      port: argv.tlsPort,
      verbose: argv.verbose,
      http2: !argv.noHttp2,
    }) :
    new DNSoverHTTPS({
      url: argv.url,
      preferPost: !argv.get,
      verbose: argv.verbose,
      contentType: argv.contentType,
      http2: !argv.noHttp2,
    })
}

function lookup() {
  const over = create()
  return get(over, argv.name, argv.rrtype).then(() => {
    if (typeof over.close === 'function') {
      over.close()
    }
  }, er => {
    if (argv.verbose > 0) {
      console.error(er)
    } else {
      console.error(er.message ? er.message : er)
    }
    process.exit(1)
  })
}

function prompt() {
  const over = create()
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'domain (rrtype)> ',
  })
  rl.on('line', async line => {
    if (line.length === 0) {
      return
    }
    try {
      await get(over, ...line.split(/\s+/))
    } catch (e) {
      console.log(e.message || e)
      process.exit(1)
    }
    rl.prompt()
  })
  rl.on('close', () => {
    if (typeof over.close === 'function') {
      over.close()
    }
  })
  rl.prompt()
}

function main() {
  if (argv.name) {
    return lookup()
  }
  return prompt()
}

main()
