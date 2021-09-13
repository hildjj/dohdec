#!/usr/bin/env node

import { DNSoverHTTPS, DNSoverTLS } from '../lib/index.js'
import DNSutils from '../lib/dnsUtils.js'
import { fork } from 'child_process'
import { hideBin } from 'yargs/helpers'
import url from 'url'
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
    subnet: {
      desc: 'Use this IP address for EDNS Client Subnet (ECS)',
      alias: 'b',
      string: true,
    },
    ecs: {
      desc: 'Use this many bits for EDNS Client Subnet (ECS)',
      alias: 'e',
      number: true,
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
    dnssec: {
      alias: 's',
      desc: 'Request DNSsec records',
      boolean: true,
    },
    url: {
      desc: 'The URL of the DoH service',
      alias: 'u',
      default: DNSoverHTTPS.defaultURL,
      string: true,
      requiresArg: true,
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
    verbose: {
      desc: 'Print debug info',
      alias: 'v',
      boolean: true,
    },
    INTERNAL_VERBOSE: {
      boolean: true,
      hidden: true,
    },
  })
  .parse(hideBin(process.argv))

async function get(over, name, rrtype) {
  const opts = {
    name,
    rrtype,
    json: !argv.dns,
    decode: !argv.noDecode,
    subnet: argv.subnet,
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

(() => {
  if (argv.verbose) {
    // HACK: i'm not proud of this.
    // Restart with NODE_DEBUG=http and --INTERNAL_VERBOSE
    if (!argv.tls &&
      (!process.env.NODE_DEBUG || (process.env.NODE_DEBUG.indexOf('http') >= 0))) {
      const newArgs = process.argv
        .filter(a => (a !== '-v') && (a !== '--verbose'))
        .map(a => a.replace(/^-(?<opt>[^-]*)v/, '-$<opt>')) // If run as "dohdec -tvs"
      newArgs.splice(2, 0, '--INTERNAL_VERBOSE')
      process.env.NODE_DEBUG = 'http'
      const cp = fork(url.fileURLToPath(import.meta.url), newArgs.slice(2), {
        env: process.env,
        stdio: [0, 1, 2, 'ipc'],
      })
      cp.on('exit', code => process.exit(code))
      return
    }
  }

  const over = argv.tls ?
    new DNSoverTLS({
      host: argv.tlsServer,
      port: argv.tlsPort,
      verbose: argv.verbose,
    }) :
    new DNSoverHTTPS({
      url: argv.url,
      preferPost: !argv.get,
      verbose: argv.INTERNAL_VERBOSE,
      contentType: argv.contentType,
    })

  if (argv.name) {
    get(over, argv.name, argv.rrtype).then(() => {
      if (typeof over.close === 'function') {
        over.close()
      }
    }, er => {
      console.error(er.message ? er.message : er)
      process.exit(1)
    })
  } else {
    const readline = require('readline')
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
})()
