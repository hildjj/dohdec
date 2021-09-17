import { DNSoverHTTPS, DNSoverTLS } from '../lib/index.js'
import DNSutils from '../lib/dnsUtils.js'
import { hideBin } from 'yargs/helpers'
import readline from 'readline'
import util from 'util'
import yargs from 'yargs'

export class DnsCli {
  constructor() {
    this.in = process.stdin
    this.out = process.stdout
    this.err = process.stderr

    this.yargs = yargs()
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
      .scriptName('dohdec')
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
  }

  parse(args, cb) {
    this.argv = this.yargs.parse(args ? args : hideBin(process.argv), cb)
    return this
  }

  main(args) {
    if (this.argv.name) {
      return this.lookup()
    }
    return this.prompt()
  }

  createOver() {
    return this.argv.tls ?
      new DNSoverTLS({
        host: this.argv.tlsServer,
        port: this.argv.tlsPort,
        verbose: this.argv.verbose,
        http2: !this.argv.noHttp2,
      }) :
      new DNSoverHTTPS({
        url: this.argv.url,
        preferPost: !this.argv.get,
        verbose: this.argv.verbose,
        contentType: this.argv.contentType,
        http2: !this.argv.noHttp2,
      })
  }

  lookup() {
    const over = this.createOver()
    return this.get(over, this.argv.name, this.argv.rrtype).then(() => {
      if (typeof over.close === 'function') {
        over.close()
      }
    })
  }

  async get(over, name, rrtype) {
    const opts = {
      name,
      rrtype,
      json: !this.argv.dns,
      decode: !this.argv.noDecode,
      ecsSubnet: this.argv.ecsSubnet,
      ecs: this.argv.ecs,
      dnssec: this.argv.dnssec,
    }
    let resp = await over.lookup(opts)
    if (this.argv.noDecode) {
      this.out.write(resp)
      if (!this.argv.dns) {
        this.out.write('\n')
      }
    } else {
      if (!this.argv.full) {
        if (Object.prototype.hasOwnProperty.call(resp, 'rcode')) {
          if (resp.rcode !== 'NOERROR') {
            this.out.write(`${resp.rcode}\n`)
            return
          }
        } else if (Object.prototype.hasOwnProperty.call(resp, 'Status')) {
          if (resp.Status !== 0) {
            this.out.write(`Error: ${resp.Status}\n`)
            return
          }
        }
        resp = resp.answers || resp.Answer || resp
      }
      this.out.write(util.inspect(DNSutils.buffersToB64(resp), {
        depth: Infinity,
        colors: this.out.isTTY,
      }))
      this.out.write('\n')
    }
  }

  prompt() {
    const over = this.createOver()
    const rl = readline.createInterface({
      input: this.in,
      output: this.out,
      prompt: 'domain (rrtype)> ',
    })
    rl.on('line', async line => {
      if (line.length === 0) {
        return
      }
      try {
        await this.get(over, ...line.split(/\s+/))
      } catch (e) {
        this.err.write(e.message || e)
        this.err.write('\n')
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
}
