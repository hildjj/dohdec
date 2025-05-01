import {Command, InvalidArgumentError} from 'commander';
import {DNSError, DNSoverHTTPS, DNSoverTLS, DNSutils} from 'dohdec';
import {Buffer} from 'node:buffer';
import assert from 'node:assert';
import net from 'node:net';
import readline from 'node:readline';
import util from 'node:util';

/**
 * Parse an int or throw if invalid.
 *
 * @param {string} value Command line value.
 * @returns {number} Parsed value.
 * @throws {InvalidArgumentError} Invalid number format.
 * @private
 */
function myParseInt(value) {
  const parsedValue = parseInt(value, 10);
  if (isNaN(parsedValue)) {
    throw new InvalidArgumentError('Bad number');
  }
  return parsedValue;
}

/**
 * @param {any} pkt
 * @returns {asserts pkt is import('dns-packet').Packet}
 * @private
 */
function assertIsPacket(pkt) {
  assert(pkt);
  assert(typeof pkt === 'object');
  assert(!Buffer.isBuffer(pkt));
  assert(!Array.isArray(pkt));
}

/**
 * @param {any} er
 * @returns {asserts er is Error}
 */
function assertIsError(er) {
  assert(er);
  assert(typeof er === 'object');
  assert(Object.prototype.hasOwnProperty.call(er, 'message'));
}

/**
 * Parse an IPv4/IPv6 address or throw if invalid.
 *
 * @param {string} value Command line value.
 * @returns {string} Parsed value.
 * @throws {InvalidArgumentError} Invalid address format.
 * @private
 */
function checkAddress(value) {
  const family = net.isIP(value);
  if (family === 0) {
    throw new InvalidArgumentError('Invalid IPv[46] address');
  }
  return value;
}

/**
 * @typedef {object} Stdio
 * @property {import('stream').Readable} [in] StdIn.
 * @property {import('stream').Writable} [out] StdOut.
 * @property {import('stream').Writable} [err] StdErr.
 */

/**
 * @typedef {object} HelpWidth
 * @property {number} [helpWidth] Width of help, in columns, for testing.
 */

/**
 * Command Line Interface for dohdec.
 */
export class DnsCli extends Command {
  /**
   * Create a CLI environment.
   *
   * @param {string[]} args Arguments from the command line
   *   (usually process.argv).
   * @param {Stdio & HelpWidth} [stdio] Replacement streams for stdio,
   *   for testing.
   */
  constructor(args, stdio) {
    super();

    /** @type {DNSoverHTTPS|DNSoverTLS|undefined} */
    this.transport = undefined;

    /** @type {Required<Stdio>} */
    this.std = {
      in: process.stdin,
      out: process.stdout,
      err: process.stderr,
      ...stdio,
    };

    this
      .configureOutput({
        writeOut: c => this.std.out.write(c),
        writeErr: c => this.std.err.write(c),
      });
    if (stdio?.helpWidth) {
      this.configureHelp({helpWidth: stdio.helpWidth});
    }
    this
      .version(DNSoverHTTPS.version)
      .argument('[name]', 'DNS name to look up (e.g. domain name) or IP address to reverse lookup.  If not specified, a read-execute-print loop (REPL) is started.')
      .argument('[rrtype]', 'Resource record name or number', 'A')
      .option(
        '-c, --contentType <type>',
        'MIME type for POST',
        'application/dns-message'
      )
      .option('-d, --dns', 'Use DNS format instead of JSON (ignored for TLS)')
      .option('-s, --dnssec', 'Request DNSsec records')
      .option('-k, --dnssecCheckingDisabled', 'Disable DNSsec validation')
      .option(
        '-e, --ecs <number>',
        'Use this many bits for EDNS Client Subnet (ECS)',
        myParseInt
      )
      .option(
        '-b, --ecsSubnet <address>',
        'Use this IP address for EDNS Client Subnet (ECS)',
        checkAddress
      )
      .option('-f, --full', 'Full response, not just answers')
      .option('-g, --get', 'Force http GET for DNS-format lookups')
      .option('-n, --no-decode', 'Do not decode JSON or DNS wire format')
      .option('-2, --no-http2', 'Disable http2 support')
      .option('-t, --tls', 'Use DNS-over-TLS instead of DNS-over-HTTPS')
      .option(
        '-i, --tlsServer <serverIP>',
        'Connect to this DNS-over-TLS server',
        '1.1.1.1'
      )
      .option(
        '-p, --tlsPort <number>',
        'Connect to this TCP port for DNS-over-TLS',
        myParseInt,
        853
      )
      .option(
        '-u, --url <URL>',
        'The URL of the DoH service',
        DNSoverHTTPS.defaultURL
      )
      .option(
        '-v, --verbose',
        'Increase verbosity of debug information.  May be specified multiple times.',
        (_, prev) => prev + 1,
        0
      )
      .addHelpText('after', `
For more debug information:

  $ NODE_DEBUG=http,https,http2 dohdec -v [arguments]`);
    // END CLI CONFIG

    if (stdio && (Object.keys(stdio).length > 0)) {
      this.exitOverride();
    }

    this.argv = this.parse(args).opts();
    this.argv.name = this.args.shift();
    this.argv.rrtype = this.args.shift();

    this.transport = this.argv.tls ?
      new DNSoverTLS({
        host: this.argv.tlsServer,
        port: this.argv.tlsPort,
        verbose: this.argv.verbose,
        verboseStream: this.std.err,
      }) :
      new DNSoverHTTPS({
        contentType: this.argv.contentType,
        http2: this.argv.http2,
        preferPost: !this.argv.get,
        url: this.argv.url,
        verbose: this.argv.verbose,
        verboseStream: this.std.err,
      });
    this.transport.verbose(1, 'DnsCli options:', this.argv);
  }

  /**
   * Run the CLI.
   */
  async main() {
    assert(this.transport);
    try {
      if (this.argv.name) {
        await this.get(this.argv.name, this.argv.rrtype);
      } else {
        const [errors, total] = await this.prompt();
        this.transport.verbose(0, `\n${errors}/${total} error${total === 1 ? '' : 's'}`);
      }
    } finally {
      this.transport.close();
    }
  }

  /**
   * @param {string} name
   * @param {import('dns-packet').RecordType} rrtype
   */
  async get(name, rrtype) {
    const opts = {
      name,
      rrtype,
      json: !this.argv.dns,
      decode: this.argv.decode,
      ecsSubnet: this.argv.ecsSubnet,
      ecs: this.argv.ecs,
      dnssec: this.argv.dnssec,
      dnssecCheckingDisabled: this.argv.dnssecCheckingDisabled,
    };
    assert(this.transport);
    try {
      if (net.isIP(opts.name)) {
        opts.name = DNSutils.reverse(opts.name);
        if (!opts.rrtype) {
          opts.rrtype = 'PTR';
        }
      }
      let resp = await this.transport.lookup(opts);
      if (this.argv.decode) {
        if (!this.argv.full) {
          assertIsPacket(resp);
          const er = DNSError.getError(resp);
          if (er) {
            // This isn't ideal, since a) this is normal operation and
            // b) we're just going to re-raise the error below.  However,
            // this turned out to be easier to test.
            throw er;
          }
          resp =
            resp.answers ||
            /** @type {Record<string, any>}*/ (resp).Answer ||
            resp;
        }
        this.std.out.write(util.inspect(DNSutils.buffersToB64(resp), {
          depth: Infinity,
          // @ts-ignore TS2339: It's too hard to make this work correctly.
          colors: this.std.out.isTTY,
        }));
        this.std.out.write('\n');
      } else {
        this.std.out.write(resp);
        if (!this.argv.dns && !this.argv.tls) {
          this.std.out.write('\n');
        }
      }
    } catch (er) {
      assertIsError(er);
      this.transport.verbose(1, er) ||
      this.transport.verbose(0, () => (er.message ? er.message : er));
      throw er;
    }
  }

  async prompt() {
    assert(this.transport);

    let errors = 0;
    let total = 0;
    const rl = readline.createInterface({
      input: this.std.in,
      output: this.std.out,
      prompt: 'domain (rrtype)> ',
    });
    rl.prompt();
    for await (const line of rl) {
      this.transport.verbose(1, 'LINE', line);
      if (line.length > 0) {
        total++;
        try {
          const [name, rrtype] = line.split(/\s+/);
          await this.get(
            name,
            /** @type {import('dns-packet').RecordType} */(rrtype)
          );
        } catch (ignored) {
          // Catches all errors.  get() printed them already
          errors++;
        }
      }
      rl.prompt();
    }
    return [errors, total];
  }
}
