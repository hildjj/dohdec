/// <reference types="node" />
export class DNSutils extends EventEmitter {
    /**
     * Encode a DNS query packet to a buffer.
     *
     * @param {object} opts Options for the query.
     * @param {number} [opts.id=0] ID for the query.  SHOULD be 0 for DOH.
     * @param {string} [opts.name] The name to look up.
     * @param {string} [opts.rrtype="A"] The record type to look up.
     * @param {boolean} [opts.dnssec=false] Request DNSSec information?
     * @param {string} [opts.ecsSubnet] Subnet to use for ECS.
     * @param {number} [opts.ecs] Number of ECS bits.  Defaults to 24 or 56
     *   (IPv4/IPv6).
     * @param {boolean} [opts.stream=false] Encode for streaming, with the packet
     *   prefixed by a 2-byte big-endian integer of the number of bytes in the
     *   packet.
     * @returns {Buffer} The encoded packet.
     */
    static makePacket(opts: {
        id?: number;
        name?: string;
        rrtype?: string;
        dnssec?: boolean;
        ecsSubnet?: string;
        ecs?: number;
        stream?: boolean;
    }): Buffer;
    /**
     * @typedef {object} LookupOptions
     * @property {string} [name] Name to look up.
     * @property {string} [rrtype] The Resource Record type to retrive.
     * @property {number} [id] The 2-byte unsigned integer for the request.
     *   For DOH, should be 0 or undefined.
     * @property {boolean} [json] Force JSON lookups for DOH.  Ignored for DOT.
     * @property {boolean} [stream=false] Encode for streaming, with the packet
     *   prefixed by a 2-byte big-endian integer of the number of bytes in the
     *   packet.
     */
    /**
     * Normalize parameters into the lookup functions.
     *
     * @param {string|LookupOptions} [name] If string, lookup this name,
     *   otherwise it is options.  Has precedence over opts.name if string.
     * @param {string|LookupOptions} [opts] If string, rrtype.
     *   Otherwise options.
     * @param {object} [defaults] Defaults options.
     * @returns {LookupOptions} Normalized options, including punycode∑d
     *   options.name and upper-case options.rrtype.
     * @throws {Error} Invalid type for name.
     */
    static normalizeArgs(name?: string | {
        /**
         * Name to look up.
         */
        name?: string;
        /**
         * The Resource Record type to retrive.
         */
        rrtype?: string;
        /**
         * The 2-byte unsigned integer for the request.
         * For DOH, should be 0 or undefined.
         */
        id?: number;
        /**
         * Force JSON lookups for DOH.  Ignored for DOT.
         */
        json?: boolean;
        /**
         * Encode for streaming, with the packet
         * prefixed by a 2-byte big-endian integer of the number of bytes in the
         * packet.
         */
        stream?: boolean;
    }, opts?: string | {
        /**
         * Name to look up.
         */
        name?: string;
        /**
         * The Resource Record type to retrive.
         */
        rrtype?: string;
        /**
         * The 2-byte unsigned integer for the request.
         * For DOH, should be 0 or undefined.
         */
        id?: number;
        /**
         * Force JSON lookups for DOH.  Ignored for DOT.
         */
        json?: boolean;
        /**
         * Encode for streaming, with the packet
         * prefixed by a 2-byte big-endian integer of the number of bytes in the
         * packet.
         */
        stream?: boolean;
    }, defaults?: object): {
        /**
         * Name to look up.
         */
        name?: string;
        /**
         * The Resource Record type to retrive.
         */
        rrtype?: string;
        /**
         * The 2-byte unsigned integer for the request.
         * For DOH, should be 0 or undefined.
         */
        id?: number;
        /**
         * Force JSON lookups for DOH.  Ignored for DOT.
         */
        json?: boolean;
        /**
         * Encode for streaming, with the packet
         * prefixed by a 2-byte big-endian integer of the number of bytes in the
         * packet.
         */
        stream?: boolean;
    };
    /**
     * See [RFC 4648]{@link https://tools.ietf.org/html/rfc4648#section-5}.
     *
     * @param {Buffer} buf Buffer to encode.
     * @returns {string} The base64url string.
     */
    static base64urlEncode(buf: Buffer): string;
    /**
     * Recursively traverse an object, turning all of its properties that have
     * Buffer values into base64 representations of the buffer.
     *
     * @param {any} o The object to traverse.
     * @param {WeakSet<object>} [circular] WeakMap to prevent circular
     *   dependencies.
     * @returns {any} The converted object.
     */
    static buffersToB64(o: any, circular?: WeakSet<object>): any;
    /**
     * Calculate the reverse name to look up for an IP address.
     *
     * @param {string} addr The IPv[46] address to reverse.
     * @returns {string} Address ending in .in-addr.arpa or .ip6.arpa.
     * @throws {Error} Invalid IP Address.
     */
    static reverse(addr: string): string;
    /**
     * Creates an instance of DNSutils.
     *
     * @param {object} [opts={}] Options.
     * @param {number} [opts.verbose=0] How verbose do you want your logging?
     * @param {Writable} [opts.verboseStream=process.stderr] Where to write
     *   verbose output.
     */
    constructor(opts?: {
        verbose?: number;
        verboseStream?: Writable;
    });
    _verbose: number;
    verboseStream: Writable | (NodeJS.WriteStream & {
        fd: 2;
    });
    /**
     * Output verbose logging information, if this.verbose is true.
     *
     * @param {number} level Print at this verbosity level or higher.
     * @param {any[]} args Same as onsole.log parameters.
     * @returns {boolean} True if output was written.
     */
    verbose(level: number, ...args: any[]): boolean;
    /**
     * Dump a nice hex representation of the given buffer to verboseStream,
     * if verbose is true.
     *
     * @param {number} level Print at this verbosity level or higher.
     * @param {Buffer} buf The buffer to dump.
     * @returns {boolean} True if output was written.
     */
    hexDump(level: number, buf: Buffer): boolean;
}
export class DNSError extends Error {
    static getError(pkt: any): DNSError;
    constructor(er: any, pkt: any);
    packet: any;
    code: string;
}
export default DNSutils;
import { EventEmitter } from "events";
import { Writable } from "stream";
import { Buffer } from "buffer";
