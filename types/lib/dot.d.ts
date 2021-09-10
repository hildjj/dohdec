/// <reference types="node" />
export = DNSoverTLS;
/**
 * Options for doing DOT lookups.
 *
 * @typedef {object} DOT_LookupOptions
 * @property {string} [name] The DNS name to look up.
 * @property {packet.RecordType} [rrtype='A'] The Resource Record type
 *   to retrive.
 * @property {number} [id] 2-byte ID for the DNS packet.  Defaults to random.
 * @property {boolean} [decode=true] Decode the response, either into JSON
 *   or an object representing the DNS format result.
 * @property {boolean} [dnssec=false] Request DNSSec records.  Currently
 *   requires `json: false`.
 */
/**
 * @callback pendingResolve
 * @param {Buffer|object} results The results of the DNS query.
 */
/**
 * @callback pendingError
 * @param {Error} error The error that occurred.
 */
/**
 * @typedef {object} Pending
 * @property {pendingResolve} resolve Callback for success.
 * @property {pendingError} reject Callback for error.
 * @property {DOT_LookupOptions} opts The original options for the request.
 */
/**
 * A class that manages a connection to a DNS-over-TLS server.  The first time
 * [lookup]{@link DNSoverTLS#lookup} is called, a connection will be created.
 * If that connection is timed out by the server, a new connection will be
 * created as needed.
 *
 * If you want to do certificate pinning, make sure that the `hash` and
 * `hashAlg` options are set correctly to a hash of the DER-encoded
 * certificate that the server will offer.
 */
declare class DNSoverTLS extends DNSutils {
    /**
     * Hash a certificate using the given algorithm.
     *
     * @param {Buffer|crypto.X509Certificate} cert The cert to hash.
     * @param {string} [hashAlg="sha256"] The hash algorithm to use.
     * @returns {string} Hex string.
     * @throws {Error} Unknown certificate type.
     */
    static hashCert(cert: Buffer | crypto.X509Certificate, hashAlg?: string): string;
    /**
     * Construct a new DNSoverTLS.
     *
     * @param {object} opts Options.
     * @param {string} [opts.host='1.1.1.1'] Server to connect to.
     * @param {number} [opts.port=853] TCP port number for server.
     * @param {string} [opts.hash] Hex-encoded hash of the DER-encoded cert
     *   expected from the server.  If not specified, no pinning checks are
     *   performed.
     * @param {string} [opts.hashAlg='sha256'] Hash algorithm for cert pinning.
     * @param {boolean} [opts.rejectUnauthorized=true] Should the server
     *   certificate even be checked using the normal TLS approach?
     * @param {boolean} [opts.verbose=false] Print bytes sent and received.
     * @param {Writable} [opts.verboseStream=process.stderr] Where to write
     *   verbose output.
     */
    constructor(opts?: {
        host?: string;
        port?: number;
        hash?: string;
        hashAlg?: string;
        rejectUnauthorized?: boolean;
        verbose?: boolean;
        verboseStream?: Writable;
    });
    opts: {
        host: string;
        port: number;
        hash?: string;
        hashAlg: string;
        rejectUnauthorized: boolean;
    };
    _reset(): void;
    size: number;
    /** @type {tls.TLSSocket} */
    socket: tls.TLSSocket;
    /** @type {Object.<number, Pending>} */ pending: {
        [x: number]: Pending;
    };
    /** @type {NoFilter} */
    nof: NoFilter;
    /** @type {Buffer[]} */
    bufs: Buffer[];
    /**
     * @returns {Promise<void>}
     * @private
     */
    private _connect;
    /**
     * Server socket was disconnected.  Clean up any pending requests.
     *
     * @private
     */
    private _disconnected;
    /**
     * Parse data if enough is available.
     *
     * @param {Buffer} b Data read from socket.
     * @private
     */
    private _data;
    /**
     * Generate a currently-unused random ID.
     *
     * @returns {Promise<number>} A random 2-byte ID number.
     * @private
     */
    private _id;
    /**
     * Look up a name in the DNS, over TLS.
     *
     * @param {DOT_LookupOptions|string} name The DNS name to look up, or opts
     *   if this is an object.
     * @param {DOT_LookupOptions|string} [opts={}] Options for the request.  If
     *   a string is given, it will be used as the rrtype.
     */
    lookup(name: string | DOT_LookupOptions, opts?: string | DOT_LookupOptions): Promise<any>;
    /**
     * Close the socket.
     *
     * @returns {Promise<void>} Resolved on socket close.
     */
    close(): Promise<void>;
}
declare namespace DNSoverTLS {
    export { DEFAULT_SERVER as server, DOT_LookupOptions, pendingResolve, pendingError, Pending };
}
import DNSutils = require("./dnsUtils");
import tls = require("tls");
type Pending = {
    /**
     * Callback for success.
     */
    resolve: pendingResolve;
    /**
     * Callback for error.
     */
    reject: pendingError;
    /**
     * The original options for the request.
     */
    opts: DOT_LookupOptions;
};
import NoFilter = require("nofilter");
import { Buffer } from "buffer";
/**
 * Options for doing DOT lookups.
 */
type DOT_LookupOptions = {
    /**
     * The DNS name to look up.
     */
    name?: string;
    /**
     * The Resource Record type
     * to retrive.
     */
    rrtype?: packet.RecordType;
    /**
     * 2-byte ID for the DNS packet.  Defaults to random.
     */
    id?: number;
    /**
     * Decode the response, either into JSON
     * or an object representing the DNS format result.
     */
    decode?: boolean;
    /**
     * Request DNSSec records.  Currently
     * requires `json: false`.
     */
    dnssec?: boolean;
};
import crypto = require("crypto");
import { Writable } from "stream";
declare const DEFAULT_SERVER: "1.1.1.1";
type pendingResolve = (results: Buffer | object) => any;
type pendingError = (error: Error) => any;
import packet = require("dns-packet");
