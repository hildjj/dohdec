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
export class DNSoverHTTPS extends DNSutils {
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
    constructor(opts?: {
        userAgent?: string;
        url?: string;
        preferPost?: boolean;
        contentType?: string;
        verbose?: boolean;
        verboseStream?: Writable;
    });
    opts: {
        userAgent: string;
        url: string;
        preferPost: boolean;
        contentType: string;
    };
    /**
     * @private
     * @ignore
     */
    private _checkServerIdentity;
    /**
     * Get a DNS-format response.
     *
     * @param {DOH_LookupOptions} opts Options for the request.
     * @returns {Promise<Buffer|object>} DNS result.
     */
    getDNS(opts: DOH_LookupOptions): Promise<Buffer | object>;
    /**
     * Make a HTTPS GET request for JSON DNS.
     *
     * @param {object} opts Options for the request.
     * @param {string} [opts.name] The name to look up.
     * @param {packet.RecordType} [opts.rrtype="A"] The record type to look up.
     * @param {boolean} [opts.decode=true] Parse the returned JSON?
     * @returns {Promise<string|object>} DNS result.
     */
    getJSON(opts: {
        name?: string;
        rrtype?: packet.RecordType;
        decode?: boolean;
    }): Promise<string | object>;
    /**
     * Look up a DNS entry using DNS-over-HTTPS (DoH).
     *
     * @param {object|DOH_LookupOptions} name The DNS name to look up, or opts
     *   if this is an object.
     * @param {DOH_LookupOptions|packet.RecordType} [opts={}] Options for the
     *   request.  If a string is given, it will be used as the rrtype.
     * @returns {Promise<Buffer|string|object>} DNS result.
     */
    lookup(name: object | DOH_LookupOptions, opts?: packet.RecordType | DOH_LookupOptions): Promise<Buffer | string | object>;
}
export namespace DNSoverHTTPS {
    const version: string;
    const userAgent: string;
    const defaultURL: string;
}
export default DNSoverHTTPS;
/**
 * Options for doing DOH lookups.
 */
export type DOH_LookupOptions = {
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
     * Retrieve a JSON response.  If false,
     * retrieve using DNS format.
     */
    json?: boolean;
    /**
     * Decode the response, either into JSON
     * or an object representing the DNS format result.
     */
    decode?: boolean;
    /**
     * For DNS format requests, should
     * the HTTP POST verb be used?  If false, uses GET.
     */
    preferPost?: boolean;
    /**
     * Request DNSSec records.  Currently
     * requires `json: false`.
     */
    dnssec?: boolean;
    /**
     * What DoH endpoint should be
     * used?
     */
    url?: string;
};
import DNSutils from "./dnsUtils.js";
import * as packet from "dns-packet";
import { Writable } from "stream";
