/// <reference types="node" />
/**
 * @typedef {object} Stdio
 * @property {stream.Readable} [in] StdIn.
 * @property {stream.Writable} [out] StdOut.
 * @property {stream.Writable} [err] StdErr.
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
     * @param {Stdio} [stdio] Replacement streams for stdio, for testing.
     */
    constructor(args: string[], stdio?: Stdio);
    /** @type {DNSoverHTTPS|DNSoverTLS} */
    transport: DNSoverHTTPS | DNSoverTLS;
    /** @type {Stdio} */
    std: Stdio;
    argv: import("commander").OptionValues;
    /**
     * Run the CLI.
     */
    main(): Promise<void>;
    get(name: any, rrtype: any): Promise<void>;
    prompt(): Promise<number[]>;
}
export type Stdio = {
    /**
     * StdIn.
     */
    in?: stream.Readable;
    /**
     * StdOut.
     */
    out?: stream.Writable;
    /**
     * StdErr.
     */
    err?: stream.Writable;
};
import { Command } from "commander";
import { DNSoverHTTPS } from "../lib/index.js";
import { DNSoverTLS } from "../lib/index.js";
import stream from "stream";
