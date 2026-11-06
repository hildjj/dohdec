/**
 * @typedef {import('./tcp.js').TCPoptions} TCPoptions
 */

/**
 * @typedef {import('./udp.js').UDPoptions} UDPoptions
 */

/**
 * @typedef {import('./udp.js').ConnectOptions} ConnectOptions
 */

export {DNSoverHTTPS} from './doh.js';
export {DNSoverTLS} from './dot.js';
export {DNSoverTCP} from './tcp.js';
export {DNSoverUDP} from './udp.js';
export {DNSError, DNSutils} from './dnsUtils.js';
