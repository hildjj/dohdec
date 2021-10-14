/**
 * Create a mock DNS server.
 *
 * @param {object} [options] Any options for mock-tls-server.  Port defaults
 *   to 853.
 * @returns {MockTLSServer} The created server, already listening.
 */
export function createServer(options?: object): MockTLSServer;
import { MockTLSServer } from "mock-tls-server";
export { connect, plainConnect } from "mock-tls-server";
