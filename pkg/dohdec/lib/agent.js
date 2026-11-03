
// Everything in this file is a hack to extract the Undici Agent class from
// the internals of node.js.  Works in Node 20, 22, and 24 at

const UNDICI_GLOBAL_DISPATCHER_1 = 'undici.globalDispatcher.1';
const UNDICI_GLOBAL_DISPATCHER_2 = 'undici.globalDispatcher.2';

const unidiciGlobalDispatcherSymbol_1 = Symbol.for(UNDICI_GLOBAL_DISPATCHER_1);
const unidiciGlobalDispatcherSymbol_2 = Symbol.for(UNDICI_GLOBAL_DISPATCHER_2);

// Have to call fetch once to pre-load the undici Agent class.
globalThis.fetch('').catch(() => {
  // Ignore.
});

/** @import {Agent as UAgent} from  'undici-types' */

const gthis = /** @type {DispatchGlobal & typeof globalThis} */(globalThis);

/**
 * @typedef {{readonly [unidiciGlobalDispatcherSymbol_2]: UAgent,
 *   readonly [unidiciGlobalDispatcherSymbol_1]: UAgent}} DispatchGlobal
 */
const undiciGlobalDispatcher =
  gthis[unidiciGlobalDispatcherSymbol_2] ??
  gthis[unidiciGlobalDispatcherSymbol_1];

export const Agent =
  /** @type {typeof UAgent} */ (undiciGlobalDispatcher.constructor);
