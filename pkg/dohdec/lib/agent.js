
// Everything in this file is a hack to extract the Undici Agent class from
// the internals of node.js.  Works in Node 20, 22, and 24 at

const UNDICI_GLOBAL_DISPATCHER = 'undici.globalDispatcher.1';
const unidiciGlobalDispatcherSymbol = Symbol.for(UNDICI_GLOBAL_DISPATCHER);

// Have to call fetch once to pre-load the undici Agent class.
// eslint-disable-next-line n/no-top-level-await
await fetch('').catch(() => {
  // Ignore.
});

/** @import {Agent as UAgent} from  'undici-types' */
/**
 * @typedef {{readonly [unidiciGlobalDispatcherSymbol]: UAgent}} DispatchGlobal
 */
const undiciGlobalDispatcher =
  /** @type {DispatchGlobal & typeof globalThis} */(globalThis)[
    unidiciGlobalDispatcherSymbol
  ];

export const Agent =
  /** @type {typeof UAgent} */ (undiciGlobalDispatcher.constructor);
