import {Transform} from 'node:stream';
import path from 'node:path';
import url from 'node:url';

export class Buf extends Transform {
  constructor(opts = {}) {
    const {errorToThrow, ...others} = opts;
    super(others);
    this.errorToThrow = errorToThrow;
  }

  _transform(chunk, encoding, cb) {
    if (this.errorToThrow) {
      cb(this.errorToThrow);
    } else {
      this.push(chunk, encoding);
      cb();
    }
  }

  static from(str) {
    return new Buf().end(str);
  }
}

/**
 * Prepare the test environment for using nock.
 *
 * @param {any} test The AVA test suite.
 * @param {any} nock The nock instance.
 * @param {URL} metaUrl The import.meta.url of the calling module.
 */
export function prepNock(test, nock, metaUrl) {
  test.before(async t => {
    nock.back.fixtures = url.fileURLToPath(new URL('fixtures/', metaUrl));
    if (!process.env.NOCK_BACK_MODE) {
      nock.back.setMode('lockdown');
    }

    const title = escape(path.basename(url.fileURLToPath(metaUrl)));
    const {nockDone, context} = await nock.back(`${title}.json`, {
      before(scope) {
        // Strip off padding when checking for a path match
        scope.filteringPath = p => p.replace(/&random_padding=.*/, '&random_padding=0');
      },
      afterRecord(scopes) {
        for (const scope of scopes) {
          // Strip off padding when saving recording
          scope.path = scope.path.replace(/&random_padding=.*/, '&random_padding=0');
        }
        return scopes;
      },
    });
    if (context.scopes.length === 0) {
      // Set the NOCK_BACK_MODE variable to "record" when needed
      if (nock.back.currentMode !== 'record') {
        // eslint-disable-next-line no-console
        console.error(`WARNING: Nock recording needed for "${title}".
  Set NOCK_BACK_MODE=record`);
      }
    }
    t.context.nockDone = nockDone;

    if (nock.back.currentMode === 'record') {
      nock.enableNetConnect();
    } else {
      nock.disableNetConnect();
    }
  });

  test.after(t => {
    t.truthy(nock.isDone(), 'Ingore error if running selected tests');
  });

  test.after.always(t => {
    // Ensure recording gets written, even if the tests don't all pass.
    // For example, TTLs might need to be tweaked.
    t.context.nockDone();
  });
}
