import {Agent} from '../lib/agent.js';
import test from 'ava';

test('agent', t => {
  t.is(typeof Agent, 'function');

  const a = new Agent({
    closed: false,
  });
  t.is(typeof a, 'object');
});

test('fetch', async t => {
  const res = await fetch('https://self-signed.badssl.com/', {
    dispatcher: new Agent({
      connect: {
        rejectUnauthorized: false,
      },
    }),
  });
  t.truthy(res);
  t.truthy(res.ok);
});
