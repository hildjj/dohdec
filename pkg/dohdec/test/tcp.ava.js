import {DNSoverTCP} from '../lib/tcp.js';
import test from 'ava';

test('tcp', async t => {
  const tcp = new DNSoverTCP();
  // eslint-disable-next-line ava/assertion-arguments
  tcp.on('error', er => t.fail(String(er)));
  const pkt = await tcp.lookup('ietf.org', 'MX');
  t.assert(pkt?.answers);
  t.assert(pkt.answers.length > 0);
  for (const a of pkt.answers) {
    t.is(a.type, 'MX');
  }
  t.assert(await tcp.lookup('ietf.org', 'AAAA'));
  await tcp.close();
});
