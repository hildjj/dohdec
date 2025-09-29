import {DNSoverUDP} from '../lib/udp.js';
import test from 'ava';

test('udp4', async t => {
  const udp = new DNSoverUDP();
  // eslint-disable-next-line ava/assertion-arguments
  udp.on('error', er => t.fail(String(er)));
  const pkt = await udp.lookup('ietf.org', 'MX');
  t.assert(pkt?.answers);
  t.assert(pkt.answers.length > 0);
  for (const a of pkt.answers) {
    t.is(a.type, 'MX');
  }
  t.assert(await udp.lookup('ietf.org', 'AAAA'));
  await udp.close();
});

test('udp6', async t => {
  const udp = new DNSoverUDP({host: '2606:4700:4700::1111'});
  // eslint-disable-next-line ava/assertion-arguments
  udp.on('error', er => t.fail(String(er)));
  const pkt = await udp.lookup('ietf.org', 'MX');
  t.assert(pkt?.answers);
  t.assert(pkt.answers.length > 0);
  for (const a of pkt.answers) {
    t.is(a.type, 'MX');
  }
  t.assert(await udp.lookup('ietf.org', 'AAAA'));
  await udp.close();
});

test('udp errors', async t => {
  const badHost = new DNSoverUDP({host: 'foo'});
  await t.throwsAsync(() => badHost.lookup('ietf.org'));
  await badHost.close();
  const badPort = new DNSoverUDP({host: '::1', port: -1});
  await t.throwsAsync(() => badPort.lookup('ietf.org'));
});

test('AbortController', async t => {
  const aco = new AbortController();
  const ac = new AbortController();
  const udp = new DNSoverUDP({host: '127.0.0.1', signal: aco.signal});

  const p = udp.lookup({name: 'ietf.org', signal: ac.signal});
  setTimeout(() => {
    ac.abort();
  }, 50);
  await t.throwsAsync(() => p);

  // Shutdown is proof this worked.
  aco.abort();
});
