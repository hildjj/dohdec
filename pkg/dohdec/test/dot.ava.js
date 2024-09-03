import {createServer, plainConnect} from 'mock-dns-server';
import {Buffer} from 'node:buffer';
import {DNSoverTLS} from '../lib/dot.js';
import crypto from 'node:crypto';
import test from 'ava';

const mockServer = createServer();
function create(cliOpts, duplexOpts) {
  const socket = plainConnect({
    port: mockServer.port,
    ...duplexOpts,
  });
  return new DNSoverTLS({
    socket,
    ca: mockServer.ca,
    host: 'localhost',
    ...cliOpts,
  });
}

test('lookup', async t => {
  const dot = create();
  const res = await dot.lookup('ietf.org');
  const [{name, type, data}] = res.answers;
  t.is(name, 'ietf.org');
  t.is(type, 'A');
  t.is(data, '4.31.198.44');
  const srv = await dot.lookup('_xmpp-server._tcp.jabber.org', 'srv');
  t.deepEqual(srv.answers[0].data, {
    port: 5269,
    priority: 30,
    target: 'hermes2.jabber.org',
    weight: 30,
  });
  const buf = await dot.lookup('ietf.org', {decode: false});
  t.truthy(Buffer.isBuffer(buf));
  t.is(buf.length, 468, 'Check padding');
  dot.close();
});

test('close with in-flight requests', async t => {
  const dot = create();
  // eslint-disable-next-line no-empty-function
  dot._data = () => {}; // Ignore any data received
  dot.on('send', buf => {
    // Close after the request has been written, but hopefully
    // before the response
    if (buf.length > 2) {
      dot.close();
    }
  });
  await t.throwsAsync(dot.lookup('ietf.org'));
});

test('immediate close', async t => {
  const dot = create();
  dot.on('error', e => {
    t.fail(`Should not get error: ${e.message}`);
  });
  await dot.close();
  t.is(dot.socket, null);
});

test('hash fail', async t => {
  const buf = Buffer.from('foo');
  t.throws(() => DNSoverTLS.hashCert(buf, 'badAlg'));
  t.throws(() => DNSoverTLS.hashCert('badCert'));
  t.is(DNSoverTLS.hashCert(buf),
    '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae');

  const dot = create({
    hash: 'WRONG',
  });
  await t.throwsAsync(dot.lookup('ietf.org'));
});

test('bad cert', async t => {
  const dot = create({
    host: 'untrusted-root.badssl.com',
  });
  await t.throwsAsync(dot.lookup('ietf.org'), undefined, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
});

test('pin cert', async t => {
  if (!crypto.X509Certificate) {
    // X509Certificate added in node 15.6.0
    t.pass();
    return;
  }
  const dot = create({
    host: 'untrusted-root.badssl.com',
    hash: DNSoverTLS.hashCert(
      new crypto.X509Certificate(mockServer.cert)
    ),
  });
  const res = await dot.lookup('ietf.org');
  t.is(res.rcode, 'NOERROR');
});

test('chunked reads', async t => {
  const dot = create();
  const resp = await dot.lookup('chunky.example', {id: 123});
  t.is(resp.id, 123);
  t.is(resp.rcode, 'NOERROR');
});

test('bad id', async t => {
  const dot = create();
  await t.throwsAsync(dot.lookup('badid.example'));
});
