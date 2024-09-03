import * as DohDec from '../lib/index.js';
import {DNSoverHTTPS} from '../lib/doh.js';
import {DNSoverTLS} from '../lib/dot.js';
import test from 'ava';

test('index exists', t => {
  t.is(DohDec.DNSoverHTTPS, DNSoverHTTPS);
  t.is(DohDec.DNSoverTLS, DNSoverTLS);
});
