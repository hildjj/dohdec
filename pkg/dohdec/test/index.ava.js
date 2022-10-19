import * as DohDec from '../lib/index.js'
import {DNSoverHTTPS} from '../lib/doh.js'
import {DNSoverTLS} from '../lib/dot.js'
// eslint-disable-next-line node/no-missing-import
import test from 'ava'

test('index exists', t => {
  t.is(DohDec.DNSoverHTTPS, DNSoverHTTPS)
  t.is(DohDec.DNSoverTLS, DNSoverTLS)
})
