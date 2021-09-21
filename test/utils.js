import * as rs from 'jsrsasign'
import {Duplex, Transform} from 'stream'
import {TLSSocket} from 'tls'

const MINS_5 = 5 * 60 * 1000

export class Buf extends Transform {
  constructor(opts = {}) {
    const { errorToThrow, ...others } = opts
    super(others)
    this.errorToThrow = errorToThrow
  }

  _transform(chunk, encoding, cb) {
    if (this.errorToThrow) {
      cb(this.errorToThrow)
    } else {
      this.push(chunk, encoding)
      cb()
    }
  }

  static from(str) {
    return new Buf().end(str)
  }
}

// Below to be pulled into a separate project the next time I need a mock TLS
// server.
export class HalfSocket extends Duplex {
  constructor(name, opts) {
    super(opts)
    this.name = name
  }

  _write(chunk, encoding, cb) {
    // De-couple the halves
    this.emit('written', chunk, encoding)
    cb()
  }

  // eslint-disable-next-line class-methods-use-this, no-empty-function
  _read(sz) {
  }
}

export class MockTLSserver {
  constructor(ServerInstanceClass, ...names) {
    this.ServerInstanceClass = ServerInstanceClass

    const now = new Date().getTime()
    this.chain = {
      notafter: new Date(now + MINS_5),
      notbefore: new Date(now - MINS_5),
      ca_dn: 'C=US/ST=Colorado/L=Denver/CN=Example-Root-CA',
      ca_pem: null,
      srv_pem: null,
      srv_key: null,
    }

    if (names.length === 0) {
      names.push('localhost')
    }

    // Create a self-signed CA cert
    const ca_kp = rs.KEYUTIL.generateKeypair('RSA', 1024)
    const ca_prv = ca_kp.prvKeyObj
    const ca_pub = ca_kp.pubKeyObj

    const ca = new rs.KJUR.asn1.x509.Certificate({
      version: 3,
      serial: {int: now},
      issuer: {str: this.chain.ca_dn},
      notbefore: {str: rs.datetozulu(this.chain.notbefore)},
      notafter: {str: rs.datetozulu(this.chain.notafter)},
      subject: {str: this.chain.ca_dn},
      sbjpubkey: ca_pub,
      ext: [
        {extname: 'basicConstraints', cA: true},
      ],
      sigalg: 'SHA256withRSA',
      cakey: ca_prv,
    })
    this.chain.ca_pem = ca.getPEM()

    // Create a server cert signed by the CA cert
    const srv_kp = rs.KEYUTIL.generateKeypair('RSA', 1024)
    const srv_prv = srv_kp.prvKeyObj
    const srv_pub = srv_kp.pubKeyObj

    const srv = new rs.KJUR.asn1.x509.Certificate({
      version: 3,
      serial: {int: 2},
      issuer: {str: this.chain.ca_dn},
      notbefore: {str: rs.datetozulu(this.chain.notbefore)},
      notafter: {str: rs.datetozulu(this.chain.notafter)},
      subject: {str: `C=US/ST=Colorado/L=Denver/CN=${names[0]}`},
      sbjpubkey: srv_pub,
      ext: [
        {extname: 'authorityKeyIdentifier', kid: this.chain.ca_pem},
        {extname: 'basicConstraints', cA: false},
        {
          extname: 'keyUsage',
          names: [
            'digitalSignature',
            'nonRepudiation',
            'keyEncipherment',
            'dataEncipherment',
          ],
        },
        {
          extname: 'subjectAltName',
          array: names.map(n => ({dns: n})),
        },
      ],
      sigalg: 'SHA256withRSA',
      cakey: ca_prv,
    })

    this.chain.srv_pem = srv.getPEM()
    this.chain.srv_key = rs.KEYUTIL.getPEM(srv_prv, 'PKCS1PRV')
  }

  instance(opts) {
    return new this.ServerInstanceClass(this.chain, opts)
  }
}

export class MockServerInstance extends Duplex {
  constructor(chain, opts) {
    super(opts)
    this.chain = chain
    this.rawClientSocket = new HalfSocket('cli')
    this.rawServerSocket = new HalfSocket('srv')

    this.rawClientSocket.on('written', (chunk, encoding) => {
      this.rawServerSocket.push(chunk)
    })
    this.rawServerSocket.on('written', (chunk, encoding) => {
      this.rawClientSocket.push(chunk)
    })

    this.server = new TLSSocket(this.rawServerSocket, {
      isServer: true,
      enableTrace: true,
      requestCert: false,
      cert: this.chain.srv_pem,
      key: this.chain.srv_key,
      secureProtocol: 'TLSv1_2_method',
    })
    this.server.on('data', chunk => {
      this.push(chunk)
    })
    this.server.on('secureConnection', s => this.emit('connection', s))
    this.server.on('error', e => this.emit('error', e))
    this.server.on('data', this._data.bind(this))
    this.server.on('end', this._end.bind(this))
  }

  _write(chunk, encoding, cb) {
    this.server.write(chunk, encoding, cb)
  }

  _final(cb) {
    this.server.end(null, cb)
  }

  // eslint-disable-next-line class-methods-use-this, no-empty-function
  _read(sz) {}

  // eslint-disable-next-line class-methods-use-this, no-empty-function
  _end() {}

  // eslint-disable-next-line class-methods-use-this, no-empty-function
  _data(chunk, encoding) {}

  _finish() {
    this.server.end()
  }
}
