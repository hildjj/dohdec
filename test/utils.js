'use strict'

const {Transform} = require('stream')

class Buf extends Transform {
  constructor(opts = {}) {
    const { errorToThrow, ...others } = opts
    super({
      ...others
    })
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

exports.Buf = Buf
