import * as packet from 'dns-packet'
import {connect, createServer} from '../index.js'
import {default as NoFilter} from 'nofilter'
import {pEvent} from 'p-event'
import test from 'ava'

test('server', async t => {
  const server = createServer()
  t.truthy(server)
  const cli = connect(server.port)
  t.truthy(cli)
  await pEvent(cli, 'secure')
  const nof = new NoFilter()
  cli.pipe(nof)

  const query = {
    type: 'query',
    id: 17,
    flags: packet.RECURSION_DESIRED,
    questions: [{
      type: 'A',
      class: 'IN',
      name: 'ietf.org',
    }],
  }
  cli.write(packet.streamEncode(query))
  const sz = (await nof.readFull(2)).readUint16BE()
  const dresp = packet.decode(await nof.readFull(sz))
  t.is(dresp.id, 17)
  t.like(dresp.answers[0], {
    data: '4.31.198.44',
    name: 'ietf.org',
    type: 'A',
  })

  query.questions[0].name = 'chunky.example'
  query.additionals = [{
    name: '.',
    type: 'OPT',
    // @ts-ignore TS2339: types not up to date
    udpPayloadSize: 4096,
    flags: 0,
    options: [{
      code: 'PADDING',
      length: 10, // Just for test
    }],
  }]

  const qbuf = packet.streamEncode(query)
  // Sorry for callback hell.  Ensure we don't get Nagle'd.
  cli.write(qbuf.slice(0, 1), () => {
    cli.write(qbuf.slice(1, 3), () => {
      cli.write(qbuf.slice(3, 7), () => {
        cli.write(qbuf.slice(7))
      })
    })
  })
  const sz2 = (await nof.readFull(2)).readUint16BE()
  const dresp2 = packet.decode(await nof.readFull(sz2))
  t.truthy(dresp2)
  t.like(dresp2.answers[0], {
    data: '192.168.1.1',
    name: 'chunky.example',
    type: 'A',
  })

  query.questions[0].name = 'badid.example'
  cli.write(packet.streamEncode(query))
  const sz3 = (await nof.readFull(2)).readUint16BE()
  const dresp3 = packet.decode(await nof.readFull(sz3))
  t.not(dresp3.id, 17)

  query.questions[0].name = 'unknown.invalid'
  cli.write(packet.streamEncode(query))
  const sz4 = (await nof.readFull(2)).readUint16BE()
  const dresp4 = packet.decode(await nof.readFull(sz4))
  t.is(dresp4.rcode, 'NXDOMAIN')

  server.close()
  await pEvent(server, 'close')
})
