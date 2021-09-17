#!/usr/bin/env node

import {DnsCli} from '../lib/cli.js'

const cli = new DnsCli()
cli
  .parse(process.argv.slice(2))
  .main()
  .catch(e => {
    if (cli.opts.verbose) {
      console.error(e)
    } else {
      console.error(e.message ? e.message : e)
    }
    process.exit(1)
  })
