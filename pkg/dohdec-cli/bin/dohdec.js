#!/usr/bin/env node

import {DnsCli} from '../lib/cli.js';

const cli = new DnsCli(process.argv);
cli
  .main()
  .catch(_e => {
    process.exit(1);
  });
