'use strict';

/** @import {TypeDocOptions} from 'typedoc' */
/** @type {TypeDocOptions} */
module.exports = {
  entryPoints: ['lib/index.js', 'lib/doh.js', 'lib/dot.js', 'lib/dnsUtils.js'],
  out: '../../docs',
  cleanOutputDir: true,
  sidebarLinks: {
    Spec: 'https://datatracker.ietf.org/doc/html/rfc8484',
    Documentation: 'http://hildjj.github.io/dohdec/',
  },
  navigation: {
    includeCategories: false,
    includeGroups: false,
  },
  categorizeByGroup: false,
  sort: ['static-first', 'alphabetical'],
  exclude: ['**/*.spec.ts'],
};
