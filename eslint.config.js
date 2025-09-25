import ava from '@cto.af/eslint-config/ava.js';
import es6 from '@cto.af/eslint-config/es6.js';
import jsdoc from '@cto.af/eslint-config/jsdoc.js';
import markdown from '@cto.af/eslint-config/markdown.js';

export default [
  {
    ignores: [
      '**/*.d.ts',
    ],
  },
  ...es6,
  ...jsdoc,
  ...markdown,
  ...ava,
  {
    files: ['**/*.js'],
    rules: {
      'jsdoc/valid-types': 'off', // Let TS check.
    },
  },
];
