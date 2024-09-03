import ava from '@cto.af/eslint-config/ava.js';
import base from '@cto.af/eslint-config';
import markdown from '@cto.af/eslint-config/markdown.js';
import mod from '@cto.af/eslint-config/module.js';

export default [
  {
    ignores: [
      '**/*.d.ts',
    ],
  },
  ...base,
  ...mod,
  ...markdown,
  ...ava,
];
