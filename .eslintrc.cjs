module.exports = {
  root: true,
  ignorePatterns: [
    'node_modules/',
    'docs/',
    'coverage/',
  ],
  extends: ['@cto.af'],
  parserOptions: {
    sourceType: 'module',
  },
  rules: {
    'sort-imports': 'error',
    // [Possible Errors](https://eslint.org/docs/rules/#possible-errors)
    'node/no-unsupported-features/es-syntax': [
      'error',
      {
        version: '>=12.19',
        ignores: ['modules'],
      },
    ],
  },
}
