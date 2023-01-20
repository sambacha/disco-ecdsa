module.exports = {
/*  editorconfig: true, */
  arrowParens: 'always',
  bracketSpacing: true,
  endOfLine: 'lf',
  printWidth: 80,
  singleQuote: true,
  tabWidth: 2,
  trailingComma: 'all',
  quoteProps: 'as-needed',
  semi: true,
  overrides: [
    {
      files: ['*.sol', '*.t.sol'],
      plugins: [require.resolve('prettier-plugin-solidity')],
      options: {
        printWidth: 100,
        tabWidth: 4,
        useTabs: true,
        singleQuote: false,
        bracketSpacing: true,
      }
    }
  ],
};