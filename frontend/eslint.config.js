import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from '@typescript-eslint/eslint-plugin'
import tsParser from '@typescript-eslint/parser'

export default [
  {
    ignores: [
      'dist',
      'node_modules',
      'coverage',
      '*.min.js',
      'public/vendor',
      '.vite',
      'vite.config.js.timestamp*'
    ],
  },
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    settings: {
      react: { version: '18.3' },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tseslint.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,

      // React Refresh
      'react-refresh/only-export-components': 'off',

      // TypeScript
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrors: 'none',
        },
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-empty-function': 'warn',
      '@typescript-eslint/no-var-requires': 'off',

      // General JS/React (style rules relaxed to match current code)
      'no-console': 'off',
      'no-debugger': 'error',
      'no-alert': 'off',
      'no-unused-vars': 'off',
      'no-var': 'warn',
      'object-shorthand': 'off',
      'prefer-arrow-callback': 'off',
      'prefer-template': 'off',
      'template-curly-spacing': 'off',
      'arrow-spacing': 'off',
      'comma-dangle': 'off',
      'quotes': 'off',
      'semi': 'off',
      'indent': 'off',
      'linebreak-style': 'off',
      'eol-last': 'off',
      'no-trailing-spaces': 'off',
      'no-multiple-empty-lines': 'off',
      'sort-imports': 'off',
      'no-undef': 'off',

      // Security rules (keep)
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',

      // Code quality (keep as warnings)
      'complexity': ['warn', 30],
      'max-depth': ['warn', 6],
      'max-lines': 'off',
      'max-params': ['warn', 8],
      'no-magic-numbers': 'off',

      // Imports
      'no-duplicate-imports': 'warn',

      // React hooks
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'off',
    },
  },
  {
    files: ['**/*.d.ts'],
    rules: {
      'semi': 'off',
      'eol-last': 'off',
    },
  },
  {
    files: [
      '**/*.test.{js,jsx,ts,tsx}',
      '**/__tests__/**/*.{js,jsx,ts,tsx}',
      'src/test-setup.ts',
      'src/test-utils.jsx',
    ],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.jest,
        vi: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        describe: 'readonly',
        it: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
      },
    },
    rules: {
      // Relax some rules for tests
      'no-magic-numbers': 'off',
      'max-lines': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      'no-console': 'off',
      'no-undef': 'off',
      'semi': 'off',
      'sort-imports': 'off',
      'no-trailing-spaces': 'off',
      'eol-last': 'off',
      'no-useless-escape': 'off',
      'no-script-url': 'off',
      'no-eval': 'off',
    },
  },
  {
    files: ['**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-empty-object-type': 'off',
    },
  },
  {
    files: ['vite.config.js', 'vitest.config.js', 'postcss.config.js', 'tailwind.config.js'],
    languageOptions: {
      globals: globals.node,
    },
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-var-requires': 'off',
    },
  },
]
