const js = require('@eslint/js');

module.exports = [
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                require: 'readonly',
                module: 'readonly',
                process: 'readonly',
                console: 'readonly',
                __dirname: 'readonly',
                Buffer: 'readonly',
                fetch: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                setInterval: 'readonly',
                clearInterval: 'readonly'
            }
        },
        rules: {
            'no-unused-vars': ['warn', { args: 'none', caughtErrors: 'none' }]
        }
    },
    {
        ignores: ['node_modules/**']
    }
];
