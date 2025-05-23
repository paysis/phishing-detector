import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import inject from '@rollup/plugin-inject';
import { glob } from 'glob';

// Find all JS files in src directory (excluding .dist.js files)
const inputFiles = await glob('src/**/*.js', { ignore: '**/*.dist.js' });

// Create a config for each input file
export default inputFiles.map(inputFile => ({
  input: inputFile,
  output: {
    file: inputFile.replace('.js', '.dist.js'),
    format: 'esm',
    sourcemap: true
  },
  plugins: [
    nodeResolve({
      browser: true,
      preferBuiltins: false,
      extensions: ['.js', '.json']
    }),
    commonjs(),
    json(),
    inject({
      Buffer: ["buffer", "Buffer"]
    })
  ]
}));
