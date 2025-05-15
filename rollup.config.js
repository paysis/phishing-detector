import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import inject from '@rollup/plugin-inject';

export default {
	input: 'src/background/background.js',
	output: {
		file: 'src/background/background.dist.js',
		format: 'esm'
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
};
