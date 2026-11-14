const esbuild = require('esbuild');
const path = require('path');

esbuild.buildSync({
  stdin: {
    contents: 'export { x25519, ed25519 } from "@noble/curves/ed25519.js";',
    resolveDir: __dirname,
    sourcefile: 'entry.js',
    loader: 'js',
  },
  bundle: true,
  minify: true,
  format: 'iife',
  globalName: 'nobleCurves',
  outfile: path.join(__dirname, '../client/js/crypto/noble-curves.js'),
});

console.log('noble-curves.js successfully bundled!');

