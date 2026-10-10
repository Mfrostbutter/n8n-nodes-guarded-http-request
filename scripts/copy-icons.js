// Copies SVG icons from nodes/ and credentials/ into dist/, mirroring paths.
const { readdirSync, mkdirSync, copyFileSync, statSync } = require('node:fs');
const { join, dirname } = require('node:path');

const root = join(__dirname, '..');

function walk(dir, out = []) {
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) walk(full, out);
		else if (entry.endsWith('.svg')) out.push(full);
	}
	return out;
}

let count = 0;
for (const base of ['nodes', 'credentials']) {
	const src = join(root, base);
	for (const file of walk(src)) {
		const rel = file.slice(root.length + 1);
		const dest = join(root, 'dist', rel);
		mkdirSync(dirname(dest), { recursive: true });
		copyFileSync(file, dest);
		count++;
	}
}
console.log(`copied ${count} icon(s)`);
