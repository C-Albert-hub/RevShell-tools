import fs from 'node:fs/promises';
import path from 'node:path';
import sharp from 'sharp';
import pngToIco from 'png-to-ico';

const root = path.resolve(process.cwd());
const srcSvg = path.join(root, 'public', 'rev.svg');
const outDir = path.join(root, 'src-tauri', 'icons');

async function ensureDir(p) { await fs.mkdir(p, { recursive: true }); }

async function generatePngs() {
  const svg = await fs.readFile(srcSvg);
  const sizes = [32, 128, 256, 512, 1024];
  await ensureDir(outDir);
  for (const s of sizes) {
    const buf = await sharp(svg).resize(s, s, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } }).png().toBuffer();
    await fs.writeFile(path.join(outDir, `r-${s}.png`), buf);
  }
  await fs.writeFile(path.join(outDir, '32x32.png'), await fs.readFile(path.join(outDir, 'r-32.png')));
  await fs.writeFile(path.join(outDir, '128x128.png'), await fs.readFile(path.join(outDir, 'r-128.png')));
  await fs.writeFile(path.join(outDir, '128x128@2x.png'), await fs.readFile(path.join(outDir, 'r-256.png')));
}

async function generateIco() {
  const files = ['r-256.png','r-128.png','r-32.png'].map(f=>path.join(outDir,f));
  const ico = await pngToIco(files);
  await fs.writeFile(path.join(outDir, 'icon.ico'), ico);
}


async function main() {
  await generatePngs();
  await generateIco();
  // ICNS generation skipped on Windows; keep existing if present
  console.log('Icons generated in', outDir);
}

main().catch(err=>{ console.error(err); process.exit(1); });
