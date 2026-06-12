// Erzeugt echte PNG-App-Icons (forest-grünes gerundetes Quadrat mit Curavio-Herz/Blatt).
// Reines Node (zlib), keine externen Pakete. Aufruf: node generate_icons.js
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

const FOREST = [28, 58, 42];
const CREAM = [247, 242, 228];
const AMBER = [242, 201, 138];

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}
function encodePNG(width, height, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width * 4 + 1)] = 0;
    rgba.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

// Punkt-in-Herz-Test (normalisierte Koordinaten, Herz zentriert)
function inHeart(nx, ny) {
  // klassische Herzkurve: (x^2+y^2-1)^3 - x^2*y^3 <= 0
  const x = nx, y = -ny;
  const a = x * x + y * y - 1;
  return a * a * a - x * x * y * y * y <= 0;
}

function renderIcon(size, { rounded = true, bleed = false } = {}) {
  const rgba = Buffer.alloc(size * size * 4);
  const SS = 3; // 3x Supersampling für glatte Kanten
  const radius = size * 0.22; // Eckenradius
  const cx = size / 2, cy = size / 2;
  // Herz-Skalierung: bei maskable kleiner (Safe-Zone), sonst größer
  const heartScale = bleed ? size * 0.30 : size * 0.34;
  const heartCY = cy - size * 0.02;

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const fx = px + (sx + 0.5) / SS;
          const fy = py + (sy + 0.5) / SS;
          // gerundetes Quadrat / Hintergrund
          let inside = true;
          if (rounded && !bleed) {
            const dx = Math.max(radius - fx, fx - (size - radius), 0);
            const dy = Math.max(radius - fy, fy - (size - radius), 0);
            inside = (dx * dx + dy * dy) <= radius * radius;
          }
          if (!inside) continue; // transparent außerhalb
          // Default Hintergrund forest
          let cr = FOREST[0], cg = FOREST[1], cb = FOREST[2];
          // Herz in cream
          const nx = (fx - cx) / heartScale;
          const ny = (fy - heartCY) / heartScale;
          if (inHeart(nx, ny)) { cr = CREAM[0]; cg = CREAM[1]; cb = CREAM[2]; }
          // zwei kleine amber „Köpfe" oben (Begleitungs-Symbol) als Akzent
          const headR = size * 0.075;
          const hY = heartCY - heartScale * 0.62;
          for (const hx of [cx - heartScale * 0.42, cx + heartScale * 0.42]) {
            const ddx = fx - hx, ddy = fy - hY;
            if (ddx * ddx + ddy * ddy <= headR * headR) { cr = AMBER[0]; cg = AMBER[1]; cb = AMBER[2]; }
          }
          r += cr; g += cg; b += cb; a += 255;
        }
      }
      const n = SS * SS;
      const idx = (py * size + px) * 4;
      const cov = a / (255 * n); // Deckung 0..1
      if (cov === 0) { rgba[idx + 3] = 0; continue; }
      rgba[idx] = Math.round(r / a * 255);
      rgba[idx + 1] = Math.round(g / a * 255);
      rgba[idx + 2] = Math.round(b / a * 255);
      rgba[idx + 3] = Math.round(cov * 255);
    }
  }
  return encodePNG(size, size, rgba);
}

const outDir = path.join(__dirname, 'public', 'icons');
fs.mkdirSync(outDir, { recursive: true });

const targets = [
  ['icon-192.png', 192, { rounded: true }],
  ['icon-512.png', 512, { rounded: true }],
  ['icon-192-maskable.png', 192, { bleed: true }],
  ['icon-512-maskable.png', 512, { bleed: true }],
  ['apple-touch-icon.png', 180, { bleed: true }], // iOS füllt + rundet selbst
  ['favicon-32.png', 32, { rounded: true }]
];
for (const [name, size, opts] of targets) {
  fs.writeFileSync(path.join(outDir, name), renderIcon(size, opts));
  console.log('  ✓', name, size + 'px');
}
console.log('Icons erzeugt in public/icons/');
