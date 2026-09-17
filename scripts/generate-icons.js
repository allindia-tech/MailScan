/**
 * Pure Node.js script to generate valid PNG icons for Chrome Extension
 * Creates 16x16, 32x32, 48x48, and 128x128 icons with MailTrace AI Cyber Shield Branding
 */

import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

function createCRC32Table() {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c;
  }
  return table;
}

const CRC32_TABLE = createCRC32Table();

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function makeChunk(type, data) {
  const len = data.length;
  const chunk = Buffer.alloc(len + 12);
  chunk.writeUInt32BE(len, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);
  const crc = crc32(chunk.subarray(4, len + 8));
  chunk.writeUInt32BE(crc, len + 8);
  return chunk;
}

function generatePng(size) {
  const width = size;
  const height = size;

  // Raw RGBA scanlines with filter byte (0)
  const rawBytes = Buffer.alloc((width * 4 + 1) * height);
  let offset = 0;

  const cx = width / 2;
  const cy = height / 2;
  const r = size * 0.44;

  for (let y = 0; y < height; y++) {
    rawBytes[offset++] = 0; // Filter: None
    for (let x = 0; x < width; x++) {
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);

      // Cyber shield / hexagon shape math
      const ny = (y - 0.1 * size) / (0.8 * size);
      const nx = Math.abs(x - cx) / (0.42 * size);
      const inShield = (ny >= 0 && ny <= 1 && nx <= (1 - Math.max(0, ny - 0.4) * 0.8));

      let rCol = 15;
      let gCol = 23;
      let bCol = 42;
      let aCol = 0;

      if (dist <= r * 1.1) {
        // Outer dark circle backdrop
        aCol = 255;
        rCol = 10;
        gCol = 15;
        bCol = 30;

        if (inShield) {
          // Inside shield: gradient from electric blue to cyan
          const t = y / size;
          rCol = Math.round(14 + t * 20);
          gCol = Math.round(116 + (1 - t) * 60);
          bCol = Math.round(244 - t * 40);

          // Envelope / V accent inside shield
          const envY = (y - 0.28 * size) / (0.44 * size);
          const envX = Math.abs(x - cx) / (0.28 * size);
          if (envY >= 0 && envY <= 0.8 && envX <= 0.8) {
            const onV = Math.abs(envY - envX * 0.7) < 0.12 && envY < 0.55;
            const onBorder = (envY > 0.7 || envX > 0.7);
            if (onV || onBorder) {
              rCol = 255;
              gCol = 255;
              bCol = 255;
            } else {
              rCol = 6;
              gCol = 78;
              bCol = 160;
            }
          }
        } else if (dist > r * 0.95) {
          // Glowing cyan border
          rCol = 34;
          gCol = 211;
          bCol = 238;
        }
      }

      rawBytes[offset++] = rCol;
      rawBytes[offset++] = gCol;
      rawBytes[offset++] = bCol;
      rawBytes[offset++] = aCol;
    }
  }

  const deflated = zlib.deflateSync(rawBytes);

  // PNG Header
  const signature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

  // IHDR
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 6; // color type RGBA
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace
  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // IDAT
  const idatChunk = makeChunk('IDAT', deflated);

  // IEND
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

const targetDirs = [
  path.resolve('./extension/icons'),
  path.resolve('./public/icons')
];

for (const dir of targetDirs) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

const sizes = [16, 32, 48, 128];
for (const size of sizes) {
  const buf = generatePng(size);
  for (const dir of targetDirs) {
    fs.writeFileSync(path.join(dir, `icon-${size}.png`), buf);
  }
  console.log(`Generated icon-${size}.png (${buf.length} bytes)`);
}

console.log('All icons generated successfully.');
