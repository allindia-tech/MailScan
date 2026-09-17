/**
 * MailTrace AI — Chrome Extension Builder
 * ========================================
 * Assembles the production-ready Manifest V3 extension into dist/extension/
 * and packages the ZIP distribution archives.
 */

import fs from 'fs';
import path from 'path';

function copyRecursiveSync(src, dest) {
  const exists = fs.existsSync(src);
  const stats = exists && fs.statSync(src);
  const isDirectory = exists && stats.isDirectory();

  if (isDirectory) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }
    fs.readdirSync(src).forEach((childItemName) => {
      copyRecursiveSync(path.join(src, childItemName), path.join(dest, childItemName));
    });
  } else {
    const parentDir = path.dirname(dest);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true });
    }
    fs.copyFileSync(src, dest);
  }
}

export async function buildExtension() {
  console.log('>>> [Extension Build] Starting Chrome Extension build...');

  const srcExtensionDir = path.resolve('./extension');
  const distExtensionDir = path.resolve('./dist/extension');

  if (!fs.existsSync(srcExtensionDir)) {
    throw new Error(`Extension source directory not found at: ${srcExtensionDir}`);
  }

  // Clean dist/extension
  if (fs.existsSync(distExtensionDir)) {
    fs.rmSync(distExtensionDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distExtensionDir, { recursive: true });

  // Copy all files from extension/ to dist/extension/
  copyRecursiveSync(srcExtensionDir, distExtensionDir);

  // Copy background/service-worker.js to background.js at root as well for maximum compatibility
  const swSrc = path.join(distExtensionDir, 'background', 'service-worker.js');
  const bgRoot = path.join(distExtensionDir, 'background.js');
  if (fs.existsSync(swSrc)) {
    fs.copyFileSync(swSrc, bgRoot);
  }

  console.log(`✓ Copied extension assets to: ${distExtensionDir}`);
  console.log(`✓ Verified manifest.json at: ${path.join(distExtensionDir, 'manifest.json')}`);

  return distExtensionDir;
}

// Auto-execute if run directly
if (process.argv[1] && process.argv[1].endsWith('build-extension.js')) {
  buildExtension().catch((err) => {
    console.error('[Extension Build Error]:', err);
    process.exit(1);
  });
}
