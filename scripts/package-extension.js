/**
 * Scripts to package the Chrome Extension into a downloadable ZIP archive
 */

import fs from 'fs';
import path from 'path';
import { ZipArchive } from 'archiver';
import { buildExtension } from './build-extension.js';
import { validateExtensionDirectory } from './validate-extension.js';

async function zipExtension() {
  // 1. Build dist/extension directory
  const distExtensionDir = await buildExtension();

  // 2. Validate built extension
  const valResult = validateExtensionDirectory(distExtensionDir);
  if (!valResult.passed) {
    throw new Error('Extension validation failed. Aborting packaging.');
  }

  const outDirs = [
    path.resolve('./public/downloads'),
    path.resolve('./dist/downloads')
  ];

  for (const dir of outDirs) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const zipPath = path.join(outDirs[0], 'mailtrace-ai-extension.zip');
  const output = fs.createWriteStream(zipPath);
  const archive = new ZipArchive({ zlib: { level: 9 } });

  return new Promise((resolve, reject) => {
    output.on('close', () => {
      console.log(`[Packager] Extension packaged successfully: ${zipPath} (${archive.pointer()} bytes)`);

      // Copy to dist/downloads as well if dist exists
      const distZip = path.join(outDirs[1], 'mailtrace-ai-extension.zip');
      try {
        fs.copyFileSync(zipPath, distZip);
        console.log(`[Packager] Copied to ${distZip}`);
      } catch (e) {
        // dist might not exist yet before build
      }

      resolve(zipPath);
    });

    archive.on('error', (err) => {
      console.error('[Packager] Archive error:', err);
      reject(err);
    });

    archive.pipe(output);

    // Append files from built extension directory
    archive.directory(distExtensionDir, false);

    archive.finalize();
  });
}

zipExtension().catch((err) => {
  console.error('Packaging failed:', err);
  process.exit(1);
});
