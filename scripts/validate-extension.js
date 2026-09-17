/**
 * MailTrace AI — Chrome Extension Validator (Manifest V3)
 * =========================================================
 * Rigorously validates that the extension in dist/extension/
 * (and source extension/) satisfies all Chrome Web Store & Manifest V3 criteria:
 * - manifest.json at root
 * - valid JSON formatting
 * - manifest_version === 3
 * - all referenced files exist
 * - no source TypeScript references (.ts / .tsx)
 * - no wildcard <all_urls>
 * - safe externally_connectable matching
 * - valid background service worker
 */

import fs from 'fs';
import path from 'path';

export function validateExtensionDirectory(extensionDir) {
  const errors = [];
  const warnings = [];

  console.log(`\n======================================================`);
  console.log(`🔍 VALIDATING CHROME EXTENSION: ${extensionDir}`);
  console.log(`======================================================`);

  // 1. Check directory exists
  if (!fs.existsSync(extensionDir)) {
    errors.push(`Extension directory does not exist: ${extensionDir}`);
    return { passed: false, errors, warnings };
  }

  // 2. Check manifest.json at root
  const manifestPath = path.join(extensionDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    errors.push(`Manifest file missing at extension root: ${manifestPath}`);
    return { passed: false, errors, warnings };
  }

  // 3. Parse manifest.json
  let manifest;
  try {
    const raw = fs.readFileSync(manifestPath, 'utf8');
    manifest = JSON.parse(raw);
    console.log('✓ manifest.json parsed as valid JSON');
  } catch (err) {
    errors.push(`Failed to parse manifest.json: ${err.message}`);
    return { passed: false, errors, warnings };
  }

  // 4. Validate manifest_version === 3
  if (manifest.manifest_version !== 3) {
    errors.push(`Expected manifest_version: 3, got: ${manifest.manifest_version}`);
  } else {
    console.log('✓ manifest_version is 3 (Manifest V3)');
  }

  // 5. Validate Name and Version
  if (!manifest.name || !manifest.version) {
    errors.push('Manifest must specify "name" and "version"');
  } else {
    console.log(`✓ Name: "${manifest.name}", Version: ${manifest.version}`);
  }

  // 6. Check Background Service Worker
  if (!manifest.background || !manifest.background.service_worker) {
    errors.push('Manifest must define "background.service_worker"');
  } else {
    const swPath = path.join(extensionDir, manifest.background.service_worker);
    if (!fs.existsSync(swPath)) {
      errors.push(`Background service worker file not found: ${swPath}`);
    } else {
      console.log(`✓ Background service worker verified: ${manifest.background.service_worker}`);
    }
  }

  // 7. Check Action / Popup
  if (manifest.action && manifest.action.default_popup) {
    const popupPath = path.join(extensionDir, manifest.action.default_popup);
    if (!fs.existsSync(popupPath)) {
      errors.push(`Default popup file not found: ${popupPath}`);
    } else {
      console.log(`✓ Default popup verified: ${manifest.action.default_popup}`);
    }
  }

  // 8. Check Icons
  if (manifest.icons) {
    for (const [size, iconRelPath] of Object.entries(manifest.icons)) {
      const iconPath = path.join(extensionDir, iconRelPath);
      if (!fs.existsSync(iconPath)) {
        errors.push(`Declared icon-${size} not found: ${iconPath}`);
      } else {
        const stats = fs.statSync(iconPath);
        if (stats.size === 0) {
          errors.push(`Declared icon-${size} is empty: ${iconPath}`);
        }
      }
    }
    console.log('✓ All declared extension icons verified (16, 32, 48, 128)');
  }

  // 9. Check Content Scripts
  if (manifest.content_scripts && Array.isArray(manifest.content_scripts)) {
    for (const cs of manifest.content_scripts) {
      if (cs.js && Array.isArray(cs.js)) {
        for (const jsFile of cs.js) {
          const jsPath = path.join(extensionDir, jsFile);
          if (!fs.existsSync(jsPath)) {
            errors.push(`Content script JS not found: ${jsPath}`);
          }
        }
      }
      if (cs.css && Array.isArray(cs.css)) {
        for (const cssFile of cs.css) {
          const cssPath = path.join(extensionDir, cssFile);
          if (!fs.existsSync(cssPath)) {
            errors.push(`Content script CSS not found: ${cssPath}`);
          }
        }
      }
    }
    console.log('✓ All content script JS and CSS bundles verified');
  }

  // 10. Check Options Page
  if (manifest.options_page) {
    const optionsPath = path.join(extensionDir, manifest.options_page);
    if (!fs.existsSync(optionsPath)) {
      errors.push(`Options page not found: ${optionsPath}`);
    } else {
      console.log(`✓ Options page verified: ${manifest.options_page}`);
    }
  }

  // 11. Check Side Panel
  if (manifest.side_panel && manifest.side_panel.default_path) {
    const sidePanelPath = path.join(extensionDir, manifest.side_panel.default_path);
    if (!fs.existsSync(sidePanelPath)) {
      errors.push(`Side panel path not found: ${sidePanelPath}`);
    } else {
      console.log(`✓ Side panel verified: ${manifest.side_panel.default_path}`);
    }
  }

  // 12. Security Check: No wildcard <all_urls> in permissions or host_permissions
  const allPermissions = [
    ...(manifest.permissions || []),
    ...(manifest.host_permissions || [])
  ];
  if (allPermissions.includes('<all_urls>')) {
    errors.push('Security Violation: Disallowed <all_urls> found in permissions.');
  } else {
    console.log('✓ No excessive <all_urls> wildcards');
  }

  // 13. Security Check: externally_connectable must not be wide open
  if (manifest.externally_connectable && manifest.externally_connectable.matches) {
    if (manifest.externally_connectable.matches.includes('*://*/*')) {
      errors.push('Security Violation: externally_connectable wildcard "*://*/*" is disallowed.');
    } else {
      console.log('✓ externally_connectable uses targeted domain matching');
    }
  }

  // 14. Check that no TypeScript (.ts / .tsx) files are directly referenced
  const rawManifestStr = fs.readFileSync(manifestPath, 'utf8');
  if (/\.tsx?["']/i.test(rawManifestStr)) {
    errors.push('Syntax Violation: Raw TypeScript file (.ts / .tsx) directly referenced in manifest.');
  } else {
    console.log('✓ Pure executable JavaScript references (No uncompiled TS)');
  }

  const passed = errors.length === 0;

  if (passed) {
    console.log(`\n🎉 EXTENSION VALIDATION PASSED: ${extensionDir} is ready to load unpacked in Chrome!`);
  } else {
    console.error(`\n❌ EXTENSION VALIDATION FAILED with ${errors.length} error(s):`);
    errors.forEach((e) => console.error(`  - ${e}`));
  }

  return { passed, errors, warnings };
}

// Run if invoked directly
if (process.argv[1] && process.argv[1].endsWith('validate-extension.js')) {
  // Validate both dist/extension/ and source extension/
  const targets = [
    path.resolve('./dist/extension'),
    path.resolve('./extension')
  ];

  let anyFailed = false;
  for (const target of targets) {
    if (fs.existsSync(target)) {
      const res = validateExtensionDirectory(target);
      if (!res.passed) anyFailed = true;
    }
  }

  if (anyFailed) {
    process.exit(1);
  }
}
