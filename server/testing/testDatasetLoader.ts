/**
 * MailTrace AI — Test Dataset Loader
 * ===================================
 * Authoritative, reusable dataset loader for application regression,
 * integration, security, and determinism testing.
 * 
 * Rules:
 * 1. Only loads from `dataset/testing/`.
 * 2. Explicitly rejects `dataset/` (ML training root) as an application test source.
 * 3. Never falls back to mock or demo data if `dataset/testing/` is empty or missing.
 * 4. Generates deterministic SHA-256 testCaseIds.
 * 5. Validates labeled vs unlabeled cases.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ThreatCategory } from '../../src/types/forensics.js';

export interface LoadedTestCase {
  id: string;
  name: string;
  description: string;
  category: ThreatCategory | 'UNLABELED';
  filePath: string;
  rawEml: string;
  sha256: string;
  fileSizeBytes: number;
  groundTruth: ThreatCategory | 'UNLABELED';
  isHardNegative: boolean;
  expected: {
    classification?: string[];
    threatRiskMin?: number;
    threatRiskMax?: number;
    spamLikelihoodMin?: number;
    spamLikelihoodMax?: number;
    authenticityMin?: number;
    authenticityMax?: number;
    action?: string[];
  };
  tags: string[];
}

export interface DatasetQualityReport {
  timestamp: string;
  sourceDir: string;
  totalFilesDiscovered: number;
  supportedFiles: number;
  unsupportedFiles: number;
  malformedFiles: number;
  duplicateCount: number;
  labeledCasesCount: number;
  unlabeledCasesCount: number;
  categories: Record<string, number>;
  cases: {
    id: string;
    file: string;
    category: string;
    sizeBytes: number;
    sha256: string;
    isLabeled: boolean;
  }[];
}

export class TestDatasetLoader {
  private static readonly SUPPORTED_EXTENSIONS = ['.eml', '.txt', '.html', '.json'];
  private static readonly DEFAULT_TESTING_DIR = path.resolve('dataset/testing');

  private testingDir: string;
  private cachedCases: LoadedTestCase[] | null = null;
  private qualityReport: DatasetQualityReport | null = null;

  constructor(customTestingDir?: string) {
    this.testingDir = customTestingDir ? path.resolve(customTestingDir) : TestDatasetLoader.DEFAULT_TESTING_DIR;
    
    // Safety check: Prevent accidental loading from the raw ML training directory
    const normalizedTesting = path.normalize(this.testingDir);
    const normalizedDatasetRoot = path.normalize(path.resolve('dataset'));
    if (normalizedTesting === normalizedDatasetRoot) {
      throw new Error(
        `TESTING ISOLATION VIOLATION: Cannot use root ML dataset directory '${normalizedDatasetRoot}' as application test source. Testing must use 'dataset/testing/'.`
      );
    }
  }

  /**
   * Recursively discovers and loads all valid test cases from dataset/testing/.
   * Throws a hard error if directory does not exist or has zero valid test cases.
   */
  public discoverTestCases(forceReload = false): LoadedTestCase[] {
    if (this.cachedCases && !forceReload) {
      return this.cachedCases;
    }

    if (!fs.existsSync(this.testingDir)) {
      throw new Error(
        `TEST DATA ERROR: Testing directory '${this.testingDir}' does not exist. Automated analysis tests cannot run.`
      );
    }

    const manifestPath = path.join(this.testingDir, 'manifest.json');
    let manifestData: Record<string, any> | null = null;
    if (fs.existsSync(manifestPath)) {
      try {
        manifestData = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
      } catch (err: any) {
        console.warn(`[TestDatasetLoader] Warning: Could not parse manifest.json: ${err.message}`);
      }
    }

    const manifestMap = new Map<string, any>();
    if (manifestData && Array.isArray(manifestData.cases)) {
      for (const mc of manifestData.cases) {
        manifestMap.set(mc.id, mc);
        if (mc.file) {
          manifestMap.set(path.normalize(mc.file), mc);
        }
      }
    }

    const discoveredFiles = this.scanDirRecursively(this.testingDir);
    const cases: LoadedTestCase[] = [];
    const seenHashes = new Set<string>();
    let unsupportedCount = 0;
    let malformedCount = 0;
    let duplicateCount = 0;
    const categoryCounts: Record<string, number> = {};

    for (const filePath of discoveredFiles) {
      const ext = path.extname(filePath).toLowerCase();
      if (filePath.endsWith('manifest.json') || filePath.endsWith('.meta.json') || filePath.endsWith('.csv')) {
        continue;
      }

      if (!TestDatasetLoader.SUPPORTED_EXTENSIONS.includes(ext)) {
        unsupportedCount++;
        continue;
      }

      let content = '';
      try {
        content = fs.readFileSync(filePath, 'utf-8');
      } catch {
        malformedCount++;
        continue;
      }

      if (!content || content.trim().length === 0) {
        malformedCount++;
        continue;
      }

      const sha256 = crypto.createHash('sha256').update(content.trim()).digest('hex');
      if (seenHashes.has(sha256)) {
        duplicateCount++;
        continue;
      }
      seenHashes.add(sha256);

      const relPath = path.relative(this.testingDir, filePath);
      const fileStats = fs.statSync(filePath);

      // Check sidecar metadata file
      const sidecarMetaPath = filePath.replace(/\.[^/.]+$/, '.meta.json');
      let sidecarMeta: any = null;
      if (fs.existsSync(sidecarMetaPath)) {
        try {
          sidecarMeta = JSON.parse(fs.readFileSync(sidecarMetaPath, 'utf-8'));
        } catch {
          // ignore
        }
      }

      const manifestEntry = manifestMap.get(relPath) || sidecarMeta || {};
      const fallbackId = `test-case-${sha256.substring(0, 12)}`;
      const id = manifestEntry.id || fallbackId;
      const name = manifestEntry.name || path.basename(filePath, ext);
      const description = manifestEntry.description || `Test email fixture loaded from ${relPath}`;
      const groundTruth = manifestEntry.groundTruth || manifestEntry.category || 'UNLABELED';
      const isHardNegative = !!manifestEntry.isHardNegative;
      const expected = manifestEntry.expected || { classification: groundTruth !== 'UNLABELED' ? [groundTruth] : [] };
      const tags = Array.isArray(manifestEntry.tags) ? manifestEntry.tags : [];

      const tc: LoadedTestCase = {
        id,
        name,
        description,
        category: groundTruth,
        filePath,
        rawEml: content,
        sha256,
        fileSizeBytes: fileStats.size,
        groundTruth,
        isHardNegative,
        expected,
        tags
      };

      cases.push(tc);
      categoryCounts[groundTruth] = (categoryCounts[groundTruth] || 0) + 1;
    }

    if (cases.length === 0) {
      throw new Error(
        `TEST DATA ERROR: No valid test cases found in '${this.testingDir}'. Automated analysis tests cannot run.`
      );
    }

    // Sort deterministically by ID
    cases.sort((a, b) => a.id.localeCompare(b.id));
    this.cachedCases = cases;

    this.qualityReport = {
      timestamp: new Date().toISOString(),
      sourceDir: this.testingDir,
      totalFilesDiscovered: discoveredFiles.length,
      supportedFiles: cases.length,
      unsupportedFiles: unsupportedCount,
      malformedFiles: malformedCount,
      duplicateCount,
      labeledCasesCount: cases.filter(c => c.category !== 'UNLABELED').length,
      unlabeledCasesCount: cases.filter(c => c.category === 'UNLABELED').length,
      categories: categoryCounts,
      cases: cases.map(c => ({
        id: c.id,
        file: path.relative(this.testingDir, c.filePath),
        category: c.category,
        sizeBytes: c.fileSizeBytes,
        sha256: c.sha256,
        isLabeled: c.category !== 'UNLABELED'
      }))
    };

    return cases;
  }

  public loadAllTestCases(): LoadedTestCase[] {
    return this.discoverTestCases();
  }

  public getTestCaseById(id: string): LoadedTestCase | undefined {
    const all = this.discoverTestCases();
    return all.find(c => c.id === id);
  }

  public getLabeledCases(): LoadedTestCase[] {
    const all = this.discoverTestCases();
    return all.filter(c => c.category !== 'UNLABELED');
  }

  public getUnlabeledCases(): LoadedTestCase[] {
    const all = this.discoverTestCases();
    return all.filter(c => c.category === 'UNLABELED');
  }

  public getCasesByCategory(category: string): LoadedTestCase[] {
    const all = this.discoverTestCases();
    return all.filter(c => c.category.toLowerCase() === category.toLowerCase());
  }

  public getQualityReport(): DatasetQualityReport {
    if (!this.qualityReport) {
      this.discoverTestCases();
    }
    return this.qualityReport!;
  }

  private scanDirRecursively(dir: string): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;

    const list = fs.readdirSync(dir);
    for (const file of list) {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      if (stat && stat.isDirectory()) {
        results.push(...this.scanDirRecursively(fullPath));
      } else {
        results.push(fullPath);
      }
    }
    return results;
  }
}
