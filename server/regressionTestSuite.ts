/**
 * MailTrace AI - Automated Security & Forensic Regression Test Suite
 * ==================================================================
 * Authoritative regression test runner that loads ALL real test cases
 * directly from `dataset/testing/` via `TestDatasetLoader`.
 * 
 * ZERO hardcoded emails in code.
 * ZERO fallback to demo/mock data.
 */

import { RegressionTestResult, ThreatCategory } from '../src/types/forensics.js';
import { runEmailAnalysisPipeline } from './emailAnalysisPipeline.js';
import { TestDatasetLoader, LoadedTestCase } from './testing/testDatasetLoader.js';

export interface ComprehensiveRegressionResult extends RegressionTestResult {
  groundTruth: ThreatCategory | 'UNLABELED';
  prediction: ThreatCategory;
  threatRisk: number;
  spamBulkScore: number;
  evidenceCount: number;
  finalVerdict: string;
  isHardNegative: boolean;
}

export interface RegressionSuiteSummary {
  totalCases: number;
  labeledCases: number;
  unlabeledCases: number;
  passedCount: number;
  failedCount: number;
  passRate: number;
  results: ComprehensiveRegressionResult[];
}

export function getRegressionTestCases(customTestingDir?: string): LoadedTestCase[] {
  const loader = new TestDatasetLoader(customTestingDir);
  return loader.loadAllTestCases();
}

export const REGRESSION_TEST_CASES = getRegressionTestCases();

export async function runRegressionTestSuite(customTestingDir?: string): Promise<RegressionSuiteSummary> {
  const loader = new TestDatasetLoader(customTestingDir);
  const testCases: LoadedTestCase[] = loader.loadAllTestCases();

  const results: ComprehensiveRegressionResult[] = [];

  for (const tc of testCases) {
    const startTime = Date.now();
    const failures: string[] = [];

    try {
      const res = await runEmailAnalysisPipeline(tc.rawEml, tc.id, false, { skipExternalAI: true });
      const threatRisk = res.overallRiskScore;
      const spamLikelihood = res.spamLikelihood ?? res.spam?.score ?? 0;
      const authenticity = res.authenticityConfidence ?? 85;
      const classification = res.primaryClassification;
      const action = res.threatAssessment?.recommendedAction || 'allow';

      // If test case has ground truth / expectations, validate them
      if (tc.expected && tc.expected.classification && tc.expected.classification.length > 0) {
        const expectedClasses = tc.expected.classification;
        const classMatch = expectedClasses.some(ec =>
          ec.toLowerCase() === classification.toLowerCase() ||
          (ec.toLowerCase() === 'legitimate' && (classification.toLowerCase() === 'legitimate' || classification.toLowerCase() === 'benign')) ||
          (ec.toLowerCase().includes('scam') && classification.toLowerCase().includes('scam'))
        );

        if (!classMatch) {
          failures.push(`Expected classification in [${expectedClasses.join(', ')}], got "${classification}"`);
        }
      }

      // Threat risk bounds
      if (tc.expected?.threatRiskMin !== undefined && threatRisk < tc.expected.threatRiskMin) {
        failures.push(`Threat risk (${threatRisk}) below minimum (${tc.expected.threatRiskMin})`);
      }
      if (tc.expected?.threatRiskMax !== undefined && threatRisk > tc.expected.threatRiskMax) {
        failures.push(`Threat risk (${threatRisk}) exceeded maximum allowed (${tc.expected.threatRiskMax})`);
      }

      // Spam likelihood bounds
      if (tc.expected?.spamLikelihoodMin !== undefined && spamLikelihood < tc.expected.spamLikelihoodMin) {
        failures.push(`Spam likelihood (${spamLikelihood}) below minimum (${tc.expected.spamLikelihoodMin})`);
      }
      if (tc.expected?.spamLikelihoodMax !== undefined && spamLikelihood > tc.expected.spamLikelihoodMax) {
        failures.push(`Spam likelihood (${spamLikelihood}) exceeded maximum (${tc.expected.spamLikelihoodMax})`);
      }

      // Authenticity bounds
      if (tc.expected?.authenticityMin !== undefined && authenticity < tc.expected.authenticityMin) {
        failures.push(`Authenticity (${authenticity}) below minimum (${tc.expected.authenticityMin})`);
      }

      const passed = failures.length === 0;

      results.push({
        caseId: tc.id,
        name: tc.name,
        passed,
        actualClassification: classification,
        actualThreatRisk: threatRisk,
        actualSpamLikelihood: spamLikelihood,
        actualAuthenticity: authenticity,
        actualAction: action,
        failures,
        durationMs: Date.now() - startTime,
        groundTruth: tc.groundTruth,
        prediction: classification,
        threatRisk,
        spamBulkScore: spamLikelihood,
        evidenceCount: (res as any).forensicEvidence?.length || res.emailContentAnalysis?.socialEngineering?.length || 0,
        finalVerdict: (res as any).verdict?.summary || classification,
        isHardNegative: !!tc.isHardNegative
      });
    } catch (err: any) {
      results.push({
        caseId: tc.id,
        name: tc.name,
        passed: false,
        actualClassification: 'Legitimate',
        actualThreatRisk: 0,
        actualSpamLikelihood: 0,
        actualAuthenticity: 0,
        actualAction: 'error',
        failures: [`Execution error: ${err.message}`],
        durationMs: Date.now() - startTime,
        groundTruth: tc.groundTruth,
        prediction: 'Legitimate',
        threatRisk: 0,
        spamBulkScore: 0,
        evidenceCount: 0,
        finalVerdict: 'ERROR',
        isHardNegative: !!tc.isHardNegative
      });
    }
  }

  const labeledCount = results.filter(r => r.groundTruth !== 'UNLABELED').length;
  const unlabeledCount = results.length - labeledCount;
  const passedCount = results.filter(r => r.passed).length;
  const failedCount = results.length - passedCount;

  return {
    totalCases: results.length,
    labeledCases: labeledCount,
    unlabeledCases: unlabeledCount,
    passedCount,
    failedCount,
    passRate: Number(((passedCount / results.length) * 100).toFixed(1)),
    results
  };
}

// Direct CLI execution support
if (typeof process !== 'undefined' && process.argv && process.argv[1] && (process.argv[1].endsWith('regressionTestSuite.ts') || process.argv[1].endsWith('regressionTestSuite.js'))) {
  console.log('Running MailTrace AI Regression Test Suite from dataset/testing/ ...\n');
  runRegressionTestSuite().then(res => {
    console.log(`=======================================================`);
    console.log(`REGRESSION SUITE COMPLETED: ${res.passedCount}/${res.totalCases} PASSED (${res.passRate}%)`);
    console.log(`Total Cases: ${res.totalCases} | Labeled: ${res.labeledCases} | Unlabeled: ${res.unlabeledCases}`);
    console.log(`=======================================================`);
    res.results.forEach((r, idx) => {
      const mark = r.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`${mark} [${idx + 1}/${res.totalCases}] ${r.name}`);
      console.log(`       Verdict: ${r.actualClassification} | Threat Risk: ${r.actualThreatRisk}/100 | Spam/Bulk: ${r.actualSpamLikelihood}/100 | Duration: ${r.durationMs}ms`);
      if (!r.passed && r.failures && r.failures.length > 0) {
        r.failures.forEach(f => console.log(`       → Failure: ${f}`));
      }
    });
    console.log(`\nFinal Regression Result: ${res.failedCount === 0 ? 'ALL SCENARIOS PASSED' : `${res.failedCount} SCENARIOS FAILED`}`);
    if (res.failedCount > 0) {
      process.exit(1);
    }
  }).catch(err => {
    console.error('Fatal error running regression suite:', err);
    process.exit(1);
  });
}
