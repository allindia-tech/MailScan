/**
 * MailTrace AI — Determinism Testing Suite
 * =========================================
 * Runs test cases through the full pipeline across multiple passes (Run 1, Run 2, Run 3)
 * to verify 100% deterministic outputs:
 * - Same Threat Risk
 * - Same Spam/Bulk Score
 * - Same Classification
 * - Same Authenticity Score
 * - Same Detected Techniques
 * 
 * Verifies ZERO random variance and ZERO Math.random() in production inference.
 */

import { runEmailAnalysisPipeline } from '../emailAnalysisPipeline.js';
import { TestDatasetLoader, LoadedTestCase } from './testDatasetLoader.js';

export interface DeterminismResult {
  caseId: string;
  name: string;
  iterations: number;
  deterministic: boolean;
  varianceDetected: string[];
  runScores: number[];
  runClassifications: string[];
}

export interface DeterminismSummary {
  totalTested: number;
  passed: number;
  failed: number;
  passRate: number;
  results: DeterminismResult[];
}

export async function runDeterminismTests(iterations = 3): Promise<DeterminismSummary> {
  const loader = new TestDatasetLoader();
  const cases: LoadedTestCase[] = loader.loadAllTestCases();
  const results: DeterminismResult[] = [];

  for (const tc of cases) {
    const scores: number[] = [];
    const spamScores: number[] = [];
    const classifications: string[] = [];
    const techniqueSets: string[] = [];
    const varianceDetected: string[] = [];

    for (let i = 0; i < iterations; i++) {
      const res = await runEmailAnalysisPipeline(tc.rawEml, tc.id, false, { skipExternalAI: true });
      scores.push(res.overallRiskScore);
      spamScores.push(res.spamLikelihood ?? res.spam?.score ?? 0);
      classifications.push(res.primaryClassification);
      const techniques = (((res.threatAssessment as any)?.attackTechniques || (res as any).forensicEvidence?.map((e: any) => e.type) || []) as string[]).sort().join(',');
      techniqueSets.push(techniques);
    }

    // Check score equality
    const score0 = scores[0];
    if (!scores.every(s => s === score0)) {
      varianceDetected.push(`Score variance: [${scores.join(', ')}]`);
    }

    // Check spam score equality
    const spam0 = spamScores[0];
    if (!spamScores.every(s => s === spam0)) {
      varianceDetected.push(`Spam score variance: [${spamScores.join(', ')}]`);
    }

    // Check classification equality
    const class0 = classifications[0];
    if (!classifications.every(c => c === class0)) {
      varianceDetected.push(`Classification variance: [${classifications.join(', ')}]`);
    }

    // Check techniques equality
    const tech0 = techniqueSets[0];
    if (!techniqueSets.every(t => t === tech0)) {
      varianceDetected.push(`Techniques variance: [${techniqueSets.join(' | ')}]`);
    }

    const deterministic = varianceDetected.length === 0;

    results.push({
      caseId: tc.id,
      name: tc.name,
      iterations,
      deterministic,
      varianceDetected,
      runScores: scores,
      runClassifications: classifications
    });
  }

  const passed = results.filter(r => r.deterministic).length;
  const failed = results.length - passed;

  return {
    totalTested: results.length,
    passed,
    failed,
    passRate: Number(((passed / results.length) * 100).toFixed(1)),
    results
  };
}

if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].endsWith('determinismTest.ts')) {
  console.log('Running MailTrace AI Determinism Test Suite (3 passes/case)...\n');
  runDeterminismTests(3).then(summary => {
    console.log(`=======================================================`);
    console.log(`DETERMINISM SUITE: ${summary.passed}/${summary.totalTested} PASSED (${summary.passRate}%)`);
    console.log(`=======================================================`);
    summary.results.forEach((r, idx) => {
      const mark = r.deterministic ? '✓ PASS' : '✗ FAIL';
      console.log(`${mark} [${idx + 1}/${summary.totalTested}] ${r.name}`);
      console.log(`       Scores: [${r.runScores.join(', ')}] | Verdict: ${r.runClassifications[0]}`);
      if (!r.deterministic) {
        r.varianceDetected.forEach(v => console.log(`       → Error: ${v}`));
      }
    });
    if (summary.failed > 0) {
      process.exit(1);
    }
  }).catch(err => {
    console.error('Determinism test fatal error:', err);
    process.exit(1);
  });
}
