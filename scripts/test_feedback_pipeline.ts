/**
 * End-to-end verification of the Analyst Verification & Ground-Truth Feedback Pipeline
 */

import { feedbackService } from '../server/feedbackService.js';
import { mlGovernanceStore } from '../server/mlGovernanceStore.js';
import { runRegressionTestSuite } from '../server/regressionTestSuite.js';

async function main() {
  console.log('=== 1. TESTING FEEDBACK SUBMISSION & DEDUPLICATION ===');
  const fb1 = feedbackService.submitVerification({
    analysisId: 'test-case-phish-harvest-1',
    emailSubject: 'Action Required: Confirm your Office 365 account credentials',
    sender: 'security@micros0ft-support-portal.com',
    rawBody: 'Your Microsoft 365 session has expired. Re-authenticate now at http://login.micros0ft-portal-auth.com/m365/auth.php',
    urls: ['http://login.micros0ft-portal-auth.com/m365/auth.php'],
    originalPrediction: {
      primaryCategory: 'PHISHING',
      secondaryCategories: ['CREDENTIAL_THEFT'],
      threatRisk: 92,
      spamBulkScore: 10,
      confidence: 0.94,
      probabilities: { PHISHING: 0.90, CREDENTIAL_THEFT: 0.08 },
      detectedTechniques: ['T1566.002'],
      evidence: ['Lookalike domain micros0ft-portal-auth.com']
    },
    verifiedGroundTruth: {
      primaryCategory: 'CREDENTIAL_THEFT',
      secondaryCategories: ['PHISHING', 'EXECUTIVE_IMPERSONATION'],
      verdict: 'Credential Theft',
      isMalicious: true,
      isSpam: false,
      correctedEvidence: ['Confirmed credential harvesting endpoint']
    },
    isCorrect: true,
    classificationType: 'CONFIRMED_THREAT',
    analyst: {
      id: 'analyst.chen@defense.corp',
      name: 'Chen Analyst',
      role: 'Senior SOC Analyst',
      confidence: 0.98
    },
    reason: 'Verified credential harvesting attack using Microsoft brand impersonation.'
  });

  console.log(`Submitted feedback: ID=${fb1.feedback.feedbackId}, Status=${fb1.feedback.status}, Weight=${fb1.feedback.sampleWeight}`);

  console.log('\n=== 2. TESTING FEEDBACK STATS ===');
  const stats = feedbackService.getFeedbackStats();
  console.log('Feedback stats:', JSON.stringify(stats, null, 2));

  console.log('\n=== 3. COMPILING VERSIONED DATASET ===');
  const dataset = feedbackService.createFeedbackDataset('e2e-test');
  console.log('Created dataset version:', dataset.version, 'with', dataset.sampleCount, 'samples');

  console.log('\n=== 4. RUNNING REGRESSION TEST SUITE (17 SCENARIOS) ===');
  const regResults = await runRegressionTestSuite();
  console.log(`Regression Test Results: ${regResults.passedCount}/${regResults.totalCases} passed (${regResults.passRate}%)`);
  for (const r of regResults.results) {
    const mark = r.passed ? '✓' : '✗';
    console.log(`  ${mark} ${r.name}: Pred=${r.actualClassification}, ThreatRisk=${r.actualThreatRisk}, Spam=${r.actualSpamLikelihood}, Verdict=${r.finalVerdict}`);
    if (!r.passed) {
      console.log(`     Failures: ${r.failures.join('; ')}`);
    }
  }

  console.log('\n=== 5. TESTING CHAMPION / CHALLENGER & PROMOTION GATES ===');
  const champ = mlGovernanceStore.getChampionModel();
  console.log(`Current Champion: ${champ.version} (Status: ${champ.status}, F1: ${champ.evaluationMetrics.f1})`);

  // Test promotion with candidate
  const candVersion = 'mailtrace-100m-v2';
  mlGovernanceStore.registerModelVersion({
    modelVersion: candVersion,
    architecture: 'Multimodal Deep Transformer (8 Layers, 12 Heads, 100M Parameters)',
    parameterCount: 128894258,
    trainableParameterCount: 128894258,
    trainingDatasetVersion: dataset.version,
    feedbackSamplesUsed: dataset.sampleCount,
    hardNegativesUsed: dataset.hardNegativeCount,
    trainingConfiguration: {
      epochs: 5,
      batchSize: 4,
      learningRate: 0.0001,
      optimizer: 'AdamW',
      lossWeights: { primary: 1.0, language: 0.2, binary: 0.5 }
    },
    featureSchemaVersion: 'MT-TENSOR-FUSION-V4',
    detectorVersions: { content: '2.1.0', url: '2.0.0', auth: '2.3.0', attachments: '1.9.0' },
    evaluationMetrics: {
      precision: 1.0,
      recall: 1.0,
      f1: 1.0,
      falsePositiveRate: 0.0,
      falseNegativeRate: 0.0,
      rocAuc: 0.999,
      prAuc: 0.998,
      calibration: 0.97,
      byCategory: {}
    },
    trainingHardware: 'Apple Silicon M-Series (MPS)',
    trainingTimestamp: new Date().toISOString(),
    gitCommit: '5e96e79',
    parentModelVersion: 'mailtrace-100m-v1',
    status: 'EVALUATING_CHALLENGER',
    checkpointPath: 'checkpoints/mailtrace-100m-v2.pt',
    evaluationTimestamp: new Date().toISOString()
  });

  const promResult = mlGovernanceStore.promoteModel(candVersion);
  console.log(`Promotion result for ${candVersion}:`, promResult.message);
  console.log('Passed gates:', promResult.promotionRecord.passedGates);
}

main().catch(console.error);
