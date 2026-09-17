/**
 * MailTrace AI - Forensic Email Scenarios
 */

export interface SampleEmailScenario {
  id: string;
  name: string;
  scenarioTag: string;
  threatType: string;
  expectedRisk: number;
  description: string;
  rawEml: string;
}

// All demo scenarios removed as requested
export const SAMPLE_SCENARIOS: SampleEmailScenario[] = [];
