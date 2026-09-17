/**
 * MailTrace AI — Server-side Model Manager Service
 * ===============================================
 * Orchestrates model manifest retrieval, runtime status probing,
 * GCS artifact lifecycle coordination, and deep ML forward passes.
 */

import fs from 'fs';
import path from 'path';
import { mlTransformer100M } from '../engines/mlTransformer100M.js';

export interface ModelManifest {
  modelId: string;
  version: string;
  architecture: string;
  parameterCount: number;
  artifact: {
    provider: string;
    bucketEnv: string;
    objectEnv: string;
    defaultObject?: string;
    sha256: string;
    sizeBytes: number;
  };
  config?: Record<string, any>;
  production: boolean;
}

export class ModelManagerService {
  private manifestPath: string;

  constructor() {
    this.manifestPath = path.resolve(process.cwd(), 'ml/model_registry/model_manifest.json');
  }

  public getManifest(): ModelManifest | null {
    try {
      if (fs.existsSync(this.manifestPath)) {
        const raw = fs.readFileSync(this.manifestPath, 'utf-8');
        return JSON.parse(raw);
      }
    } catch (err) {
      console.error('[ModelManagerService] Error reading manifest:', err);
    }
    return null;
  }

  public async getStatus() {
    return await mlTransformer100M.getProductionModelStatus();
  }

  public async forwardPass(payload: any) {
    return mlTransformer100M.forwardPass(payload);
  }
}

export const serverModelManager = new ModelManagerService();
