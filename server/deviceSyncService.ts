/**
 * MailTrace AI - Device Identity & Real-Time State Synchronization Service
 * Provides cryptographically secure, privacy-preserving device registration,
 * real-time SSE event streaming, and synchronized investigation state across
 * the Chrome Extension and Web Forensic Console.
 */

import crypto from 'crypto';
import express from 'express';
import { EventEmitter } from 'events';
import { socStore } from './store.js';

export interface DeviceIdentity {
  deviceId: string;
  deviceType: 'extension' | 'web_console' | 'desktop_agent';
  deviceName: string;
  platform: string;
  browser: string;
  extensionVersion?: string;
  webConsoleVersion?: string;
  ipAddress?: string;
  createdAt: string;
  lastSeenAt: string;
  syncVersion: number;
  activeInvestigationId?: string;
  status: 'ONLINE' | 'ACTIVE' | 'IDLE' | 'UNLINKED';
  capabilities: string[];
}

export interface SyncedInvestigationState {
  deviceId: string;
  currentEmailId?: string;
  currentSubject?: string;
  currentSender?: string;
  currentRiskScore?: number;
  currentSeverity?: string;
  currentClassification?: string;
  activeAlertCount: number;
  openCasesCount: number;
  lastAnalysisTimestamp: string;
  synchronizedAt: string;
  analysisResult?: any;
}

class DeviceSyncService extends EventEmitter {
  private devices: Map<string, DeviceIdentity> = new Map();
  private sseClients: Map<string, express.Response> = new Map();
  private syncedStates: Map<string, SyncedInvestigationState> = new Map();
  private latestSyncedState: SyncedInvestigationState | null = null;

  constructor() {
    super();
    this.seedDefaultDevices();
  }

  private seedDefaultDevices() {
    const primaryConsoleId = 'mt_dev_console_primary_soc';
    this.devices.set(primaryConsoleId, {
      deviceId: primaryConsoleId,
      deviceType: 'web_console',
      deviceName: 'Master SOC Forensic Console',
      platform: 'Enterprise Web Client',
      browser: 'Chrome / WebKit',
      webConsoleVersion: '2.4.0',
      createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
      lastSeenAt: new Date().toISOString(),
      syncVersion: 1,
      status: 'ONLINE',
      capabilities: ['ANALYSIS_INGEST', 'DFIR_CASE_MANAGEMENT', 'ML_GOVERNANCE', 'SSE_REALTIME']
    });
  }

  public generateDeviceId(prefix: 'ext' | 'web' = 'web'): string {
    const randomUuid = crypto.randomUUID();
    return `mt_dev_${prefix}_${randomUuid.replace(/-/g, '').substring(0, 16)}`;
  }

  public registerOrHeartbeat(params: {
    deviceId?: string;
    clientType?: 'extension' | 'website' | 'web_console' | 'desktop_agent';
    deviceName?: string;
    os?: string;
    browser?: string;
    userAgent?: string;
    platform?: string;
    extensionVersion?: string;
    webConsoleVersion?: string;
    ipAddress?: string;
    activeInvestigationId?: string;
  }): DeviceIdentity {
    let deviceId = params.deviceId;
    const deviceType = params.clientType === 'extension' ? 'extension' : 'web_console';

    if (!deviceId || !deviceId.startsWith('mt_dev_')) {
      const prefix = deviceType === 'extension' ? 'ext' : 'web';
      deviceId = this.generateDeviceId(prefix);
    }

    const now = new Date().toISOString();
    const existing = this.devices.get(deviceId);

    const deviceName = params.deviceName || (
      deviceType === 'extension'
        ? `Chrome Extension (${params.browser || 'Webmail Client'})`
        : `Web Forensic Console (${params.os || params.platform || 'Workstation'})`
    );

    const updatedDevice: DeviceIdentity = {
      deviceId,
      deviceType,
      deviceName,
      platform: params.os || params.platform || existing?.platform || 'Unknown OS',
      browser: params.browser || existing?.browser || 'Chrome/Blink',
      extensionVersion: params.extensionVersion || existing?.extensionVersion || '2.4.0',
      webConsoleVersion: params.webConsoleVersion || existing?.webConsoleVersion || '2.4.0',
      ipAddress: params.ipAddress || existing?.ipAddress || '127.0.0.1',
      createdAt: existing?.createdAt || now,
      lastSeenAt: now,
      syncVersion: (existing?.syncVersion || 0) + 1,
      activeInvestigationId: params.activeInvestigationId || existing?.activeInvestigationId,
      status: 'ONLINE',
      capabilities: [
        'ANALYSIS_INGEST',
        deviceType === 'extension' ? 'WEBMAIL_DOM_EXTRACTION' : 'FULL_RFC5322_MIME',
        'ML_100M_INFERENCE',
        'REALTIME_STATE_SYNC'
      ]
    };

    this.devices.set(deviceId, updatedDevice);

    this.broadcastEvent('DEVICE_REGISTERED', {
      device: updatedDevice,
      totalActiveDevices: this.devices.size
    });

    return updatedDevice;
  }

  public registerDevice(params: any): DeviceIdentity {
    return this.registerOrHeartbeat(params);
  }

  public performHandshake(params: {
    websiteDeviceId?: string;
    extensionDeviceId?: string;
    authenticatedUserId?: string;
  }): {
    status: 'MATCHED' | 'MISMATCH' | 'SINGLE_DEVICE';
    primaryDeviceId: string;
    websiteDeviceId: string | null;
    extensionDeviceId: string | null;
    message: string;
  } {
    const webId = params.websiteDeviceId || null;
    const extId = params.extensionDeviceId || null;

    if (webId && extId) {
      if (webId === extId) {
        return {
          status: 'MATCHED',
          primaryDeviceId: extId,
          websiteDeviceId: webId,
          extensionDeviceId: extId,
          message: 'Website and extension device identities are fully synchronized.'
        };
      } else {
        return {
          status: 'MISMATCH',
          primaryDeviceId: extId, // Extension is authoritative when installed
          websiteDeviceId: webId,
          extensionDeviceId: extId,
          message: 'Browser identity mismatch detected between Website and Extension. Handshake requires verification.'
        };
      }
    }

    const primary = extId || webId || this.generateDeviceId('web');
    return {
      status: 'SINGLE_DEVICE',
      primaryDeviceId: primary,
      websiteDeviceId: webId,
      extensionDeviceId: extId,
      message: 'Single device identity active.'
    };
  }

  public listDevices(): DeviceIdentity[] {
    return Array.from(this.devices.values()).sort(
      (a, b) => new Date(b.lastSeenAt).getTime() - new Date(a.lastSeenAt).getTime()
    );
  }

  public getAllDevices(): DeviceIdentity[] {
    return this.listDevices();
  }

  public getPairedDevicesCount(): number {
    return this.devices.size;
  }

  public getDevice(deviceId: string): DeviceIdentity | undefined {
    return this.devices.get(deviceId);
  }

  public unregisterDevice(deviceId: string): boolean {
    const deleted = this.devices.delete(deviceId);
    this.syncedStates.delete(deviceId);
    if (deleted) {
      this.broadcastEvent('DEVICE_UNREGISTERED', { deviceId });
    }
    return deleted;
  }

  public syncState(state: {
    deviceId: string;
    currentEmailId?: string;
    activeEmailId?: string;
    currentSubject?: string;
    activeSubject?: string;
    currentSender?: string;
    currentRiskScore?: number;
    riskScore?: number;
    currentSeverity?: string;
    currentClassification?: string;
    verdict?: string;
    deepLinkPath?: string;
    analysisResult?: any;
    source?: string;
  }): SyncedInvestigationState {
    const now = new Date().toISOString();
    const activeAlerts = Array.from(socStore.alerts.values()).filter(a => a.status === 'NEW').length;
    const openCases = Array.from(socStore.cases.values()).filter(c => c.status === 'OPEN' || c.status === 'INVESTIGATING').length;

    const emailId = state.currentEmailId || state.activeEmailId;
    const subject = state.currentSubject || state.activeSubject;
    const score = state.currentRiskScore !== undefined ? state.currentRiskScore : state.riskScore;
    const classification = state.currentClassification || state.verdict;

    const syncedState: SyncedInvestigationState = {
      deviceId: state.deviceId,
      currentEmailId: emailId,
      currentSubject: subject,
      currentSender: state.currentSender,
      currentRiskScore: score,
      currentSeverity: state.currentSeverity,
      currentClassification: classification,
      activeAlertCount: activeAlerts,
      openCasesCount: openCases,
      lastAnalysisTimestamp: now,
      synchronizedAt: now,
      analysisResult: state.analysisResult
    };

    this.syncedStates.set(state.deviceId, syncedState);
    this.latestSyncedState = syncedState;

    const dev = this.devices.get(state.deviceId);
    if (dev) {
      dev.lastSeenAt = now;
      dev.activeInvestigationId = state.currentEmailId;
      dev.syncVersion += 1;
    }

    this.emit('state_sync', syncedState);

    this.broadcastEvent('STATE_SYNCHRONIZED', {
      syncedState,
      broadcasterDeviceId: state.deviceId
    });

    return syncedState;
  }

  public syncInvestigationState(state: any): SyncedInvestigationState {
    return this.syncState(state);
  }

  public getLatestSyncState(): SyncedInvestigationState | null {
    if (this.latestSyncedState) return this.latestSyncedState;
    const states = Array.from(this.syncedStates.values());
    if (states.length === 0) return null;
    states.sort((a, b) => new Date(b.synchronizedAt).getTime() - new Date(a.synchronizedAt).getTime());
    return states[0];
  }

  public getLatestSyncedState(): SyncedInvestigationState | null {
    return this.getLatestSyncState();
  }

  public addSseClient(clientId: string, res: express.Response) {
    this.sseClients.set(clientId, res);
    const initialPayload = {
      type: 'INIT_SNAPSHOT',
      devices: this.getAllDevices(),
      latestSyncedState: this.getLatestSyncState(),
      activeAlertsCount: socStore.alerts.size,
      totalAnalyzed: socStore.analyzedEmails.size,
      timestamp: new Date().toISOString()
    };
    res.write(`data: ${JSON.stringify(initialPayload)}\n\n`);
  }

  public removeSseClient(clientId: string) {
    this.sseClients.delete(clientId);
  }

  public broadcastEvent(eventType: string, payload: any) {
    const message = JSON.stringify({
      type: eventType,
      data: payload,
      timestamp: new Date().toISOString()
    });

    for (const [clientId, clientRes] of this.sseClients.entries()) {
      try {
        clientRes.write(`data: ${message}\n\n`);
      } catch (err) {
        this.sseClients.delete(clientId);
      }
    }
  }
}

export const deviceSyncService = new DeviceSyncService();
