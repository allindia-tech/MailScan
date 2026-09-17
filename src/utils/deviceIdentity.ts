/**
 * MailTrace AI - Client-Side Device Identity & Real-Time Sync Service
 * Manages persistent pseudonymous device identity, pairing with Chrome Extension,
 * and SSE real-time state synchronization.
 */

import { registerDevice, syncDeviceState } from '../services/api.js';

export interface DeviceIdentityState {
  deviceId: string;
  isPairedWithExtension: boolean;
  extensionVersion?: string;
  clientType: 'website' | 'extension';
  syncConnected: boolean;
}

export interface SharedInvestigationState {
  activeEmailId?: string;
  activeSubject?: string;
  riskScore?: number;
  verdict?: string;
  deepLinkPath?: string;
  lastUpdated?: string;
  source?: 'website' | 'extension';
  analysisResult?: any;
}

type SyncListener = (state: SharedInvestigationState) => void;

class DeviceIdentityManager {
  private deviceId: string = '';
  private isPaired: boolean = false;
  private extensionVersion: string | undefined;
  private listeners: Set<SyncListener> = new Set();
  private eventSource: EventSource | null = null;
  private isInitialized: boolean = false;

  public async init(): Promise<DeviceIdentityState> {
    if (this.isInitialized && this.deviceId) {
      return this.getState();
    }

    // 1. Check if extension exists and request its deviceId
    let extensionIdFromRuntime: string | null = null;
    try {
      if (typeof window !== 'undefined' && (window as any).chrome?.runtime?.sendMessage) {
        // Try pinging extension if extensionId is stored or via window postMessage bridge
        const extResp = await this.queryExtensionDirectly();
        if (extResp?.deviceId) {
          extensionIdFromRuntime = extResp.deviceId;
          this.isPaired = true;
          this.extensionVersion = extResp.version;
        }
      }
    } catch {
      // Extension not directly accessible or message timed out
    }

    // 2. Read local storage
    let localId = typeof localStorage !== 'undefined' ? localStorage.getItem('mailtrace_device_id') : null;

    if (extensionIdFromRuntime) {
      // Extension is authoritative
      this.deviceId = extensionIdFromRuntime;
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('mailtrace_device_id', extensionIdFromRuntime);
      }
    } else if (localId && localId.startsWith('mt_dev_')) {
      this.deviceId = localId;
    } else {
      // Generate new cryptographically random device ID
      const randomBytes = new Uint8Array(16);
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(randomBytes);
      } else {
        for (let i = 0; i < 16; i++) randomBytes[i] = Math.floor(Math.random() * 256);
      }
      const randomHex = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      this.deviceId = `mt_dev_${randomHex}`;
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('mailtrace_device_id', this.deviceId);
      }
    }

    // 3. Register with backend
    try {
      await registerDevice({
        deviceId: this.deviceId,
        clientType: 'website',
        browser: navigator.userAgent.includes('Chrome') ? 'Google Chrome' : navigator.userAgent.includes('Firefox') ? 'Mozilla Firefox' : 'Browser Client',
        os: navigator.platform || 'Client OS',
        userAgent: navigator.userAgent,
        extensionVersion: this.extensionVersion
      });
    } catch (e) {
      console.warn('[MailTrace][Identity] Offline device registration warning:', e);
    }

    // 4. Start SSE real-time sync stream
    this.startSseStream();
    this.isInitialized = true;

    return this.getState();
  }

  private queryExtensionDirectly(): Promise<{ deviceId?: string; version?: string } | null> {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(null), 800);
      try {
        // Send custom event that content script can forward
        const onResponse = (event: MessageEvent) => {
          if (event.data?.type === 'MAILTRACE_EXTENSION_IDENTITY_RESPONSE') {
            window.removeEventListener('message', onResponse);
            clearTimeout(timeout);
            resolve(event.data);
          }
        };
        window.addEventListener('message', onResponse);
        window.postMessage({ type: 'MAILTRACE_QUERY_EXTENSION_IDENTITY' }, '*');
      } catch {
        clearTimeout(timeout);
        resolve(null);
      }
    });
  }

  private startSseStream() {
    if (typeof window === 'undefined' || typeof EventSource === 'undefined') return;
    if (this.eventSource) {
      this.eventSource.close();
    }

    try {
      this.eventSource = new EventSource('/api/device/stream');
      this.eventSource.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'STATE_SYNC' && payload.state) {
            this.notifyListeners(payload.state);
          }
        } catch (e) {
          console.error('[MailTrace][SSE] Parse error:', e);
        }
      };

      this.eventSource.onerror = () => {
        // Auto-reconnect managed by EventSource
      };
    } catch (err) {
      console.warn('[MailTrace][SSE] Stream setup warning:', err);
    }
  }

  public subscribe(listener: SyncListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(state: SharedInvestigationState) {
    for (const listener of this.listeners) {
      try {
        listener(state);
      } catch (e) {
        console.error('[MailTrace][SyncListener] Error in callback:', e);
      }
    }
  }

  public async broadcastState(state: Omit<SharedInvestigationState, 'deviceId'>) {
    if (!this.deviceId) await this.init();
    try {
      await syncDeviceState({
        deviceId: this.deviceId,
        source: 'website',
        ...state
      });
    } catch (e) {
      console.warn('[MailTrace][Sync] Broadcast warning:', e);
    }
  }

  public getDeviceId(): string {
    return this.deviceId || (typeof localStorage !== 'undefined' ? localStorage.getItem('mailtrace_device_id') || '' : '');
  }

  public getState(): DeviceIdentityState {
    return {
      deviceId: this.deviceId,
      isPairedWithExtension: this.isPaired,
      extensionVersion: this.extensionVersion,
      clientType: 'website',
      syncConnected: !!this.eventSource && this.eventSource.readyState === EventSource.OPEN
    };
  }
}

export const deviceIdentityManager = new DeviceIdentityManager();
