// polyglot/typescript/target_manager.ts

import { URL } from 'url';
import * as fs from 'fs/promises';
import * as path from 'path';

export type AuthConfig = 
  | { bearer: string }
  | { basic: { user: string; pass: string } }
  | { cookie: string };

export interface TargetDefinition {
  id: string;
  url: URL;
  auth?: AuthConfig;
  headers?: Record<string, string>;
  depth: number;
  timeoutMs: number;
}

export interface DiscoveryResult {
  targets: TargetDefinition[];
  metadata: {
    discoveredAt: Date;
    totalUrls: number;
    duplicateUrls: number;
  };
}

export interface ScanSession {
  id: string;
  targetId: string;
  state: 'active' | 'paused' | 'completed' | 'failed';
  startTime: Date;
  discoveredTargets: TargetDefinition[];
  scanResults: Map<string, unknown>; // url -> raw response data
}

export interface ScanConfig {
  rulesetId: string;
  parallelWorkers: number;
  batchSize: number;
  timeoutMs: number;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function normalizeUrl(urlString: string): URL {
  try {
    let u = new URL(urlString);
    
    // Normalize protocol
    if (!u.protocol) {
      u = new URL(`https://${urlString}`);
    }
    
    // Remove trailing slash except for root
    if (u.pathname !== '/' && u.pathname.endsWith('/')) {
      u.pathname = u.pathname.slice(0, -1);
    }
    
    return u;
  } catch (e) {
    throw new Error(`Invalid URL: ${urlString}`);
  }
}

function generateTargetId(url: URL): string {
  const normalized = normalizeUrl(url.toString());
  // Use hash of path + query for consistent ID across sessions
  return Buffer.from(normalized.pathname + normalized.search).toString('base64');
}

function mergeHeaders(base: Record<string, string>, overrides: Record<string, string>): Record<string, string> {
  const merged = { ...base };
  Object.entries(overrides).forEach(([k, v]) => {
    if (v) merged[k] = v;
  });
  return merged;
}

// ============================================================================
// TARGET MANAGER CLASS
// ============================================================================

export class TargetManager {
  private static instance: TargetManager | null = null;
  
  private configPath: string;
  private defaultConfig: Partial<ScanConfig>;
  private sessions: Map<string, ScanSession> = new Map();
  private discoveredTargetsCache: Map<string, TargetDefinition[]> = new Map();

  constructor(configPath?: string, defaultConfig?: Partial<ScanConfig>) {
    this.configPath = configPath || process.env.DASTLITE_CONFIG_PATH || '.dastlite/config.json';
    this.defaultConfig = defaultConfig || {};
  }

  public static getInstance(): TargetManager {
    if (!this.instance) {
      this.instance = new TargetManager();
    }
    return this.instance;
  }

  // ============================================================================
  // CONFIGURATION LOADING
  // ============================================================================

  async loadConfig(): Promise<Partial<ScanConfig>> {
    try {
      const content = await fs.readFile(this.configPath, 'utf-8');
      const config: Partial<ScanConfig> = JSON.parse(content);
      
      if (config.timeoutMs) {
        this.defaultConfig.timeoutMs = config.timeoutMs;
      }
      
      return config;
    } catch (e) {
      // Config not found - use defaults
      console.debug(`No config file at ${this.configPath}, using defaults`);
      return {};
    }
  }

  // ============================================================================
  // TARGET PARSING
  // ============================================================================

  async parseTargets(
    source: string | string[] | URL,
    auth?: AuthConfig,
    options?: { depth?: number; timeoutMs?: number }
  ): Promise<TargetDefinition[]> {
    const targets: TargetDefinition[] = [];
    
    if (source instanceof URL) {
      return [this.createTarget(source.toString(), auth, options)];
    }

    // Parse as CSV or JSON array of strings
    let urls: string[];
    try {
      urls = typeof source === 'string' ? [source] : Array.isArray(source) ? source : [];
      
      if (urls.length === 0) return targets;
    } catch (e) {
      // Try to parse as JSON array of objects
      try {
        const parsed: any[] = JSON.parse(source);
        urls = parsed.map((p: any) => p.url || p).filter(Boolean);
      } catch {
        throw new Error(`Failed to parse targets from source`);
      }
    }

    // Deduplicate and normalize
    const seen = new Set<string>();
    for (const rawUrl of urls) {
      try {
        const normalized = normalizeUrl(rawUrl);
        const id = generateTargetId(normalized);
        
        if (!seen.has(id)) {
          seen.add(id);
          targets.push(this.createTarget(rawUrl, auth, options));
        }
      } catch (e) {
        console.warn(`Skipping invalid URL: ${rawUrl}`, e);
      }
    }

    return targets;
  }

  private createTarget(
    urlString: string, 
    auth?: AuthConfig, 
    options?: { depth?: number; timeoutMs?: number }
  ): TargetDefinition {
    const url = normalizeUrl(urlString);
    const id = generateTargetId(url);
    
    return {
      id,
      url,
      auth: auth || this.defaultConfig.auth,
      headers: this.defaultConfig.headers,
      depth: options?.depth ?? 1,
      timeoutMs: options?.timeoutMs ?? (this.defaultConfig.timeoutMs as number) ?? 30000,
    };
  }

  // ============================================================================
  // SURFACE DISCOVERY
  // ============================================================================

  async discoverSurface(
    target: TargetDefinition,
    session?: ScanSession
  ): Promise<DiscoveryResult> {
    const startTime = new Date();
    const discoveredUrls = new Set<string>();
    let duplicateCount = 0;

    try {
      while (target.depth > 0) {
        await this.fetchWithRetry(target, async () => {
          // HEAD request for efficiency
          const response = await fetch(target.url.toString(), {
            method: 'HEAD',
            headers: this.getAuthHeaders(target),
            signal: AbortSignal.timeout(5000),
          });

          if (response.ok) {
            discoveredUrls.add(target.url.toString());
            
            // Follow redirects by updating target URL
            if (response.headers.has('location')) {
              const nextUrl = response.headers.get('location');
              if (nextUrl) {
                try {
                  target.url = normalizeUrl(nextUrl);
                  duplicateCount++;
                } catch (e) {
                  console.warn(`Invalid redirect URL: ${nextUrl}`);
                }
              }
            }

            // Check depth limit
            const currentDepth = this.getFetchDepth(target, startTime);
            if (currentDepth >= target.depth) {
              throw new Error('Depth limit reached');
            }
          } else if (response.status === 301 || response.status === 302) {
            // Redirect - continue with updated URL
            duplicateCount++;
          } else {
            throw new Error(`HTTP ${response.status}`);
          }

        });

        target.depth--;
      }

    } catch (e: any) {
      if (e.message === 'Depth limit reached' || e.name === 'TimeoutError') {
        // Expected termination conditions
      } else if (!e.message.includes('HTTP')) {
        throw new Error(`Discovery failed for ${target.url}: ${e.message}`);
      }
    }

    return {
      targets: [target],
      metadata: {
        discoveredAt: startTime,
        totalUrls: discoveredUrls.size,
        duplicateUrls: duplicateCount,
      },
    };
  }

  private getFetchDepth(target: TargetDefinition, start: Date): number {
    return Math.max(0, target.depth - (Date.now() - start.getTime()) / 1000);
  }

  // ============================================================================
  // FETCHING WITH RETRY LOGIC
  // ============================================================================

  private async fetchWithRetry(
    target: TargetDefinition,
    fn: () => Promise<Response>,
    retries = 3
  ): Promise<void> {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        await fn();
        return;
      } catch (e: any) {
        if (attempt === retries - 1 || e.message.includes('Timeout')) {
          throw e;
        }
        // Exponential backoff
        await new Promise(r => setTimeout(r, Math.pow(2, attempt) * 50));
      }
    }
  }

  private getAuthHeaders(target: TargetDefinition): Record<string, string> {
    const headers = target.headers || {};
    
    if (target.auth?.bearer) {
      headers['Authorization'] = `Bearer ${target.auth.bearer}`;
    } else if (target.auth?.basic) {
      const encoded = Buffer.from(
        `${target.auth.basic.user}:${target.auth.basic.pass}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${encoded}`;
    } else if (target.auth?.cookie) {
      headers['Cookie'] = target.auth.cookie;
    }

    return headers;
  }

  // ============================================================================
  // SESSION MANAGEMENT
  // ============================================================================

  async createSession(
    targetId: string,
    config?: Partial<ScanConfig>
  ): Promise<ScanSession> {
    const session: ScanSession = {
      id: `session_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      targetId,
      state: 'active',
      startTime: new Date(),
      discoveredTargets: [],
      scanResults: new Map(),
    };

    if (config?.parallelWorkers) {
      session.id = `${session.id}_p${config.parallelWorkers}`;
    }

    this.sessions.set(session.id, session);
    
    // Load or create target definition
    const targets = await this.loadOrCreateTarget(targetId);
    session.discoveredTargets.push(...targets);

    return session;
  }

  private async loadOrCreateTarget(id: string): Promise<TargetDefinition[]> {
    if (this.discoveredTargetsCache.has(id)) {
      return this.discoveredTargetsCache.get(id)!;
    }

    // Try to find target from existing sessions
    for (const [sid, session] of this.sessions) {
      const found = session.discoveredTargets.find(t => t.id === id);
      if (found) {
        this.discoveredTargetsCache.set(id, [...session.discoveredTargets]);
        return session.discoveredTargets;
      }
    }

    // Try to find from config file
    try {
      const content = await fs.readFile(this.configPath, 'utf-8');
      const config: any = JSON.parse(content);
      
      if (config.targets) {
        for (const t of Array.isArray(config.targets) ? config.targets : []) {
          if (t.id === id || t.url?.toString() === id) {
            this.discoveredTargetsCache.set(id, [this.createTarget(t.url.toString())]);
            return [this.createTarget(t.url.toString())];
          }
        }
      }
    } catch (e) {}

    // Default: create from ID hash
    const defaultUrl = new URL(`https://target-${id}.example.com`);
    this.discoveredTargetsCache.set(id, [this.createTarget(defaultUrl.toString())]);
    return [this.createTarget(defaultUrl.toString())];
  }

  async getActiveSession(targetId: string): Promise<ScanSession | undefined> {
    for (const [sid, session] of this.sessions) {
      if (session.targetId === targetId && session.state === 'active') {
        return session;
      }
    }
    return undefined;
  }

  async pauseSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.state = 'paused';
    }
  }

  async completeSession(
    sessionId: string, 
    results?: Map<string, unknown>
  ): Promise<ScanSession | undefined> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    if (results) {
      for (const [url, data] of results) {
        session.scanResults.set(url, data);
      }
    }

    session.state = 'completed';
    session.startTime = new Date(); // Update end time
    
    this.sessions.delete(sessionId);
    return session;
  }

  async failSession(
    sessionId: string, 
    error?: Error
  ): Promise<ScanSession | undefined> {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.state = 'failed';
    session.startTime = new Date();
    
    // Store error context
    (session as any).error = error?.message || 'Unknown error';
    
    this.sessions.delete(sessionId);
    return session;
  }

  // ============================================================================
  // AGGREGATION & SARIF PREPARATION
  // ============================================================================

  async aggregateResults(
    targetId: string,
    includeMetadata = true
  ): Promise<{
    targets: TargetDefinition[];
    results: Map<string, unknown>;
    metadata?: {
      sessionsCompleted: number;
      totalTargets: number;
      startTime: Date;
      endTime: Date | null;
    };
  }> {
    const activeSession = await this.getActiveSession(targetId);
    
    if (!activeSession) {
      // Try to find any completed session for this target
      let foundSession: ScanSession | undefined;
      
      for (const [sid, session] of this.sessions) {
        if (session.targetId === targetId && 
            (session.state === 'completed' || session.state === 'failed')) {
          foundSession = session;
          break;
        }
      }

      if (!foundSession) {
        return { targets: [], results: new Map() };
      }

      activeSession = foundSession;
    }

    const metadata: any = {};
    
    if (includeMetadata && activeSession.state === 'completed') {
      metadata.sessionsCompleted = 1;
      metadata.totalTargets = activeSession.discoveredTargets.length;
      metadata.startTime = activeSession.startTime;
      metadata.endTime = new Date();
    }

    return {
      targets: activeSession.discoveredTargets,
      results: activeSession.scanResults,
      metadata,
    };
  }

  // ============================================================================
  // EXPORT & PERSISTENCE
  // ============================================================================

  async exportSarif(
    targetId: string,
    outputPath?: string
  ): Promise<string> {
    const { targets, results, metadata } = await this.aggregateResults(targetId);
    
    if (targets.length === 0) {
      throw new Error(`No scan data found for target ${targetId}`);
    }

    // Build SARIF structure
    const sarif: any = {
      $schema: 'http://schematics.org/sarif/2.1.0',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'dastlite',
            informationUri: 'https://github.com/polyglot/dastlite',
            version: process.env.npm_package_version || '1.0.0',
          },
        },
        targets: targets.map(t => t.url.toString()),
        results: [],
      }],
    };

    // Convert results to SARIF format
    for (const [url, data] of results) {
      if (data && typeof data === 'object') {
        const sarifResult: any = {
          ruleId: data.ruleId || 'dastlite-default',
          level: data.level || 'note',
          message: { text: String(data.message || '') },
          locations: [{
            physicalLocation: