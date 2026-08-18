import * as fs from 'fs';
import * as path from 'path';
import { z, ZodError } from 'zod';

// =============================================================================
// CONFIGURATION SCHEMA TYPES
// =============================================================================

export interface DASTConfig {
  targets: string[];
  auth: AuthConfig;
  ruleset: RulesetConfig;
  output: OutputConfig;
}

export interface AuthConfig {
  type: 'header' | 'cookie' | 'oauth2' | 'basic';
  header?: Record<string, string>;
  cookie?: string[];
  oauth2?: OAuth2Config;
  basic?: BasicAuthConfig;
}

export interface OAuth2Config {
  client_id: string;
  client_secret: string;
  token_url: string;
  scopes: string[];
  refresh_token?: string;
}

export interface BasicAuthConfig {
  username: string;
  password: string;
}

export interface RulesetConfig {
  enabled: boolean;
  rules: RuleRef[];
  custom_rules?: CustomRule[];
  severity_filter: SeverityFilter;
}

export interface RuleRef {
  id: string;
  version?: string;
  active: boolean;
}

export interface CustomRule {
  name: string;
  pattern: string;
  flags: string;
  description: string;
}

export interface SeverityFilter {
  min: 'low' | 'medium' | 'high' | 'critical';
  max?: never;
}

export interface OutputConfig {
  format: 'sarif' | 'json' | 'html' | 'text';
  path: string;
  compress: boolean;
}

// =============================================================================
// ZOD SCHEMA VALIDATION
// =============================================================================

const AuthSchema = z.object({
  type: z.enum(['header', 'cookie', 'oauth2', 'basic']),
  header: z.record(z.string()).optional(),
  cookie: z.array(z.string()).optional(),
  oauth2: z.object({
    client_id: z.string().min(1),
    client_secret: z.string().min(1),
    token_url: z.string().url(),
    scopes: z.array(z.string()),
    refresh_token: z.string().optional(),
  }).optional(),
  basic: z.object({
    username: z.string().min(1),
    password: z.string().min(1),
  }).optional(),
}).passthrough();

const RulesetSchema = z.object({
  enabled: z.boolean(),
  rules: z.array(z.object({
    id: z.string(),
    version: z.string().optional(),
    active: z.boolean(),
  })),
  custom_rules: z.array(
    z.object({
      name: z.string(),
      pattern: z.string(),
      flags: z.string(),
      description: z.string(),
    })
  ).optional(),
  severity_filter: z.object({
    min: z.enum(['low', 'medium', 'high', 'critical']),
    max: z.undefined().default(undefined),
  }),
}).passthrough();

const OutputSchema = z.object({
  format: z.enum(['sarif', 'json', 'html', 'text']),
  path: z.string(),
  compress: z.boolean().default(false),
});

// =============================================================================
// PARSER IMPLEMENTATION
// =============================================================================

export class ConfigParserError extends Error {
  constructor(
    message: string,
    public readonly file?: string,
    public readonly line?: number,
    public readonly column?: number
  ) {
    super(message);
    this.name = 'ConfigParserError';
  }
}

export function parseConfigFile(filePath: string): DASTConfig {
  const absolutePath = path.resolve(filePath);
  
  if (!fs.existsSync(absolutePath)) {
    throw new ConfigParserError(`Configuration file not found: ${filePath}`, filePath);
  }

  let content: string;
  try {
    content = fs.readFileSync(absolutePath, 'utf-8');
  } catch (err) {
    if (err instanceof Error && err.code === 'EACCES') {
      throw new ConfigParserError(`Permission denied reading: ${filePath}`, filePath);
    }
    throw new ConfigParserError(`Failed to read configuration file: ${(err as Error).message}`, filePath);
  }

  return parseConfigString(content, absolutePath);
}

export function parseConfigString(source: string, filename?: string): DASTConfig {
  let parsed: any;
  
  try {
    // Auto-detect format based on content or file extension
    if (filename && /\.yaml$|\.yml$/.test(filename)) {
      parsed = yamlParse(source);
    } else if (filename && /\.json$/.test(filename)) {
      parsed = jsonParse(source);
    } else {
      // Try JSON first, then YAML
      try {
        parsed = jsonParse(source);
      } catch {
        parsed = yamlParse(source);
      }
    }
  } catch (err) {
    throw new ConfigParserError(
      `Failed to parse configuration: ${(err as Error).message}`,
      filename,
      getLineColumn(source, err as Error)
    );
  }

  // Validate against schema
  const result = RulesetSchema.merge(AuthSchema).merge(OutputSchema).parse(parsed);
  
  return result;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function yamlParse(source: string): any {
  try {
    // Simple YAML parser for common DAST config patterns
    const lines = source.split('\n');
    let currentKey: string | null = null;
    let currentValue: any = {};
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      if (!line || line.startsWith('#')) continue;
      
      // Handle nested objects
      if (line.includes(':') && !line.endsWith(':')) {
        const match = line.match(/^(.+):\s*(.*)$/);
        if (match) {
          currentKey = match[1].trim();
          currentValue[match[2].trim()] = true; // placeholder for nested value
        }
      } else if (line.endsWith(':')) {
        const key = line.slice(0, -1).trim();
        currentKey = key;
        currentValue[key] = {};
      } else if (line.startsWith('- ')) {
        // Array item
        const value = line.slice(2).trim().replace(/["']/g, '');
        if (!Array.isArray(currentValue[currentKey])) {
          currentValue[currentKey] = [];
        }
        currentValue[currentKey].push(value);
      } else if (line) {
        // Simple key-value
        const match = line.match(/^(.+):\s*(.*)$/);
        if (match) {
          const key = match[1].trim();
          const value = match[2].trim().replace(/["']/g, '');
          
          if (!currentValue[key]) {
            currentValue[key] = [];
          }
          currentValue[key].push(value);
        }
      }
    }
    
    // Convert to proper structure
    return convertYamlToStructure(currentValue);
  } catch (err) {
    throw new ConfigParserError(`YAML parsing failed: ${(err as Error).message}`);
  }
}

function jsonParse(source: string): any {
  try {
    return JSON.parse(source);
  } catch (err) {
    throw new ConfigParserError(`JSON parsing failed: ${(err as Error).message}`);
  }
}

function convertYamlToStructure(obj: any): any {
  // Convert arrays of single values to proper types
  for (const key in obj) {
    if (!obj.hasOwnProperty(key)) continue;
    
    const value = obj[key];
    if (Array.isArray(value) && value.length === 1) {
      obj[key] = value[0];
    } else if (typeof value === 'object' && !Array.isArray(value)) {
      convertYamlToStructure(value);
    }
  }
  
  return obj;
}

function getLineColumn(source: string, err: Error): { line?: number, column?: number } {
  const message = err.message || '';
  const match = message.match(/line\s+(\d+)/i) || message.match(/column\s+(\d+)/i);
  
  if (match && match[1]) {
    return { line: parseInt(match[1], 10), column: 1 };
  }
  
  return {};
}

// =============================================================================
// DEMO / ENTRY POINT
// =============================================================================

const SAMPLE_CONFIG = `
# Dastlite Configuration Example
targets:
  - https://api.example.com/v1/users
  - https://mobile-api.example.com/graphql
auth:
  type: oauth2
  oauth2:
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    token_url: "https://oauth.example.com/token"
    scopes: ["read", "write"]
ruleset:
  enabled: true
  rules:
    - id: "XSS-001"
      version: "2.1.0"
      active: true
    - id: "SQLI-003"
      version: "1.5.0"
      active: false
  severity_filter:
    min: "medium"
output:
  format: sarif
  path: "./results/scan-results.sarif"
  compress: true
`;

function runDemo() {
  console.log('='.repeat(60));
  console.log('Dastlite Config Parser Demo');
  console.log('='.repeat(60));
  
  // Parse sample YAML config string
  const config = parseConfigString(SAMPLE_CONFIG, 'sample.yaml');
  
  console.log('\n✓ Parsed configuration:');
  console.log(`  Targets: ${config.targets.length} endpoints`);
  console.log(`  Auth type: ${config.auth.type}`);
  console.log(`  Rules enabled: ${config.ruleset.enabled ? 'Yes' : 'No'}`);
  console.log(`  Output format: ${config.output.format}`);
  
  // Validate specific fields
  const hasOauth = config.auth.oauth2 !== undefined;
  const activeRules = config.ruleset.rules.filter(r => r.active).length;
  
  console.log('\n✓ Validation results:');
  console.log(`  OAuth configured: ${hasOauth ? 'Yes' : 'No'}`);
  console.log(`  Active rules: ${activeRules} / ${config.ruleset.rules.length}`);
  console.log(`  Min severity: ${config.ruleset.severity_filter.min.toUpperCase()}`);
  
  // Simulate file-based parsing
  const tempFile = path.join(process.cwd(), 'temp-config.yaml');
  fs.writeFileSync(tempFile, SAMPLE_CONFIG);
  
  try {
    const fileConfig = parseConfigFile(tempFile);
    console.log('\n✓ File-based parsing successful');
    console.log(`  Config loaded from: ${fileConfig.output.path}`);
  } finally {
    // Cleanup
    fs.unlinkSync(tempFile);
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('Demo complete! Check console output for results.');
}

// Run demo if executed directly
if (require.main === module) {
  runDemo();
}

export { DASTConfig, AuthConfig, RulesetConfig, OutputConfig };