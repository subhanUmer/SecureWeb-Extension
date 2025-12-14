import type { SuspiciousPattern } from "./types";

/**
 * Built-in suspicious JavaScript patterns
 * These patterns detect common malicious JavaScript behaviors
 */
export const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  // === CRYPTOMINING PATTERNS ===
  {
    id: "crypto-coinhive",
    name: "CoinHive Crypto Miner",
    pattern: /coinhive|cnhv|CoinHive/i,
    description: "Detects CoinHive cryptocurrency mining script",
    severity: "critical",
    category: "cryptomining",
  },
  {
    id: "crypto-generic",
    name: "Generic Crypto Miner",
    pattern: /cryptonight|webminer|crypto-loot|cryptoloot/i,
    description: "Detects generic cryptocurrency mining patterns",
    severity: "high",
    category: "cryptomining",
  },
  {
    id: "crypto-monero",
    name: "Monero Miner",
    pattern: /monero.*miner|xmr.*mine/i,
    description: "Detects Monero mining scripts",
    severity: "high",
    category: "cryptomining",
  },

  // === CODE INJECTION PATTERNS ===
  {
    id: "injection-eval",
    name: "Dangerous eval() Usage",
    pattern: /eval\s*\(/,
    description: "Detects eval() function which can execute arbitrary code",
    severity: "high",
    category: "injection",
  },
  {
    id: "injection-function-constructor",
    name: "Function Constructor",
    pattern: /new\s+Function\s*\(/,
    description: "Detects Function constructor which can execute arbitrary code",
    severity: "high",
    category: "injection",
  },
  {
    id: "injection-document-write",
    name: "document.write Injection",
    pattern: /document\.write\s*\(/,
    description: "Detects document.write which can inject malicious content",
    severity: "medium",
    category: "injection",
  },
  {
    id: "injection-innerhtml",
    name: "innerHTML Manipulation",
    pattern: /\.innerHTML\s*=(?!['"\s]*$)/,
    description: "Detects innerHTML assignments that could inject scripts",
    severity: "medium",
    category: "injection",
  },

  // === OBFUSCATION PATTERNS ===
  {
    id: "obfuscation-base64",
    name: "Base64 Encoded Script",
    pattern: /atob\s*\(|fromCharCode\s*\(/,
    description: "Detects base64 decoding or character code obfuscation",
    severity: "medium",
    category: "obfuscation",
  },
  {
    id: "obfuscation-unicode",
    name: "Unicode Escape Obfuscation",
    pattern: /\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}/,
    description: "Detects heavy use of unicode escapes (obfuscation technique)",
    severity: "low",
    category: "obfuscation",
  },
  {
    id: "obfuscation-hex",
    name: "Hex Escape Obfuscation",
    pattern: /\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}/,
    description: "Detects heavy use of hex escapes (obfuscation technique)",
    severity: "low",
    category: "obfuscation",
  },

  // === MALWARE PATTERNS ===
  {
    id: "malware-keylogger",
    name: "Keylogger Pattern",
    pattern: /addEventListener\s*\(\s*['"]keypress['"]|onkeypress|onkeydown/i,
    description: "Detects potential keylogging behavior",
    severity: "high",
    category: "malware",
  },
  {
    id: "malware-clipboard",
    name: "Clipboard Access",
    pattern: /navigator\.clipboard|document\.execCommand\s*\(\s*['"]copy['"]/i,
    description: "Detects clipboard access which could steal copied data",
    severity: "medium",
    category: "malware",
  },
  {
    id: "malware-webcam",
    name: "Webcam/Microphone Access",
    pattern: /getUserMedia|mediaDevices\.getUserMedia/i,
    description: "Detects attempts to access webcam or microphone",
    severity: "high",
    category: "malware",
  },
  {
    id: "malware-geolocation",
    name: "Geolocation Tracking",
    pattern: /navigator\.geolocation|getCurrentPosition/i,
    description: "Detects geolocation tracking attempts",
    severity: "medium",
    category: "malware",
  },

  // === TRACKING & FINGERPRINTING ===
  {
    id: "tracking-canvas-fingerprint",
    name: "Canvas Fingerprinting",
    pattern: /canvas.*toDataURL|canvas.*getImageData/i,
    description: "Detects canvas fingerprinting for user tracking",
    severity: "medium",
    category: "tracking",
  },
  {
    id: "tracking-webgl-fingerprint",
    name: "WebGL Fingerprinting",
    pattern: /getParameter.*UNMASKED|webgl.*fingerprint/i,
    description: "Detects WebGL fingerprinting techniques",
    severity: "medium",
    category: "tracking",
  },

  // === SUSPICIOUS NETWORK PATTERNS ===
  {
    id: "network-websocket-suspicious",
    name: "Suspicious WebSocket",
    pattern: /new\s+WebSocket\s*\(\s*['"]wss?:\/\/(?!localhost)/i,
    description: "Detects WebSocket connections to external servers",
    severity: "low",
    category: "malware",
  },
  {
    id: "network-external-script",
    name: "Dynamic External Script Loading",
    pattern: /createElement\s*\(\s*['"]script['"]\)|\.src\s*=.*http/i,
    description: "Detects dynamic loading of external scripts",
    severity: "low",
    category: "malware",
  },
];

/**
 * Get patterns by severity level
 */
export function getPatternsBySeverity(
  severity: "low" | "medium" | "high" | "critical"
): SuspiciousPattern[] {
  return SUSPICIOUS_PATTERNS.filter((p) => p.severity === severity);
}

/**
 * Get patterns by category
 */
export function getPatternsByCategory(
  category: "cryptomining" | "injection" | "obfuscation" | "malware" | "tracking"
): SuspiciousPattern[] {
  return SUSPICIOUS_PATTERNS.filter((p) => p.category === category);
}
