import type { PlasmoCSConfig } from "plasmo"

/**
 * Script Injection Blocker (MAIN World)
 * This runs in the page's JavaScript context to intercept eval/Function
 * BEFORE any page scripts execute.
 *
 * CRITICAL: This must run in MAIN world to accept page-level
 * eval/Function calls. ISOLATED world won't work!
 */
export const config: PlasmoCSConfig = {
  matches: ["<all_urls>"],
  all_frames: true,
  run_at: "document_start",
  world: "MAIN" // Run in page context!
}

// Store original functions
const _eval = window.eval
const _Function = window.Function

// Pattern matching with severity levels (must be in page context for speed)
// CRITICAL: Always block, HIGH: Block in strict/moderate, MEDIUM: Block in strict only
const dangerousPatterns = [
  // CRITICAL - Network exfiltration combined with data access
  {
    pattern: /fetch\s*\(.*(cookie|localStorage|sessionStorage)/gi,
    name: "data exfiltration via fetch",
    severity: "CRITICAL"
  },
  {
    pattern: /XMLHttpRequest.*cookie/gi,
    name: "cookie exfiltration via XHR",
    severity: "CRITICAL"
  },

  // CRITICAL - Known crypto miners (always block)
  {
    pattern: /coinhive|CoinHive/gi,
    name: "CoinHive miner",
    severity: "CRITICAL"
  },
  {
    pattern: /crypto-loot|cryptoloot/gi,
    name: "CryptoLoot miner",
    severity: "CRITICAL"
  },
  { pattern: /jsecoin/gi, name: "JSEcoin miner", severity: "CRITICAL" },
  {
    pattern: /minergate|deepMiner|minr\.pw/gi,
    name: "crypto miner variant",
    severity: "CRITICAL"
  },

  // CRITICAL - Obfuscated malicious patterns
  {
    pattern: /atob\s*\(.*fetch/gi,
    name: "obfuscated fetch",
    severity: "CRITICAL"
  },
  {
    pattern: /fromCharCode.*cookie/gi,
    name: "obfuscated cookie access",
    severity: "CRITICAL"
  },
  {
    pattern: /String\.fromCharCode\.apply/gi,
    name: "bulk char code conversion",
    severity: "CRITICAL"
  },

  // HIGH - Suspicious network calls
  { pattern: /fetch\s*\(/gi, name: "fetch API call", severity: "HIGH" },
  { pattern: /XMLHttpRequest/gi, name: "XMLHttpRequest", severity: "HIGH" },
  { pattern: /\.send\s*\(/gi, name: "AJAX send", severity: "HIGH" },
  {
    pattern: /navigator\.sendBeacon/gi,
    name: "sendBeacon exfiltration",
    severity: "HIGH"
  },
  { pattern: /WebSocket/gi, name: "WebSocket connection", severity: "HIGH" },

  // HIGH - Data access (suspicious in eval context)
  { pattern: /document\.cookie/gi, name: "cookie access", severity: "HIGH" },
  { pattern: /localStorage/gi, name: "localStorage access", severity: "HIGH" },
  {
    pattern: /sessionStorage/gi,
    name: "sessionStorage access",
    severity: "HIGH"
  },
  { pattern: /indexedDB/gi, name: "indexedDB access", severity: "HIGH" },

  // HIGH - Dangerous DOM manipulation
  { pattern: /document\.write/gi, name: "document.write", severity: "HIGH" },
  {
    pattern: /innerHTML\s*=.*<script/gi,
    name: "innerHTML script injection",
    severity: "HIGH"
  },
  {
    pattern: /outerHTML\s*=.*<script/gi,
    name: "outerHTML script injection",
    severity: "HIGH"
  },

  // HIGH - Redirects and popups
  {
    pattern: /location\.href\s*=\s*['"]http/gi,
    name: "external redirect",
    severity: "HIGH"
  },
  { pattern: /window\.open\s*\(/gi, name: "popup window", severity: "HIGH" },

  // HIGH - Keylogging and tracking
  {
    pattern: /addEventListener\s*\(\s*['"]key(press|down|up)/gi,
    name: "keyboard event listener",
    severity: "HIGH"
  },
  {
    pattern: /addEventListener\s*\(\s*['"]paste/gi,
    name: "paste event listener",
    severity: "HIGH"
  },
  {
    pattern: /addEventListener\s*\(\s*['"]copy/gi,
    name: "copy event listener",
    severity: "HIGH"
  },

  // HIGH - Script injection
  {
    pattern: /createElement\s*\(\s*['"]script['"]\s*\)/gi,
    name: "script element creation",
    severity: "HIGH"
  },
  {
    pattern: /\.appendChild.*script/gi,
    name: "script injection via appendChild",
    severity: "HIGH"
  },
  {
    pattern: /\.insertBefore.*script/gi,
    name: "script injection via insertBefore",
    severity: "HIGH"
  },
  { pattern: /import\s*\(/gi, name: "dynamic import", severity: "HIGH" },

  // HIGH - Iframe attacks
  {
    pattern: /createElement\s*\(\s*['"]iframe['"]/gi,
    name: "iframe creation",
    severity: "HIGH"
  },
  {
    pattern: /contentWindow|contentDocument/gi,
    name: "iframe content access",
    severity: "HIGH"
  },

  // HIGH - Form hijacking
  {
    pattern: /form\.submit\s*\(/gi,
    name: "form auto-submission",
    severity: "HIGH"
  },
  {
    pattern: /\.action\s*=\s*['"]http/gi,
    name: "form action hijacking",
    severity: "HIGH"
  },

  // MEDIUM - Obfuscation (common in legitimate code too)
  { pattern: /atob\s*\(/gi, name: "base64 decode", severity: "MEDIUM" },
  {
    pattern: /fromCharCode/gi,
    name: "character code obfuscation",
    severity: "MEDIUM"
  },
  { pattern: /unescape\s*\(/gi, name: "unescape", severity: "MEDIUM" },
  { pattern: /escape\s*\(/gi, name: "escape obfuscation", severity: "MEDIUM" },

  // MEDIUM - General DOM manipulation (very common)
  {
    pattern: /innerHTML\s*=/gi,
    name: "innerHTML assignment",
    severity: "MEDIUM"
  },
  {
    pattern: /outerHTML\s*=/gi,
    name: "outerHTML assignment",
    severity: "MEDIUM"
  },
  {
    pattern: /\.insertAdjacentHTML/gi,
    name: "insertAdjacentHTML",
    severity: "MEDIUM"
  },
  {
    pattern: /\.createContextualFragment/gi,
    name: "createContextualFragment",
    severity: "MEDIUM"
  },

  // MEDIUM - Browser fingerprinting (privacy concern, not always malicious)
  {
    pattern: /canvas\.toDataURL/gi,
    name: "canvas fingerprinting",
    severity: "MEDIUM"
  },
  {
    pattern: /AudioContext|webkitAudioContext/gi,
    name: "audio fingerprinting",
    severity: "MEDIUM"
  },
  {
    pattern: /navigator\.plugins/gi,
    name: "plugin enumeration",
    severity: "MEDIUM"
  },
  {
    pattern: /screen\.(width|height|availWidth)/gi,
    name: "screen resolution tracking",
    severity: "MEDIUM"
  },

  // MEDIUM - Common tracking
  {
    pattern: /addEventListener\s*\(\s*['"]mouse/gi,
    name: "mouse tracking listener",
    severity: "MEDIUM"
  },
  {
    pattern: /addEventListener\s*\(\s*['"]click/gi,
    name: "click tracking listener",
    severity: "MEDIUM"
  },

  // MEDIUM - Nested eval (might be legitimate in some cases)
  { pattern: /eval\s*\(/gi, name: "nested eval", severity: "MEDIUM" },
  {
    pattern: /Function\s*\(/gi,
    name: "Function constructor",
    severity: "MEDIUM"
  },
  {
    pattern: /setTimeout.*eval/gi,
    name: "setTimeout with eval",
    severity: "MEDIUM"
  },
  {
    pattern: /setInterval.*eval/gi,
    name: "setInterval with eval",
    severity: "MEDIUM"
  },
  {
    pattern: /\[['"]constructor['"]\]/gi,
    name: "constructor property access",
    severity: "MEDIUM"
  },

  // MEDIUM - Cross-origin communication (common in legitimate apps)
  {
    pattern: /postMessage/gi,
    name: "cross-origin messaging",
    severity: "MEDIUM"
  },

  // MEDIUM - External script loading (common but potentially dangerous)
  {
    pattern: /\.src\s*=.*\.js/gi,
    name: "external script loading",
    severity: "MEDIUM"
  }
]

function analyzeCode(code: string): {
  malicious: boolean
  pattern?: string
  severity?: string
} {
  const codeStr = String(code)

  // Allow very simple safe operations
  if (
    codeStr.length < 30 &&
    !/(fetch|cookie|eval|Function|atob)/.test(codeStr)
  ) {
    return { malicious: false }
  }

  // Check CRITICAL patterns first (always block)
  for (const { pattern, name, severity } of dangerousPatterns) {
    if (severity === "CRITICAL" && pattern.test(codeStr)) {
      return { malicious: true, pattern: name, severity: "CRITICAL" }
    }
  }

  // Check HIGH patterns (block in moderate/strict modes)
  for (const { pattern, name, severity } of dangerousPatterns) {
    if (severity === "HIGH" && pattern.test(codeStr)) {
      return { malicious: true, pattern: name, severity: "HIGH" }
    }
  }

  // Check MEDIUM patterns (only block in strict mode - for now, skip these)
  // This reduces false positives while still catching serious threats

  return { malicious: false }
}

// Override eval
window.eval = function (code: string): any {
  const analysis = analyzeCode(code)

  if (analysis.malicious) {
    console.error(
      `[JSBlocker] 🚫 BLOCKED eval() call - ${analysis.severity} threat`,
      `\nPattern: ${analysis.pattern}`,
      "\nCode:",
      code.substring(0, 200)
    )

    // Notify extension about the blocked eval
    window.postMessage(
      {
        type: "SECUREWEB_EVAL_BLOCKED",
        data: {
          method: "eval",
          pattern: analysis.pattern,
          severity: analysis.severity,
          code: code.substring(0, 200),
          timestamp: Date.now()
        }
      },
      "*"
    )

    throw new Error(
      `SecureWeb: eval() blocked - ${analysis.severity} threat detected (${analysis.pattern})`
    )
  }

  // Allow safe eval calls
  console.log(
    "[JSBlocker] ✅ Allowing safe eval() call:",
    code.substring(0, 100)
  )
  return _eval.call(this, code)
}

// Override Function constructor
window.Function = function (...args: string[]): Function {
  const code = args[args.length - 1] || ""
  const analysis = analyzeCode(code)

  if (analysis.malicious) {
    console.error(
      `[JSBlocker] 🚫 BLOCKED Function() call - ${analysis.severity} threat`,
      `\nPattern: ${analysis.pattern}`,
      "\nCode:",
      code.substring(0, 200)
    )

    // Notify extension about the blocked Function
    window.postMessage(
      {
        type: "SECUREWEB_EVAL_BLOCKED",
        data: {
          method: "Function",
          pattern: analysis.pattern,
          severity: analysis.severity,
          code: code.substring(0, 200),
          timestamp: Date.now()
        }
      },
      "*"
    )

    throw new Error(
      `SecureWeb: Function constructor blocked - ${analysis.severity} threat detected (${analysis.pattern})`
    )
  }

  // Allow safe Function calls
  console.log("[JSBlocker] ✅ Allowing safe Function() call")
  return _Function.apply(this, args)
} as FunctionConstructor

// Protect innerHTML/outerHTML from XSS
const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(
  Element.prototype,
  "innerHTML"
)
const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(
  Element.prototype,
  "outerHTML"
)

if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
  Object.defineProperty(Element.prototype, "innerHTML", {
    set: function (value: string) {
      const htmlStr = String(value)

      // Check for XSS patterns in HTML
      const xssPatterns = [
        /<script/gi,
        /onerror\s*=/gi,
        /onload\s*=/gi,
        /onclick\s*=/gi,
        /javascript:/gi,
        /<iframe/gi
      ]

      for (const pattern of xssPatterns) {
        if (pattern.test(htmlStr)) {
          console.error(
            "[JSBlocker] 🚫 BLOCKED innerHTML assignment - XSS pattern detected:",
            pattern.source,
            "\nHTML:",
            htmlStr.substring(0, 200)
          )

          // Notify extension about the blocked innerHTML
          window.postMessage(
            {
              type: "SECUREWEB_EVAL_BLOCKED",
              data: {
                method: "innerHTML",
                pattern: `XSS pattern: ${pattern.source}`,
                severity: "HIGH",
                code: htmlStr.substring(0, 200),
                timestamp: Date.now()
              }
            },
            "*"
          )

          throw new Error(
            "SecureWeb: innerHTML blocked - potentially malicious HTML detected"
          )
        }
      }

      // Safe - allow it
      originalInnerHTMLDescriptor.set!.call(this, value)
    },
    get: originalInnerHTMLDescriptor.get
  })
}

if (originalOuterHTMLDescriptor && originalOuterHTMLDescriptor.set) {
  Object.defineProperty(Element.prototype, "outerHTML", {
    set: function (value: string) {
      const htmlStr = String(value)

      // Check for XSS patterns in HTML
      const xssPatterns = [
        /<script/gi,
        /onerror\s*=/gi,
        /onload\s*=/gi,
        /onclick\s*=/gi,
        /javascript:/gi,
        /<iframe/gi
      ]

      for (const pattern of xssPatterns) {
        if (pattern.test(htmlStr)) {
          console.error(
            "[JSBlocker] 🚫 BLOCKED outerHTML assignment - XSS pattern detected:",
            pattern.source,
            "\nHTML:",
            htmlStr.substring(0, 200)
          )

          // Notify extension about the blocked outerHTML
          window.postMessage(
            {
              type: "SECUREWEB_EVAL_BLOCKED",
              data: {
                method: "outerHTML",
                pattern: `XSS pattern: ${pattern.source}`,
                severity: "HIGH",
                code: htmlStr.substring(0, 200),
                timestamp: Date.now()
              }
            },
            "*"
          )

          throw new Error(
            "SecureWeb: outerHTML blocked - potentially malicious HTML detected"
          )
        }
      }

      // Safe - allow it
      originalOuterHTMLDescriptor.set!.call(this, value)
    },
    get: originalOuterHTMLDescriptor.get
  })
}

console.log("[JSBlocker] 🛡️ eval/Function/innerHTML protection active")
