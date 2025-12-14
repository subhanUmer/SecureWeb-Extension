// Heuristic Analysis Logic

import {
  levenshteinDistance,
  LOOKALIKE_CHARS,
  PATTERNS,
  PROTECTED_BRANDS,
  SUSPICIOUS_PARAMS,
  SUSPICIOUS_PATHS,
  SUSPICIOUS_PORTS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS
} from "./patterns"
import type { ThreatIndicator } from "./types"

export function analyzeURLHeuristics(url: string): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname.toLowerCase()
    const path = urlObj.pathname.toLowerCase()

    indicators.push(...checkIPAddress(hostname))
    indicators.push(...checkSuspiciousTLD(hostname))
    indicators.push(...checkExcessiveSubdomains(hostname))
    indicators.push(...checkTyposquatting(hostname))
    indicators.push(...checkHomographAttack(hostname))
    indicators.push(...checkSuspiciousPath(path))
    indicators.push(...checkSuspiciousParams(urlObj.searchParams))
    indicators.push(...checkURLShortener(hostname))
    indicators.push(...checkSuspiciousPort(urlObj.port))
    indicators.push(...checkSuspiciousKeywords(hostname))
    indicators.push(...checkExcessiveDashes(hostname))
  } catch {
    indicators.push({
      type: "suspicious_path",
      severity: "high",
      description: "Malformed or invalid URL",
      value: url
    })
  }
  return indicators
}

function checkIPAddress(hostname: string): ThreatIndicator[] {
  if (PATTERNS.IP_ADDRESS.test(hostname)) {
    return [
      {
        type: "ip_address",
        severity: "high",
        description: "Uses IP address instead of domain name",
        value: hostname
      }
    ]
  }
  return []
}

function checkSuspiciousTLD(hostname: string): ThreatIndicator[] {
  const parts = hostname.split(".")
  const tld = parts[parts.length - 1]
  if (SUSPICIOUS_TLDS.includes(tld)) {
    return [
      {
        type: "suspicious_tld",
        severity: "medium",
        description: `Uses suspicious TLD: .${tld}`,
        value: tld
      }
    ]
  }
  return []
}

function checkExcessiveSubdomains(hostname: string): ThreatIndicator[] {
  const parts = hostname.split(".")
  if (parts.length > 5) {
    return [
      {
        type: "excessive_subdomains",
        severity: "medium",
        description: `Too many subdomains (${parts.length} levels)`,
        value: hostname
      }
    ]
  }
  return []
}

function checkTyposquatting(hostname: string): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  const parts = hostname.split(".")
  const domain = parts.slice(0, -1).join(".")
  for (const brand of PROTECTED_BRANDS) {
    if (domain.includes(brand)) {
      if (domain === brand || domain === `www.${brand}`) continue
      indicators.push({
        type: "typosquatting",
        severity: "critical",
        description: `Impersonates ${brand}`,
        value: domain
      })
      continue
    }
    const distance = levenshteinDistance(domain, brand)
    const similarity = 1 - distance / Math.max(domain.length, brand.length)
    if (similarity > 0.8 && distance <= 2) {
      indicators.push({
        type: "typosquatting",
        severity: "high",
        description: `Similar to ${brand} (possible typo)`,
        value: domain
      })
    }
    if (hasLookalikeChars(domain, brand)) {
      indicators.push({
        type: "typosquatting",
        severity: "critical",
        description: `Uses lookalike characters to mimic ${brand}`,
        value: domain
      })
    }
  }
  return indicators
}

function hasLookalikeChars(domain: string, brand: string): boolean {
  if (Math.abs(domain.length - brand.length) > 2) return false
  let matches = 0
  for (let i = 0; i < Math.min(domain.length, brand.length); i++) {
    const d = domain[i]
    const b = brand[i]
    if (d === b) {
      matches++
      continue
    }
    const lookalikes = LOOKALIKE_CHARS[b] || []
    if (lookalikes.includes(d)) matches++
  }
  return matches / brand.length > 0.8
}

function checkHomographAttack(hostname: string): ThreatIndicator[] {
  if (PATTERNS.MIXED_SCRIPTS.test(hostname)) {
    return [
      {
        type: "homograph_attack",
        severity: "critical",
        description: "Uses mixed character sets (homograph attack)",
        value: hostname
      }
    ]
  }
  return []
}

function checkSuspiciousPath(path: string): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  for (const pattern of SUSPICIOUS_PATHS) {
    if (pattern.test(path)) {
      indicators.push({
        type: "suspicious_path",
        severity: "medium",
        description: `Suspicious path detected: ${pattern.source}`,
        value: path
      })
      break
    }
  }
  return indicators
}

function checkSuspiciousParams(params: URLSearchParams): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  for (const param of params.keys()) {
    const paramLower = param.toLowerCase()
    if (SUSPICIOUS_PARAMS.includes(paramLower)) {
      indicators.push({
        type: "suspicious_params",
        severity: "high",
        description: `Suspicious parameter: ${param}`,
        value: param
      })
    }
  }
  return indicators
}

function checkURLShortener(hostname: string): ThreatIndicator[] {
  if (URL_SHORTENERS.includes(hostname)) {
    return [
      {
        type: "url_shortener",
        severity: "medium",
        description: "URL shortener detected (hides real destination)",
        value: hostname
      }
    ]
  }
  return []
}

function checkSuspiciousPort(port: string): ThreatIndicator[] {
  if (port && port !== "80" && port !== "443") {
    const portNum = parseInt(port, 10)
    if ([...SUSPICIOUS_PORTS].includes(portNum)) {
      return [
        {
          type: "suspicious_port",
          severity: "high",
          description: `Uses suspicious port: ${port}`,
          value: port
        }
      ]
    }
    return [
      {
        type: "suspicious_port",
        severity: "low",
        description: `Uses non-standard port: ${port}`,
        value: port
      }
    ]
  }
  return []
}

function checkSuspiciousKeywords(hostname: string): ThreatIndicator[] {
  const match = hostname.match(PATTERNS.SUSPICIOUS_KEYWORDS)
  if (match) {
    return [
      {
        type: "suspicious_path",
        severity: "medium",
        description: `Contains suspicious keyword: ${match[0]}`,
        value: match[0]
      }
    ]
  }
  return []
}

function checkExcessiveDashes(hostname: string): ThreatIndicator[] {
  if (PATTERNS.EXCESSIVE_DASHES.test(hostname)) {
    return [
      {
        type: "excessive_dashes",
        severity: "low",
        description: "Contains excessive dashes in hostname",
        value: hostname
      }
    ]
  }
  return []
}

export function calculateThreatScore(indicators: ThreatIndicator[]): number {
  if (indicators.length === 0) return 0
  const weights = { low: 0.2, medium: 0.5, high: 0.8, critical: 1.0 } as const
  let total = 0
  let max = 0
  for (const ind of indicators) {
    total += weights[ind.severity]
    max += 1
  }
  const normalized = Math.min(total / Math.max(max, 1), 1)
  return Math.pow(normalized, 0.8)
}
