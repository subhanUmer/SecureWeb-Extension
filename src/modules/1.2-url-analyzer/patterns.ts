// Suspicious URL Patterns

export const SUSPICIOUS_TLDS = [
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "pw",
  "buzz",
  "work",
  "click",
  "link",
  "top",
  "xyz",
  "club",
  "loan",
  "download",
  "racing"
]

export const PROTECTED_BRANDS = [
  "google",
  "facebook",
  "amazon",
  "apple",
  "microsoft",
  "netflix",
  "instagram",
  "twitter",
  "youtube",
  "linkedin",
  "paypal",
  "ebay",
  "adobe",
  "dropbox",
  "github",
  "visa",
  "mastercard",
  "americanexpress",
  "discover",
  "chase",
  "wellsfargo",
  "bankofamerica",
  "citibank",
  "hbl",
  "ubl",
  "mcb",
  "allied",
  "habib",
  "meezan",
  "alfalah",
  "askari",
  "soneri",
  "standard",
  "alibaba",
  "aliexpress",
  "daraz",
  "walmart"
]

export const LOOKALIKE_CHARS: Record<string, string[]> = {
  a: ["@", "á", "à", "â", "ä", "ã", "å", "α"],
  e: ["3", "é", "è", "ê", "ë", "ε"],
  i: ["1", "l", "í", "ì", "î", "ï", "ı"],
  o: ["0", "ó", "ò", "ô", "ö", "õ", "ø"],
  u: ["ú", "ù", "û", "ü", "µ"],
  l: ["1", "i", "í", "|"],
  s: ["$", "5", "š"],
  g: ["9", "q"],
  b: ["d", "8"],
  c: ["ç", "©"],
  n: ["ñ", "η"],
  m: ["rn"]
}

export const SUSPICIOUS_PATHS = [
  /\/login/i,
  /\/signin/i,
  /\/sign-in/i,
  /\/account/i,
  /\/verify/i,
  /\/secure/i,
  /\/update/i,
  /\/confirm/i,
  /\/validation/i,
  /\/authentication/i,
  /\/password/i,
  /\/banking/i,
  /\/wallet/i
]

export const SUSPICIOUS_PARAMS = [
  "password",
  "pass",
  "pwd",
  "credit",
  "creditcard",
  "cc",
  "cvv",
  "cvc",
  "ssn",
  "social",
  "account",
  "acct",
  "pin",
  "otp",
  "token",
  "auth",
  "session",
  "sid"
]

export const URL_SHORTENERS = [
  "bit.ly",
  "goo.gl",
  "tinyurl.com",
  "ow.ly",
  "t.co",
  "buff.ly",
  "is.gd",
  "cli.gs",
  "tiny.cc",
  "url.ie",
  "tr.im",
  "twurl.nl",
  "short.to",
  "cutt.ly",
  "rb.gy",
  "shorturl.at"
]

export const SUSPICIOUS_PORTS = [
  8080, 8888, 3000, 5000, 8000, 4444, 31337, 12345, 1337, 666, 6666, 6667
]

export const PATTERNS = {
  IP_ADDRESS: /^(\d{1,3}\.){3}\d{1,3}$/,
  EXCESSIVE_DASHES: /-{3,}/,
  EXCESSIVE_DOTS: /^([^.]+\.){6,}/,
  SUSPICIOUS_KEYWORDS:
    /(secure|account|verify|login|update|confirm|validate|banking|wallet|payment)/i,
  DATA_URL: /^data:/i,
  JAVASCRIPT_PROTOCOL: /^javascript:/i,
  MIXED_SCRIPTS:
    /[\u0430-\u044f\u0410-\u042f].*[a-zA-Z]|[a-zA-Z].*[\u0430-\u044f\u0410-\u042f]/,
  PORT_IN_URL: /:(\d+)\//
}

export function levenshteinDistance(str1: string, str2: string): number {
  const len1 = str1.length
  const len2 = str2.length
  const matrix: number[][] = []

  for (let i = 0; i <= len1; i++) matrix[i] = [i]
  for (let j = 0; j <= len2; j++) matrix[0][j] = j

  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      if (str1[i - 1] === str2[j - 1]) matrix[i][j] = matrix[i - 1][j - 1]
      else
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        )
    }
  }

  return matrix[len1][len2]
}
