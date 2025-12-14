// Lightweight threat database loader
// Attempts to load phishtank URL list and extended JSON, if packaged.

let urlSet: Set<string> | null = null
let domainSet: Set<string> | null = null
let ready = false

export async function loadThreatDB(): Promise<void> {
  if (ready) return
  urlSet = new Set<string>()
  domainSet = new Set<string>()

  const sources = [
    "assets/datasets/phishtank_urls.json",
    "assets/datasets/phishing-urls.json"
  ]

  for (const rel of sources) {
    try {
      const res = await fetch(chrome.runtime.getURL(rel))
      if (!res.ok) continue
      const text = await res.text()
      // Try parse as array first
      try {
        const arr = JSON.parse(text)
        if (Array.isArray(arr)) {
          for (const u of arr) {
            if (typeof u === "string") {
              urlSet.add(u)
              try {
                domainSet.add(new URL(u).hostname)
              } catch {}
            }
          }
          continue
        }
      } catch {}
      // Try parse as object with threats array
      try {
        const obj = JSON.parse(text)
        const threats = Array.isArray(obj?.threats) ? obj.threats : []
        for (const t of threats) {
          if (t?.url) urlSet.add(String(t.url))
          if (t?.domain) domainSet.add(String(t.domain))
        }
      } catch {}
    } catch (e) {
      // ignore
    }
  }
  ready = true
}

export function isKnownPhishing(url: string): {
  match: "url" | "domain" | null
  value?: string
} {
  if (!ready || !urlSet || !domainSet) return { match: null }
  if (urlSet.has(url)) return { match: "url", value: url }
  try {
    const h = new URL(url).hostname
    if (domainSet.has(h)) return { match: "domain", value: h }
  } catch {}
  return { match: null }
}
