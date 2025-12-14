export default {
  permissions: [
    "storage",
    "tabs",
    "scripting", // For behavior monitoring (inject collectors)
    "management", // For extension scanning
    "notifications" // For anomaly alerts
  ],
  host_permissions: ["<all_urls>"],
  web_accessible_resources: [
    {
      resources: ["assets/datasets/*.json", "assets/icon.png"],
      matches: ["<all_urls>"]
    }
  ],
  // Declare extension icons so Chrome can load them for notifications reliably
  icons: {
    16: "assets/icon.png",
    48: "assets/icon.png",
    128: "assets/icon.png"
  }
} as const
