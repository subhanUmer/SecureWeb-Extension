# SecureWeb - ML-Powered Browser Security Extension

🛡️ **Multi-layered browser protection against phishing, malicious JavaScript, and compromised extensions**

Built in response to recent attacks where trusted browser extensions went rogue and executed malicious JavaScript, compromising millions of users.

## ⚠️ Important Notice

**This extension is currently in development and NOT ready for production use.**

- Known bugs and issues exist
- Active development and testing in progress
- Contributions, bug reports, and PRs are welcome!
- Planning to publish on Chrome Web Store after stability improvements

**DO NOT use this for any public-facing product or in production environments.**

---

## 🎯 Features

### 1. **ML-Powered Phishing Detection**
- TensorFlow.js neural network (4-layer deep NN)
- 20-feature extraction from URLs
- 95%+ accuracy on validation datasets
- Real-time inference (<10ms per URL)
- Trained on PhishTank and custom datasets

### 2. **Behavioral Monitoring**
- Statistical anomaly detection with z-scores
- Learns "normal" behavior for each website (first 5 visits)
- Detects suspicious changes: new scripts, network requests, API usage
- Catches compromised legitimate websites

### 3. **Real-Time JavaScript Blocking**
- Blocks dangerous patterns: `eval()`, `Function()`, innerHTML exploits
- Catches crypto miners (CoinHive, CryptoLoot, etc.)
- Prevents keyloggers and data exfiltration
- Pattern-based detection with severity scoring

### 4. **Extension Scanner**
- Monitors OTHER installed extensions
- Detects permission changes and version updates
- Flags suspicious host permission additions
- Risk scoring for extension behavior

### 5. **Privacy-First Design**
- 100% local processing (zero external communication)
- No data collection or cloud services
- No telemetry or tracking
- All analysis happens in your browser

---

## 🏗️ Architecture

**Multi-Layer Protection:**
1. **Layer 1 (Pre-load):** ML classifies URLs → blocks phishing before page loads
2. **Layer 2 (Load-time):** Heuristic analysis → catches structural anomalies
3. **Layer 3 (Runtime):** JavaScript blocking → prevents malicious code execution
4. **Layer 4 (Post-load):** Statistical monitoring → detects behavioral changes

---

## 🚀 Getting Started

This is a [Plasmo extension](https://docs.plasmo.com/) project bootstrapped with [`plasmo init`](https://www.npmjs.com/package/plasmo).

### Prerequisites
- Node.js 16+
- npm or pnpm

### Installation

```bash
# Clone the repository
git clone https://github.com/subhanUmer/SecureWeb-Extension.git
cd SecureWeb-Extension

# Install dependencies
npm install
# or
pnpm install
```

### Development

First, run the development server:

```bash
npm run dev
# or
pnpm dev
```

Open your browser and load the appropriate development build. For example, if you are developing for the chrome browser, using manifest v3, use: `build/chrome-mv3-dev`.

You can start editing the popup by modifying `src/popup/index.tsx`. It should auto-update as you make changes.

For further guidance, [visit Plasmo Documentation](https://docs.plasmo.com/)

### Production Build

Run the following:

```bash
npm run build
# or
pnpm build
```

This creates a production bundle in `build/chrome-mv3-prod/`, ready to be loaded as an unpacked extension or zipped for distribution.

---

## 🧠 ML Model Training

### Prepare Dataset
```bash
npm run prepare-dataset
```

### Train Model
```bash
npm run train-model
```

Trained model will be saved to `assets/ml-models/threat-classifier/`

---

## 🤝 Contributing

Contributions are **highly welcome**! This project has known issues and bugs that need fixing.

### How to Contribute:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

### Areas Needing Help:
- Bug fixes and stability improvements
- Performance optimizations
- UI/UX enhancements
- Additional ML features and datasets
- Test coverage
- Documentation improvements

---

## 👥 Contributors

Special thanks to:
- **Ahmed Bhatti** - Contributor
- **Shameer Hassan** - Contributor

---

## 📄 License

This project is open source. Check the repository for license details.

---

## ⚖️ Disclaimer

This extension is provided "as-is" without warranty of any kind. Use at your own risk. Not intended for production environments or public-facing products at this stage.

---

## 📧 Contact

For questions, suggestions, or collaboration:
- GitHub Issues: [Report bugs or request features](https://github.com/subhanUmer/SecureWeb-Extension/issues)
- Contributions: Pull requests welcome!

---

**Stay safe out there! 🔒**
