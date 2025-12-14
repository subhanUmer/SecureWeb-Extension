# SecureWeb - ML-Powered Browser Security Extension

multi-layered browser protection against phishing, malicious javascript, and compromised extensions.

built in response to recent attacks where trusted browser extensions went rogue and executed malicious javascript, compromising millions of users.

## important notice

**this extension is currently in development and NOT ready for production use.**

- known bugs and issues exist
- active development and testing in progress
- contributions, bug reports, and PRs are welcome
- planning to publish on chrome web store after stability improvements

**do NOT use this for any public-facing product or in production environments.**

---

## features

### 1. ml-powered phishing detection
- tensorflow.js neural network (4-layer deep nn)
- 20-feature extraction from urls
- 95%+ accuracy on validation datasets
- real-time inference (<10ms per url)
- trained on phishtank and custom datasets

### 2. behavioral monitoring
- statistical anomaly detection with z-scores
- learns "normal" behavior for each website (first 5 visits)
- detects suspicious changes: new scripts, network requests, api usage
- catches compromised legitimate websites

### 3. real-time javascript blocking
- blocks dangerous patterns: `eval()`, `Function()`, innerHTML exploits
- catches crypto miners (coinhive, cryptoloot, etc.)
- prevents keyloggers and data exfiltration
- pattern-based detection with severity scoring

### 4. extension scanner
- monitors OTHER installed extensions
- detects permission changes and version updates
- flags suspicious host permission additions
- risk scoring for extension behavior

### 5. privacy-first design
- 100% local processing (zero external communication)
- no data collection or cloud services
- no telemetry or tracking
- all analysis happens in your browser

---

## architecture

**multi-layer protection:**
1. **layer 1 (pre-load):** ml classifies urls, blocks phishing before page loads
2. **layer 2 (load-time):** heuristic analysis catches structural anomalies
3. **layer 3 (runtime):** javascript blocking prevents malicious code execution
4. **layer 4 (post-load):** statistical monitoring detects behavioral changes

---

## getting started

this is a [plasmo extension](https://docs.plasmo.com/) project bootstrapped with [`plasmo init`](https://www.npmjs.com/package/plasmo).

### prerequisites
- node.js 16+
- npm or pnpm

### installation

```bash
# clone the repository
git clone https://github.com/subhanUmer/SecureWeb-Extension.git
cd SecureWeb-Extension

# install dependencies
npm install
# or
pnpm install
```

### development

first, run the development server:

```bash
npm run dev
# or
pnpm dev
```

open your browser and load the appropriate development build. for chrome with manifest v3, use: `build/chrome-mv3-dev`.

you can start editing the popup by modifying `src/popup/index.tsx`. it should auto-update as you make changes.

for further guidance, [visit plasmo documentation](https://docs.plasmo.com/)

### production build

run the following:

```bash
npm run build
# or
pnpm build
```

this creates a production bundle in `build/chrome-mv3-prod/`, ready to be loaded as an unpacked extension or zipped for distribution.

---

## ml model training

### prepare dataset
```bash
npm run prepare-dataset
```

### train model
```bash
npm run train-model
```

trained model will be saved to `assets/ml-models/threat-classifier/`

---

## contributing

contributions are **highly welcome**. this project has known issues and bugs that need fixing.

### how to contribute:
1. fork the repository
2. create a feature branch (`git checkout -b feature/your-feature`)
3. commit your changes (`git commit -m 'add some feature'`)
4. push to the branch (`git push origin feature/your-feature`)
5. open a pull request

### areas needing help:
- bug fixes and stability improvements
- performance optimizations
- ui/ux enhancements
- additional ml features and datasets
- test coverage
- documentation improvements

---

## contributors

special thanks to:
- **ahmed bhatti** - contributor
- **shameer hassan** - contributor

---

## license

this project is open source. check the repository for license details.

---

## disclaimer

this extension is provided "as-is" without warranty of any kind. use at your own risk. not intended for production environments or public-facing products at this stage.

---

## contact

for questions, suggestions, or collaboration:
- github issues: [report bugs or request features](https://github.com/subhanUmer/SecureWeb-Extension/issues)
- contributions: pull requests welcome

---

**stay safe out there.**
