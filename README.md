# PhishGuard 🛡️ (Forked Upgrades)
**ML-Powered Real-Time Phishing Detection System**

This is an upgraded fork of PhishGuard with the following improvements:

### 🌟 Key Changes in this Fork
* **Scan Cache**: Added a thread-safe, 10-minute memory cache in `app.py` to prevent redundant network requests and WHOIS queries (resolves duplicate scans in <5ms).
* **Domain Whitelist**: Added a static whitelist for secure sites and payment processors (Stripe, PayPal, Google, etc.) to skip ML processing instantly (<1ms).
* **Non-Intrusive Extension**: Modified `background.js` to scan pages silently without interrupting navigations or breaking logins and e-commerce checkouts.
* **SSRF Protection**: Added strict IP/DNS checks to block scanning of local and private network addresses (loopback, subnets).
* **Strict CORS**: Hardened Flask CORS policies to accept requests only from localhost and the browser extension.

---

## 🏗️ Project Architecture
* **Machine Learning (`/ml`):** Hybrid Voting Classifier (RF + XGB) for URL and HTML feature analysis.
* **Backend API (`app.py`):** Flask-based REST API that bridges the ML model with the client interfaces and logs scan history using SQLite.
* **Web Dashboard (`/frontend`):** A sleek vanilla HTML/CSS/JS interface served by Flask to manually scan URLs and view aggregate statistics.
* **Browser Extension (`/extension`):** A Manifest V3 Chrome extension that automatically scans web traffic and blocks access to high-risk pages.

---

## ⚙️ Prerequisites
Before running PhishGuard, ensure you have the following installed on your system:
* **Python 3.8+**
* **Google Chrome** (for the browser extension)
* **Git** (optional, for version control)

---

## 🚀 Setup & Installation Guide

Follow these steps in order to get the entire system up and running.

### Step 1: Install Dependencies
Open your terminal (or WSL) in the root directory of the project (`CP_mini_project/`) and install the required Python packages:
```bash
pip install -r requirements.txt
```

### Step 2: Setup the Machine Learning Model
The ML system requires a dataset to train the initial model. 

1. Download the `dataset.csv` file from Kaggle (as referenced in your code): [Phishing Dataset](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)
2. Place the `dataset.csv` file directly inside the `ml/` folder.
3. Run the build system to train the model and generate the `hybrid_model.pkl` file:
```bash
python ml/build_system.py
```
*(Note: If you want to retrain the model with hyperparameter tuning, run `python ml/build_system.py --tune`)*

### Step 3: Start the Backend Server
Once the `.pkl` model file is generated, you can start the Flask backend. From the root directory, run:
```bash
python app.py
```
You should see output indicating that the PhishGuard API is running on `http://localhost:5000`. Leave this terminal window open.

### Step 4: Install the Chrome Extension
To get the real-time protection working in your browser:
1. Open Google Chrome and type `chrome://extensions/` in the address bar.
2. Toggle on **Developer mode** in the top right corner.
3. Click the **Load unpacked** button in the top left.
4. Select the `extension/` folder from your project directory.
5. The PhishGuard extension should now appear in your browser. Ensure it is enabled.

---

## 💻 How to Operate PhishGuard

### Using the Web Dashboard
1. With the Flask server running, open your browser and navigate to `http://localhost:5000`.
2. You will see the PhishGuard command center.
3. **Manual Scan:** Paste any URL into the input field and click **Scan**. The dashboard will display the risk score, the model's confidence, and flag any suspicious features (like missing HTTPS or suspicious domain age).
4. **History & Stats:** Scroll down to view the total number of scans, the current phishing catch rate, and a table of your recent scan history.

### Using the Chrome Extension
1. Pin the PhishGuard extension to your Chrome toolbar for easy access.
2. **Automated Protection:** Browse the web normally. The extension runs in the background. If you navigate to a site that the ML model flags with a high risk score (>60%), the extension will instantly redirect you to a red `blocked.html` warning page.
3. **Manual Page Scan:** Click the extension icon in your toolbar while on any webpage. It will analyze the current tab and give you a detailed breakdown of its safety metrics.
4. **Bypass (Not Recommended):** If a legitimate site is falsely flagged, you can click "Proceed Anyway (Unsafe)" on the blocked page to continue to the site.
