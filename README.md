# Advanced Phishing Detection Tool

A comprehensive cybersecurity tool designed to detect phishing URLs using multiple advanced verification techniques. This tool is perfect for learning cybersecurity, security research, and understanding common phishing tactics.

## 🎯 Features

### Core Detection Methods
1. **URL Length Analysis** - Detects unusually long URLs (phishers often obscure real URLs)
2. **HTTPS Protocol Check** - Identifies insecure HTTP connections
3. **Suspicious Keywords Detection** - Finds common phishing keywords (login, verify, update, etc.)
4. **Domain Age & WHOIS Lookup** - Validates domain via DNS resolution
5. **Redirect Chain Detection** - Detects suspicious redirect patterns

### Advanced Detection Methods
1. **Brand-Domain Mismatch Check** - Prevents false positives on legitimate brand domains
   - Identifies when URLs mention a brand but use a different domain
   - Example: If URL contains "Microsoft" but domain is `microsoft-secure.tk`, it's flagged as CRITICAL
   - Legitimate subdomains like `outlook.microsoft.com` are recognized

2. **Subdomain Abuse Detection** - Catches subdomain exploitation
   - Detects legitimate domain names embedded in subdomains (e.g., `google.com.attacker.com`)
   - Identifies excessive subdomain levels
   - Validates normal subdomain structures

3. **Typosquatting Detection** - Catches homograph attacks
   - Detects character substitutions:
     - `o` → `0` (zero), `ο` (Greek omicron)
     - `i` → `1`, `l` (lowercase L)
     - `e` → `3`
     - `a` → `4`, `@`
     - `s` → `5`, `$`
   - Examples: `micros0ft.com`, `g00gle.com`, `amaz0n.com`
   - Detects single character differences

4. **Redirect Chain Detection** - Identifies suspicious redirect patterns
   - Tracks multiple redirects to final destination
   - Flags excessive redirect chains (3+ redirects)
   - Reveals obfuscation attempts

## 📊 Risk Scoring System

- **SAFE** (0-14 points): No threats detected
- **LOW** (15-29 points): Minor issues, use caution
- **MEDIUM** (30-49 points): Several warning signs
- **HIGH** (50-69 points): Likely phishing attempt
- **CRITICAL** (70+ points): Definite phishing threat

## 🚀 Quick Start

### Option 1: Command Line (Standalone Python)

```bash
# Install required dependencies
pip install requests

# Run the tool
python phishing_detector.py
```

### Option 2: Web Interface (Recommended)

```bash
# Install Flask and CORS
pip install flask flask-cors requests

# Run the Flask server
python app.py

# Open in browser
# http://localhost:5000
# Then open index.html in your browser or serve it with Flask
```

## 📁 Files Included

- **phishing_detector.py** - Core detection engine with all analysis methods
- **app.py** - Flask REST API backend
- **index.html** - Beautiful web interface with real-time analysis
- **README.md** - This documentation

## 🔍 How to Use

### Command Line Usage
```
1. Run: python phishing_detector.py
2. Select option: 1 (Analyze URL)
3. Enter URL: https://example.com or example.com
4. Review detailed analysis with risk score
5. Choose to analyze another URL or exit
```

### Web Interface Usage
1. Open `index.html` in your web browser
2. Enter a URL in the input field
3. Click "🔍 Analyze URL" button
4. Review results with visual risk meter
5. Click "↺ Reset" to clear and start over

## 📋 Example Analysis Results

### Example 1: Legitimate Domain
```
URL: https://www.microsoft.com
Risk Score: 2/100
Risk Level: SAFE

✓ URL Length - SAFE (27 chars)
✓ HTTPS Protocol - SAFE (Uses HTTPS)
✓ Suspicious Keywords - SAFE (No keywords)
✓ Brand-Domain Mismatch - SAFE (Legitimate)
✓ Subdomain Abuse - SAFE (Normal structure)
✓ Typosquatting Detection - SAFE (Not detected)
```

### Example 2: Phishing Attempt
```
URL: https://micros0ft-verify-account.tk/login
Risk Score: 85/100
Risk Level: CRITICAL

✓ URL Length - SUSPICIOUS (42 chars)
✓ HTTPS Protocol - SAFE (Uses HTTPS)
✓ Suspicious Keywords - WARNING (Found: verify, login)
✓ Brand-Domain Mismatch - CRITICAL (Microsoft content but .tk domain)
✓ Subdomain Abuse - SUSPICIOUS (3 subdomains)
✓ Typosquatting Detection - CRITICAL (micros0ft ≈ microsoft)
```

## 🎓 Learning Objectives

This tool teaches you about:
1. **Phishing Tactics** - Common tricks used by attackers
2. **URL Analysis** - How to examine URLs for red flags
3. **Domain Validation** - Checking domain legitimacy
4. **Character Substitution** - Typosquatting techniques
5. **SSL/TLS Importance** - Why HTTPS matters
6. **Subdomain Exploitation** - How attackers abuse DNS
7. **Redirect Chains** - Obfuscation through redirection

## 🛡️ Improved Detection Accuracy

### What Was Fixed
Previously, the tool would flag "Microsoft" as suspicious on `microsoft.com`. This has been fixed through:

1. **Brand-Domain Mapping** - Maintains a database of legitimate brands and their correct domains
2. **Context-Aware Analysis** - Only flags brand mentions when they appear on wrong domains
3. **Subdomain Validation** - Recognizes legitimate subdomains like `outlook.microsoft.com`
4. **Typosquatting Intelligence** - Distinguishes between real and fake variations

### Smart Filtering
- ✅ `microsoft.com` - Recognized as legitimate (domain matches brand)
- ✅ `outlook.microsoft.com` - Legitimate subdomain of Microsoft
- ❌ `microsoft-verify.tk` - Flagged (brand mention + wrong domain)
- ❌ `micros0ft.com` - Flagged (typosquatting detected)

## 🔒 Security Notes

- **Use for Educational Purposes** - This tool is designed for learning cybersecurity
- **Don't Click Detected Phishing URLs** - The tool analyzes URLs without visiting them
- **No Personal Data** - This tool doesn't store any URLs or analysis results
- **Local Processing** - All analysis happens on your machine

## 📊 Technical Details

### Python Libraries Used
- `requests` - HTTP requests and redirect following
- `urllib.parse` - URL parsing and validation
- `socket` - DNS resolution for domain validation
- `re` - Regular expression matching

### Detection Weights
- Critical Issues: 30-35 points
- High Risk: 20-25 points
- Medium Risk: 10-15 points
- Low Risk: 5 points

## 🚀 Advanced Features

### WHOIS Lookup Simulation
The tool performs DNS resolution to validate domain existence. For production use, integrate with actual WHOIS services like:
- WHOIS API (whoisapi.com)
- IPQualityScore
- AbuseIPDB

### Redirect Chain Tracking
The tool follows HTTP redirects to detect:
- URL shortener chains
- Redirect loops
- Obfuscation patterns

### Typosquatting Detection
Uses character substitution patterns to catch homograph attacks:
- Visual look-alikes
- Homograph characters (Greek letters, etc.)
- Common typo patterns

## 📝 Example URLs to Test

### Safe URLs
```
https://www.google.com
https://www.amazon.com
https://github.com
https://www.wikipedia.org
```

### Suspicious URLs (for testing)
```
https://micros0ft-verify.tk/login
https://apple-account-update.xyz/confirm
https://paypa1-security.info/verify
https://google.com.attacker.com
https://amazo-n.tk
```

## 🛠️ Customization

### Add New Brands
Edit the `legitimate_brands` dictionary in `phishing_detector.py`:

```python
self.legitimate_brands = {
    'yourcompany.com': ['yourcompany', 'yourapp'],
    # Add more...
}
```

### Add Custom Keywords
Modify the `suspicious_keywords` list:

```python
self.suspicious_keywords = [
    'login', 'verify', 'custom_keyword', ...
]
```

### Adjust Risk Weights
Modify risk scores in individual check methods to suit your needs.

## 🐛 Troubleshooting

### ImportError: No module named 'requests'
```bash
pip install requests
```

### ImportError: No module named 'flask'
```bash
pip install flask flask-cors
```

### Port 5000 already in use
```bash
python app.py --port 5001
```

### URL analysis hangs
The redirect chain check has a 5-second timeout. Check your internet connection.

## 📚 Resources for Further Learning

1. **OWASP Phishing Guide** - owasp.org/www-community/attacks/phishing
2. **RFC 3986 - URI Generic Syntax** - Understand URL structure
3. **Certificate Transparency Logs** - Monitor SSL certificates
4. **DNS Records** - Learn about DNS security
5. **WHOIS Databases** - Check domain registration details

## 📄 License

This educational tool is provided for learning and research purposes. Use responsibly and ethically.

## 🤝 Contributing

Feel free to enhance the tool:
- Add more detection methods
- Improve accuracy
- Create visualizations
- Integrate external APIs

## ⚠️ Disclaimer

This tool is for educational purposes only. The author is not responsible for misuse. Always get proper authorization before testing security tools on systems you don't own.

---

**Happy Learning! Stay Safe Online! 🔐**
