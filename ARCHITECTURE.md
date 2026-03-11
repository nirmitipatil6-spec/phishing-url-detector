# Architecture & Detection Flow

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHISHING DETECTION SYSTEM                    │
└─────────────────────────────────────────────────────────────────┘

                              USER INTERFACE
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              WEB INTERFACE      COMMAND LINE      API
              (index.html)    (phishing_detector.py) (Flask)
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                        ┌───────────────────────┐
                        │   FLASK API LAYER     │
                        │  /api/analyze route   │
                        └───────────────────────┘
                                    │
                    ┌───────────────────────────────┐
                    │   PHISHING DETECTOR ENGINE    │
                    │  (PhishingDetector Class)     │
                    └───────────────────────────────┘
                                    │
          ┌─────────────────────────┼──────────────────────────┐
          │                         │                          │
     ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
     │  ANALYSIS MODULE│  │ DETECTION METHOD │  │  DATA SOURCES    │
     └─────────────────┘  └──────────────────┘  └──────────────────┘
          │                      │                      │
     - URL parsing         - Keywords check        - Brand DB
     - Structure check      - Length check          - Typo patterns
     - Risk scoring         - HTTPS check           - Subdomain rules
     - Report generation    - Brand mismatch        - Domain resolver
                           - Typosquatting
                           - Subdomain abuse
                           - Redirect chains
                           - Domain validation
```

## Detection Flow Diagram

```
USER ENTERS URL
      │
      ▼
URL VALIDATION
      │
      ▼
PARSE URL STRUCTURE
      │
      ▼
RUN PARALLEL CHECKS:
      │
      ├─► CHECK #1: URL LENGTH
      │   └─► Length > 75 chars? → Risk += 20
      │
      ├─► CHECK #2: HTTPS PROTOCOL
      │   └─► HTTP only? → Risk += 25
      │   └─► No protocol? → Risk += 30
      │
      ├─► CHECK #3: SUSPICIOUS KEYWORDS
      │   └─► Found keywords? → Risk += 5-20
      │
      ├─► CHECK #4: BRAND-DOMAIN MISMATCH
      │   └─► Brand mentioned but wrong domain? → Risk += 30-35
      │
      ├─► CHECK #5: SUBDOMAIN ABUSE
      │   ├─► Legitimate domain in subdomain? → Risk += 35
      │   └─► Too many subdomains (>3 dots)? → Risk += 15
      │
      ├─► CHECK #6: TYPOSQUATTING DETECTION
      │   └─► Character substitutions detected? → Risk += 20-35
      │
      ├─► CHECK #7: DOMAIN AGE & WHOIS
      │   └─► Domain resolves? DNS check performed
      │
      └─► CHECK #8: REDIRECT CHAIN
          ├─► Excessive redirects (3+)? → Risk += 20
          └─► Minor redirects (1-2)? → Risk += 5
      │
      ▼
AGGREGATE RISK SCORES
      │
      ▼
DETERMINE RISK LEVEL:
      │
      ├─► SAFE        (0-14)   - Green
      ├─► LOW         (15-29)  - Yellow
      ├─► MEDIUM      (30-49)  - Orange
      ├─► HIGH        (50-69)  - Red
      └─► CRITICAL    (70+)    - Dark Red
      │
      ▼
GENERATE REPORT
      │
      ▼
DISPLAY RESULTS
```

## Risk Calculation Algorithm

```python
def analyze_url(url):
    risk_score = 0
    details = []
    
    # Each check adds risk points
    for check in all_checks:
        points = check(url)
        risk_score += points
        details.append(check.report())
    
    # Calculate final risk level
    risk_level = get_risk_level(risk_score)
    
    return {
        'url': url,
        'risk_score': min(risk_score, 100),  # Cap at 100
        'risk_level': risk_level,
        'details': details
    }

Risk Score Weights:
├─ Critical Risk (30-35 points each)
│  ├─ Brand-Domain Mismatch
│  ├─ Subdomain Abuse (major)
│  └─ Typosquatting Detection
│
├─ High Risk (20-25 points each)
│  ├─ Missing HTTPS
│  ├─ Domain Doesn't Resolve
│  └─ Invalid URL Structure
│
├─ Medium Risk (10-15 points each)
│  ├─ Excessive URL Length
│  ├─ Too Many Subdomains
│  └─ Multiple Redirects
│
└─ Low Risk (5 points each)
   └─ Suspicious Keywords
```

## Detection Method Details

### 1. URL Length Analysis
```
INPUT: URL string
   │
   ├─► Measure character count
   │
   └─► If length > 75:
       ├─► Add risk: 10-20 points
       └─► Mark: SUSPICIOUS
       
REASON: Phishers use long URLs to hide real domain
```

### 2. HTTPS Protocol Check
```
INPUT: URL
   │
   ├─► Parse protocol
   │
   ├─► If HTTPS → Risk: 0 (SAFE)
   │
   ├─► If HTTP → Risk: +25 (SUSPICIOUS)
   │
   └─► If none → Risk: +30 (CRITICAL)
       
REASON: HTTPS provides encryption; HTTP is unencrypted
```

### 3. Suspicious Keywords Detection
```
KEYWORD_LIST = [
    'login', 'verify', 'account', 'update', 'confirm',
    'secure', 'urgent', 'suspended', 'click', 'warning',
    'alert', 'action', 'validate', 'authenticate',
    'payment', 'bank', 'paypal', 'amazon', 'apple'
]

INPUT: URL string
   │
   ├─► For each keyword:
   │   └─► Is keyword in URL? → Risk += 5
   │
   └─► Cap risk at 20 points
   
REASON: These words create urgency for user action
```

### 4. Brand-Domain Mismatch Check
```
BRAND_DATABASE = {
    'microsoft.com': ['microsoft', 'windows', 'outlook', 'azure'],
    'google.com': ['google', 'gmail', 'youtube'],
    'apple.com': ['apple', 'icloud', 'itunes'],
    ...
}

INPUT: URL
   │
   ├─► Extract domain
   │
   ├─► For each brand:
   │   ├─► Is brand keyword in URL?
   │   │
   │   └─► Does domain match brand domain?
   │       ├─► YES → SAFE (0 risk)
   │       └─► NO → CRITICAL (+30-35 risk)
   │
EXAMPLE:
   Input: "https://microsoft-verify.tk"
   - Contains: "microsoft" ✓
   - Domain: .tk (not .com) ✗
   - Result: CRITICAL MISMATCH
```

### 5. Subdomain Abuse Detection
```
SUSPICIOUS_BRANDS = [
    'microsoft.com', 'google.com', 'apple.com',
    'facebook.com', 'amazon.com', 'paypal.com'
]

INPUT: Domain name
   │
   ├─► Check for brand domains in subdomains
   │   ├─► google.com.attacker.tk → CRITICAL
   │   ├─► amazon.co.attack.xyz → CRITICAL
   │   └─► secure.microsoft.com → SAFE (legitimate)
   │
   ├─► Count subdomain levels (dots)
   │   ├─► > 3 dots → SUSPICIOUS (+15)
   │   └─► <= 3 dots → SAFE
   │
EXAMPLES:
   ✓ www.google.com (2 dots) - Safe
   ✓ mail.gmail.google.com (3 dots) - Safe
   ✗ google.com.phisher.tk (3 dots) - Critical (brand abuse)
   ✗ a.b.c.d.example.com (5 dots) - Suspicious
```

### 6. Typosquatting Detection
```
CHARACTER_SUBSTITUTIONS = {
    'o': ['0', 'ο', 'ᴏ'],           # zero, Greek omicron
    'i': ['1', 'l', '!', 'ı'],     # one, lowercase L, etc.
    'e': ['3'],                     # three
    'a': ['4', '@'],                # four, at sign
    's': ['5', '$'],                # five, dollar
    'g': ['9', 'q'],                # nine, q
    'l': ['1', 'i']                 # one, lowercase i
}

LOGIC:
1. For each brand name
   └─► Try all character substitutions
       └─► Does result match domain? → CRITICAL (+35)

EXAMPLES:
   ✓ microsoft.com vs micros0ft.com
     - Try: m→m, i→i, c→c, r→r, o→0 ← Match found!
     - Result: CRITICAL TYPOSQUATTING

   ✓ google.com vs g00gle.com
     - Try: g→g, o→0, o→0 ← Match found!
     - Result: CRITICAL TYPOSQUATTING
```

### 7. Domain Age & WHOIS Lookup
```
INPUT: Domain name
   │
   ├─► Perform DNS lookup
   │   ├─► socket.gethostbyname()
   │   │
   │   ├─► Success → Domain exists, get IP
   │   │   └─► Status: RESOLVED
   │   │
   │   └─► Failure → Domain doesn't exist
   │       └─► Risk: +20 (CRITICAL)
   │
LIMITATION: 
   - This version performs DNS check only
   - For production, integrate WHOIS API
   - Check domain registration age
```

### 8. Redirect Chain Detection
```
INPUT: URL
   │
   ├─► Follow HTTP redirects
   │   ├─► requests.head(allow_redirects=False)
   │   ├─► Follow Location header
   │   ├─► Count redirects (max 10)
   │   └─► Timeout: 5 seconds
   │
   ├─► Analyze redirect pattern:
   │   ├─► 0-1 redirects → SAFE
   │   ├─► 2-3 redirects → WARNING (+5)
   │   └─► 3+ redirects → SUSPICIOUS (+20)
   │
EXAMPLES:
   ✓ https://example.com
     └─► Direct, no redirects → SAFE

   ✗ https://shorturl.com/abc
     ├─► Redirect 1: https://phishing.tk
     ├─► Redirect 2: https://steal-data.ru
     └─► Multiple redirects → SUSPICIOUS
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│ INPUT: User provides URL                                │
│ "https://micros0ft-verify.tk/login"                     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │ PARSING LAYER                │
        ├──────────────────────────────┤
        │ - Extract protocol: https    │
        │ - Extract domain: ...verify.tk│
        │ - Extract path: /login       │
        │ - Calculate length: 45       │
        └──────────────┬───────────────┘
                       │
           ┌───────────┴────────────┐
           │                        │
           ▼                        ▼
    ┌────────────────┐      ┌──────────────────┐
    │ DATABASE LOOKUP│      │ PATTERN MATCHING │
    ├────────────────┤      ├──────────────────┤
    │ Brand database │      │ Keyword scan     │
    │ Typo patterns  │      │ Subdomain check  │
    │ Keyword lists  │      │ Redirect follow  │
    └────────┬───────┘      └────────┬─────────┘
             │                       │
             └───────────┬───────────┘
                         │
                         ▼
        ┌──────────────────────────────┐
        │ RISK CALCULATION             │
        ├──────────────────────────────┤
        │ ✓ URL Length: 45 (safe)      │
        │ ✓ HTTPS: Yes (safe)          │
        │ ✗ Keywords: verify (warning) │
        │ ✗ Brand mismatch: (critical) │
        │ ✗ Typosquatting: o→0 (crit)  │
        │ ─────────────────────────── │
        │ TOTAL RISK: 80/100           │
        └────────────┬─────────────────┘
                     │
                     ▼
        ┌──────────────────────────────┐
        │ OUTPUT: Risk Report          │
        ├──────────────────────────────┤
        │ Risk Score: 80/100           │
        │ Risk Level: CRITICAL         │
        │ Detailed findings: [...]     │
        │ Timestamp: [...]             │
        └──────────────────────────────┘
```

## Detection Accuracy Improvements

### The Microsoft Problem (Solved)

**Before Fix:**
```
Input: https://microsoft.com
Output: FLAGGED AS SUSPICIOUS (incorrect)
Reason: Contains keyword "microsoft"
Problem: False positive on legitimate brand site
```

**After Fix:**
```
Input: https://microsoft.com
Output: SAFE (correct)

Analysis:
1. Extract domain: microsoft.com
2. Check keywords: Found "microsoft"
3. Check brand database: microsoft → microsoft.com (MATCH!)
4. No mismatch detected → SAFE
```

**Smart Filtering Logic:**
```python
if brand_mentioned_in_url:
    if domain_matches_brand:
        → SAFE (legitimate site)
    else:
        → CRITICAL (brand impersonation)
        
Example 1: microsoft.com
- Contains: "microsoft" ✓
- Domain: microsoft.com ✓
- Match: YES → SAFE

Example 2: microsoft-verify.tk
- Contains: "microsoft" ✓
- Domain: verify.tk ✗
- Match: NO → CRITICAL
```

---

## Performance Considerations

```
Analysis Speed:
├─ Fast checks (<100ms)
│  ├─ URL parsing
│  ├─ Keyword matching
│  ├─ Length checking
│  ├─ Structure validation
│  └─ Pattern matching
│
└─ Slower checks (100ms-5000ms)
   ├─ DNS resolution (≈100-500ms)
   ├─ Redirect chain following (≈500-5000ms)
   └─ WHOIS lookup (not implemented)
```

---

End of Architecture & Flow Documentation
