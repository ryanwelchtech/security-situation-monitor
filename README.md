# Security Situation Monitor

Real-time security monitoring dashboard with CVE tracking, threat intelligence correlation, and ransomware/dark web activity monitoring.

## Features

### 1. CVE Threat Feed
- Real-time CVE data from NIST NVD API 2.0
- CVSS severity filtering (Critical, High, Medium, Low)
- Direct links to NVD vulnerability details
- 7-day rolling window of recent vulnerabilities

### 2. CISA KEV (Known Exploited Vulnerabilities)
- Live feed from CISA's authoritative KEV catalog
- Tracks vulnerabilities actively exploited in the wild
- Remediation due dates highlighted
- Ransomware campaign indicators

### 3. Threat Intelligence Correlation
- IOC feed from ThreatFox (abuse.ch)
- Real-time malware indicators (IP, Domain, URL, Hash)
- Confidence scoring
- Malware family tracking
- Cross-reference with CVEs and ransomware data

### 4. Ransomware Activity Monitor (Dark Web)
- Live victim data from Ransomware.live API
- Tracks active ransomware group activity
- Geographic and sector analysis
- Threat actor profiling

### 5. Correlation Engine
- Cross-references CVEs with active exploitation
- Identifies ransomware precursor malware
- Sector and geographic threat concentration analysis
- Active threat actor tracking

### 6. Global Threat Map
- D3.js interactive world map
- Visual threat markers by country
- Zoom and pan controls

## Data Sources

| Source | Data Type | Update Frequency |
|--------|-----------|------------------|
| [NIST NVD API 2.0](https://nvd.nist.gov/developers) | CVE vulnerabilities | Real-time |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited vulnerabilities | Daily |
| [ThreatFox](https://threatfox.abuse.ch/) | IOCs, malware indicators | Real-time |
| [Ransomware.live](https://www.ransomware.live/) | Ransomware victims & groups | Real-time |

## Tech Stack

- **Frontend**: Vanilla JavaScript (ES6 Modules)
- **Visualization**: D3.js v7, TopoJSON
- **Styling**: CSS3 with CSS Variables
- **APIs**: REST, CORS proxy for cross-origin requests
- **Hosting**: Vercel (static deployment)

## Local Development

```bash
# Clone the repository
git clone https://github.com/ryanwelchtech/security-situation-monitor.git
cd security-situation-monitor

# Serve locally (requires Node.js)
npx serve .

# Open in browser
open http://localhost:3000
```

## Deployment

The application is deployed on Vercel as a static site. Any push to the main branch triggers automatic deployment.

## Security Considerations

- No sensitive data stored client-side
- All API calls use public endpoints
- CORS proxy used for APIs without CORS support
- CSP and security headers configured via vercel.json

## Author

**Ryan Welch** - Cloud & Systems Security Engineer

## License

MIT License
