## RedRecon v1.0 — Task Reference Sheet

| ID | Category | Task Name | MITRE | Risk | CVSS | Priority | What it automates |
|---|---|---|---|---|---|---|---|
| DNS-01 | DNS Recon | DNS Record Complete Audit | T1590.002 | I – Info Disclosure | 7.0 | P2 | dig ANY, SPF/DMARC analysis, MX/NS/TXT, CAA check, wildcard DNS, mail provider detection |
| DNS-02 | DNS Recon | CNAME Dangling — Subdomain Takeover | T1584 | S – Spoofing | 8.5 | P1 | Checks CNAMEs against 20+ provider fingerprints (S3, CloudFront, GitHub Pages, Heroku, Netlify, Vercel, Azure...) |
| DNS-03 | DNS Recon | Subdomain Enumeration | T1590.001 | I – Info Disclosure | 6.5 | P2 | 200+ wordlist brute force + crt.sh CT logs |
| DNS-04 | DNS Recon | DNS Zone Transfer (AXFR) | T1590.002 | I – Info Disclosure | 9.0 | P1 | Tests all nameservers for AXFR |
| CLOUD-01 | Cloud Recon | AWS S3 Open Bucket | T1530 | C – Confidentiality | 9.1 | P1 | 500+ bucket name permutations, lists files if open |
| CLOUD-02 | Cloud Recon | AWS S3 Private Bucket Detection | T1530 | I – Info Disclosure | 5.0 | P3 | Confirms private bucket existence |
| CLOUD-03 | Cloud Recon | GCP Cloud Storage Open Bucket | T1530 | C – Confidentiality | 9.1 | P1 | Checks storage.googleapis.com |
| CLOUD-04 | Cloud Recon | Azure Blob Open Container | T1530 | C – Confidentiality | 9.1 | P1 | Checks .blob.core.windows.net |
| CLOUD-05 | Cloud Recon | AWS Route53 Detection | T1590.002 | I – Info Disclosure | 5.5 | P2 | NS record analysis |
| GWS-01 | Google Workspace | Workspace Tenant Discovery | T1590.001 | I – Info Disclosure | 6.0 | P2 | MX + SPF + SAML redirect probe |
| GWS-02 | Google Workspace | Public Drive/Docs Exposure | T1213.001 | C – Confidentiality | 7.5 | P1 | Generates 5 targeted Drive/Docs dorks |
| GWS-03 | Google Workspace | SPF/DMARC Weakness | T1566.001 | S – Spoofing | 7.0 | P2 | Checks for p=none, +all, missing DMARC |
| LEAK-01 | Credential Leaks | GitHub Secret Detection | T1552.001 | C – Confidentiality | 9.5 | P1 | Org scan, sensitive file check, code search, 15 secret patterns |
| LEAK-02 | Credential Leaks | Paste Site Leaks | T1552 | C – Confidentiality | 8.0 | P1 | Pastebin/Gist/Ghostbin dorks |
| LEAK-03 | Credential Leaks | HIBP Domain Breach Check | T1589.001 | C – Confidentiality | 8.0 | P1 | HIBP API (needs key) |
| RECON-01 | Infrastructure | Technology Fingerprinting | T1592.002 | I – Info Disclosure | 5.0 | P3 | 25+ tech signatures, version leak detection |
| RECON-02 | Infrastructure | Security Header Audit | T1592 | I – Info Disclosure | 5.3 | P3 | HSTS, CSP, X-Frame-Options, etc. |
| RECON-03 | Infrastructure | WHOIS & Domain Intel | T1590.001 | I – Info Disclosure | 4.0 | P3 | RDAP lookup, registrar, nameserver cloud provider |
| RECON-04 | Infrastructure | SSL/TLS Certificate Analysis | T1590 | I – Info Disclosure | 5.0 | P3 | Expiry, cipher, SANs, issuer |
| OSINT-01 | OSINT | Employee / LinkedIn Enum | T1591.004 | I – Info Disclosure | 6.0 | P2 | Email harvesting + pattern detection + LinkedIn dorks |
| OSINT-02 | OSINT | Google Dork Automation | T1593 | C – Confidentiality | 7.5 | P1 | 60+ dorks across 8 categories |
| OSINT-03 | OSINT | Shodan Attack Surface | T1592 | I – Info Disclosure | 6.5 | P2 | Shodan API or search links |

---

## Usage

```bash
# Install
pip install -r requirements.txt

# Black box — just company name
python redrecon.py -c "Edtech India"

# With domain
python redrecon.py -c "Edtech India" -d edtechindia.com

# Full scan with keys
python redrecon.py -c "Edtech India" -d edtechindia.com \
  --github-token ghp_xxx \
  --shodan-key xxx \
  --output ./reports

# Specific modules (faster)
python redrecon.py -c "Edtech India" -d edtechindia.com \
  --modules dns,axfr,subdomains,takeover,aws,github,dorks
```

## Output
- `redrecon_COMPANY_DATE.html` — Clickable findings table, filter by severity
- `redrecon_COMPANY_DATE_tasksheet.csv` — Direct import into your task tracker / Excel
- `redrecon_COMPANY_DATE.json` — Full machine-readable data
