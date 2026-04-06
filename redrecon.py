#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  RedRecon v1.0 — Automated Red Team Recon & Attack Surface Mapping      ║
║  Black-box recon from company name / domain only                         ║
║  Generates full findings report in red team task format                  ║
║  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY                             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import os, sys, re, json, time, socket, ssl, threading, datetime, argparse
import subprocess, ipaddress, hashlib, queue
from urllib.parse import quote, urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── colour helpers ──────────────────────────────────────────────────────────
class C:
    R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
    M='\033[95m'; C='\033[96m'; W='\033[97m'; BOLD='\033[1m'
    DIM='\033[2m'; RST='\033[0m'

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    requests.packages.urllib3.disable_warnings()
    HAS_REQ = True
except ImportError:
    HAS_REQ = False

try:
    import dns.resolver, dns.zone, dns.query, dns.exception
    import dns.rdatatype, dns.flags
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ── global results store ────────────────────────────────────────────────────
FINDINGS = []          # list of Finding dicts
LOCK = threading.Lock()
SEVERITY_ORDER = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}

def add_finding(finding):
    with LOCK:
        FINDINGS.append(finding)

def banner():
    print(f"""{C.R}{C.BOLD}
  ██████╗ ███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║  ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║  ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.Y}  Automated Red Team Recon Engine v1.0
{C.R}  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY{C.RST}
""")

def info(m):  print(f"  {C.B}[*]{C.RST} {m}")
def good(m):  print(f"  {C.G}[+]{C.RST} {C.G}{m}{C.RST}")
def warn(m):  print(f"  {C.Y}[!]{C.RST} {C.Y}{m}{C.RST}")
def bad(m):   print(f"  {C.R}[-]{C.RST} {m}")
def found(m): print(f"  {C.M}[★]{C.RST} {C.BOLD}{m}{C.RST}")
def hdr(m):   print(f"\n{C.C}{C.BOLD}{'═'*65}\n  {m}\n{'═'*65}{C.RST}")

SESSION = None

def make_session(timeout=10):
    s = requests.Session()
    s.verify = False
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429,500,502,503])
    s.mount('http://',  HTTPAdapter(max_retries=retry))
    s.mount('https://', HTTPAdapter(max_retries=retry))
    s.headers.update({'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'})
    return s

# ════════════════════════════════════════════════════════════════════════════
# TASK DEFINITIONS  — mirrors the red team task sheet format
# ════════════════════════════════════════════════════════════════════════════
TASKS = [
    {
        "id": "DNS-01",
        "category": "DNS Recon",
        "name": "DNS Record Complete Audit — Zone Walking",
        "tactic": "T1590.002",
        "risk_type": "I – Info Disclosure",
        "cvss": 7.0,
        "priority": "P2",
        "severity": "HIGH",
        "description": "Complete DNS audit to identify info disclosed, zone transfer vulns, and DNS infrastructure mapping.",
    },
    {
        "id": "DNS-02",
        "category": "DNS Recon",
        "name": "Subdomain Takeover — CNAME Dangling Detection",
        "tactic": "T1584",
        "risk_type": "S – Spoofing",
        "cvss": 8.5,
        "priority": "P1",
        "severity": "CRITICAL",
        "description": "Identify subdomains with CNAME records pointing to decommissioned AWS/GCP/Azure services.",
    },
    {
        "id": "DNS-03",
        "category": "DNS Recon",
        "name": "Subdomain Enumeration — Brute Force + Certificate Transparency",
        "tactic": "T1590.001",
        "risk_type": "I – Info Disclosure",
        "cvss": 6.5,
        "priority": "P2",
        "severity": "MEDIUM",
        "description": "Enumerate all subdomains via wordlist brute force and crt.sh CT logs.",
    },
    {
        "id": "DNS-04",
        "category": "DNS Recon",
        "name": "DNS Zone Transfer (AXFR) Test",
        "tactic": "T1590.002",
        "risk_type": "I – Info Disclosure",
        "cvss": 9.0,
        "priority": "P1",
        "severity": "CRITICAL",
        "description": "Test all nameservers for DNS zone transfer (AXFR). If successful, attacker gets complete internal DNS map.",
    },
    {
        "id": "CLOUD-01",
        "category": "Cloud Recon",
        "name": "AWS S3 Bucket — Open Bucket Discovery",
        "tactic": "T1530",
        "risk_type": "C – Confidentiality",
        "cvss": 9.1,
        "priority": "P1",
        "severity": "CRITICAL",
        "description": "Discover publicly accessible S3 buckets that may contain sensitive data.",
    },
    {
        "id": "CLOUD-02",
        "category": "Cloud Recon",
        "name": "AWS S3 Bucket — Existence Detection (Private)",
        "tactic": "T1530",
        "risk_type": "I – Info Disclosure",
        "cvss": 5.0,
        "priority": "P3",
        "severity": "MEDIUM",
        "description": "Identify private S3 buckets that exist — confirms cloud infrastructure.",
    },
    {
        "id": "CLOUD-03",
        "category": "Cloud Recon",
        "name": "GCP Cloud Storage — Open Bucket Discovery",
        "tactic": "T1530",
        "risk_type": "C – Confidentiality",
        "cvss": 9.1,
        "priority": "P1",
        "severity": "CRITICAL",
        "description": "Discover publicly accessible Google Cloud Storage buckets.",
    },
    {
        "id": "CLOUD-04",
        "category": "Cloud Recon",
        "name": "Azure Blob Storage — Open Container Discovery",
        "tactic": "T1530",
        "risk_type": "C – Confidentiality",
        "cvss": 9.1,
        "priority": "P1",
        "severity": "CRITICAL",
        "description": "Discover publicly accessible Azure Blob Storage containers.",
    },
    {
        "id": "CLOUD-05",
        "category": "Cloud Recon",
        "name": "AWS Route 53 — DNS Infrastructure Mapping",
        "tactic": "T1590.002",
        "risk_type": "I – Info Disclosure",
        "cvss": 5.5,
        "priority": "P2",
        "severity": "MEDIUM",
        "description": "Map AWS Route53 infrastructure via NS records and DNS provider fingerprinting.",
    },
    {
        "id": "GWS-01",
        "category": "Google Workspace",
        "name": "Google Workspace Tenant Discovery",
        "tactic": "T1590.001",
        "risk_type": "I – Info Disclosure",
        "cvss": 6.0,
        "priority": "P2",
        "severity": "MEDIUM",
        "description": "Confirm Google Workspace usage via MX records, SPF, and SAML/SSO endpoint probing.",
    },
    {
        "id": "GWS-02",
        "category": "Google Workspace",
        "name": "Google Drive / Docs Public Share Exposure",
        "tactic": "T1213.001",
        "risk_type": "C – Confidentiality",
        "cvss": 7.5,
        "priority": "P1",
        "severity": "HIGH",
        "description": "Identify publicly shared Google Drive files, Sheets, Docs, Forms belonging to the organisation.",
    },
    {
        "id": "GWS-03",
        "category": "Google Workspace",
        "name": "SPF/DMARC Weakness — Email Spoofing Risk",
        "tactic": "T1566.001",
        "risk_type": "S – Spoofing",
        "cvss": 7.0,
        "priority": "P2",
        "severity": "HIGH",
        "description": "Weak SPF (+all or missing) and absent DMARC allow sending spoofed email from organisation domain.",
    },
    {
        "id": "LEAK-01",
        "category": "Credential Leaks",
        "name": "GitHub Secret / Credential Leak Detection",
        "tactic": "T1552.001",
        "risk_type": "C – Confidentiality",
        "cvss": 9.5,
        "priority": "P1",
        "severity": "CRITICAL",
        "description": "Detect leaked credentials, API keys, AWS keys, tokens in public GitHub repos.",
    },
    {
        "id": "LEAK-02",
        "category": "Credential Leaks",
        "name": "Paste Site Leak Detection (Pastebin/Gist)",
        "tactic": "T1552",
        "risk_type": "C – Confidentiality",
        "cvss": 8.0,
        "priority": "P1",
        "severity": "HIGH",
        "description": "Search paste sites for leaked credentials, internal data, database dumps.",
    },
    {
        "id": "LEAK-03",
        "category": "Credential Leaks",
        "name": "Breach Intelligence — HaveIBeenPwned Domain Check",
        "tactic": "T1589.001",
        "risk_type": "C – Confidentiality",
        "cvss": 8.0,
        "priority": "P1",
        "severity": "HIGH",
        "description": "Check if company email domain appears in known data breaches.",
    },
    {
        "id": "RECON-01",
        "category": "Infrastructure Recon",
        "name": "Technology Stack Fingerprinting",
        "tactic": "T1592.002",
        "risk_type": "I – Info Disclosure",
        "cvss": 5.0,
        "priority": "P3",
        "severity": "MEDIUM",
        "description": "Identify web frameworks, servers, CDNs, analytics, and SaaS tools via HTTP headers and body.",
    },
    {
        "id": "RECON-02",
        "category": "Infrastructure Recon",
        "name": "Security Header Audit",
        "tactic": "T1592",
        "risk_type": "I – Info Disclosure",
        "cvss": 5.3,
        "priority": "P3",
        "severity": "MEDIUM",
        "description": "Check for missing security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
    },
    {
        "id": "RECON-03",
        "category": "Infrastructure Recon",
        "name": "WHOIS & Domain Registration Intelligence",
        "tactic": "T1590.001",
        "risk_type": "I – Info Disclosure",
        "cvss": 4.0,
        "priority": "P3",
        "severity": "LOW",
        "description": "Gather registration details, registrar, nameservers, domain age, and expiry.",
    },
    {
        "id": "RECON-04",
        "category": "Infrastructure Recon",
        "name": "SSL/TLS Certificate Analysis",
        "tactic": "T1590",
        "risk_type": "I – Info Disclosure",
        "cvss": 5.0,
        "priority": "P3",
        "severity": "MEDIUM",
        "description": "Analyse SSL certificates for weak ciphers, expiry, SANs, and CT log history.",
    },
    {
        "id": "OSINT-01",
        "category": "OSINT",
        "name": "Employee & LinkedIn Enumeration",
        "tactic": "T1591.004",
        "risk_type": "I – Info Disclosure",
        "cvss": 6.0,
        "priority": "P2",
        "severity": "MEDIUM",
        "description": "Enumerate employees via LinkedIn/Google. Generate email format and targeted phishing list.",
    },
    {
        "id": "OSINT-02",
        "category": "OSINT",
        "name": "Google Dork — Sensitive File & Data Exposure",
        "tactic": "T1593",
        "risk_type": "C – Confidentiality",
        "cvss": 7.5,
        "priority": "P1",
        "severity": "HIGH",
        "description": "Use Google dorks to find exposed documents, credentials, admin panels, and cloud assets indexed by Google.",
    },
    {
        "id": "OSINT-03",
        "category": "OSINT",
        "name": "Internet Exposure — Shodan Attack Surface",
        "tactic": "T1592",
        "risk_type": "I – Info Disclosure",
        "cvss": 6.5,
        "priority": "P2",
        "severity": "MEDIUM",
        "description": "Map all internet-exposed services, open ports, and CVEs via Shodan.",
    },
]

TASK_MAP = {t['id']: t for t in TASKS}

# ════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN WORDLIST
# ════════════════════════════════════════════════════════════════════════════
SUBDOMAINS_COMMON = [
    'www','mail','smtp','pop','pop3','imap','ftp','sftp','ssh','vpn',
    'remote','citrix','rdp','api','app','apps','web','portal','secure',
    'login','auth','sso','id','identity','account','accounts','my',
    'admin','administrator','cpanel','whm','plesk','panel','dashboard',
    'dev','development','test','testing','uat','staging','qa','beta',
    'demo','sandbox','preview','pre','preprod','prod','production',
    'old','legacy','archive','new','next','v1','v2','v2api',
    'git','gitlab','github','bitbucket','svn','repo','code',
    'ci','cd','jenkins','bamboo','travis','build','deploy','devops',
    'jira','confluence','wiki','kb','docs','documentation','helpdesk',
    'support','service','servicedesk','ticket','tickets','crm','erp',
    'blog','news','press','media','cdn','assets','static','img',
    'images','files','upload','uploads','download','downloads','backup',
    'internal','intranet','corp','corporate','extranet','partner',
    'grafana','kibana','prometheus','datadog','newrelic','splunk',
    'elastic','elasticsearch','logstash','monitor','monitoring','alerts',
    'db','database','mysql','postgres','mongodb','redis','kafka',
    'vault','secrets','config','consul','etcd','zookeeper',
    'k8s','kubernetes','docker','registry','harbor','artifactory',
    'pay','payment','payments','billing','invoice','checkout','shop',
    'store','ecommerce','cart','orders','order','tracking','status',
    'ns','ns1','ns2','ns3','mx','mx1','mx2','relay','exchange',
    'owa','autodiscover','lyncdiscover','meet','zoom','video','voip',
    'mobile','android','ios','api2','api3','graphql','ws','socket',
    'gateway','proxy','lb','haproxy','nginx','ingress',
    'careers','jobs','hr','people','ir','investor','investors',
    's3','storage','files2','media2','bucket','aws','gcp','azure',
    'msoid','sip','_dmarc','_domainkey','_acme-challenge',
]

# ════════════════════════════════════════════════════════════════════════════
# CLOUD TAKEOVER FINGERPRINTS
# ════════════════════════════════════════════════════════════════════════════
TAKEOVER_FINGERPRINTS = [
    # (provider, cname_pattern, error_body_pattern, severity)
    ("AWS S3",            r'\.s3\.amazonaws\.com$',
     ['NoSuchBucket','The specified bucket does not exist'], 'CRITICAL'),
    ("AWS S3 (region)",   r'\.s3[\-\.][a-z0-9\-]+\.amazonaws\.com$',
     ['NoSuchBucket','does not exist'], 'CRITICAL'),
    ("AWS CloudFront",    r'\.cloudfront\.net$',
     ['Bad request','ERROR: The request could not be satisfied'], 'HIGH'),
    ("AWS Elastic Beanstalk", r'\.elasticbeanstalk\.com$',
     ['404 Not Found','NXDOMAIN'], 'CRITICAL'),
    ("AWS ELB",           r'\.elb\.amazonaws\.com$',
     ['NXDOMAIN',''], 'HIGH'),
    ("GitHub Pages",      r'\.github\.io$',
     ["There isn't a GitHub Pages site here",
      "For root URLs","404 There is no GitHub Pages site here"], 'CRITICAL'),
    ("Heroku",            r'\.herokuapp\.com$',
     ['No such app','There is no app configured at that hostname'], 'HIGH'),
    ("Netlify",           r'\.netlify\.app$|\.netlify\.com$',
     ["Not Found - Request ID",'netlify'], 'HIGH'),
    ("Vercel",            r'\.vercel\.app$',
     ['The deployment could not be found','DEPLOYMENT_NOT_FOUND'], 'HIGH'),
    ("Shopify",           r'\.myshopify\.com$',
     ['Sorry, this shop is currently unavailable'], 'MEDIUM'),
    ("HubSpot",           r'\.hs-sites\.com$|\.hubspot\.com$',
     ['Domain not found','does not exist in our system'], 'MEDIUM'),
    ("Zendesk",           r'\.zendesk\.com$',
     ['Help Center Closed'], 'MEDIUM'),
    ("Fastly",            r'\.fastly\.net$',
     ['Fastly error: unknown domain'], 'HIGH'),
    ("Pantheon",          r'\.pantheonsite\.io$',
     ['404 error unknown site'], 'MEDIUM'),
    ("WP Engine",         r'\.wpengine\.com$',
     ['The site you were looking for could not be found'], 'MEDIUM'),
    ("Ghost",             r'\.ghost\.io$',
     ["The thing you were looking for is no longer here"], 'MEDIUM'),
    ("Azure",             r'\.azurewebsites\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$',
     ['404 Web Site not found','Error 404'], 'HIGH'),
    ("GCP / Firebase",    r'\.web\.app$|\.firebaseapp\.com$',
     ['Site Not Found'], 'HIGH'),
    ("Surge",             r'\.surge\.sh$',
     ["project not found"], 'MEDIUM'),
    ("Cargo",             r'\.cargocollective\.com$',
     ['If you\'re moving your domain away from Cargo'], 'MEDIUM'),
    ("Tumblr",            r'\.tumblr\.com$',
     ['Whatever you were looking for doesn\'t currently exist at this address'], 'MEDIUM'),
    ("Acquia",            r'\.acquia-sites\.com$',
     ['The website you are looking for could not be found'], 'MEDIUM'),
]

DMARC_WEAKNESS_PATTERNS = [
    (r'p=none',    'DMARC policy=none (no enforcement — spoofing permitted)',  'HIGH'),
    (r'p=quarantine', 'DMARC policy=quarantine (partial protection)',         'MEDIUM'),
    (r'p=reject',  'DMARC policy=reject (fully enforced)',                    'INFO'),
]

SPF_WEAKNESS_PATTERNS = [
    (r'\+all',  'SPF +all — anyone can send email as this domain!', 'CRITICAL'),
    (r'\?all',  'SPF ?all — neutral, no enforcement',               'HIGH'),
    (r'~all',   'SPF ~all — softfail (partial protection)',         'MEDIUM'),
    (r'-all',   'SPF -all — fully enforced (correct)',              'INFO'),
]

TECH_SIGNATURES = {
    'Nginx':          [('hdr','server','nginx')],
    'Apache':         [('hdr','server','apache')],
    'IIS':            [('hdr','server','microsoft-iis')],
    'PHP':            [('hdr','x-powered-by','php')],
    'ASP.NET':        [('hdr','x-powered-by','asp.net')],
    'Cloudflare':     [('hdr','server','cloudflare'),('hdr','cf-ray','')],
    'AWS CloudFront': [('hdr','x-amz-cf-id','')],
    'Fastly':         [('hdr','x-served-by','cache-')],
    'Akamai':         [('hdr','x-check-cacheable','')],
    'WordPress':      [('body','wp-content/themes'),('body','wp-includes')],
    'Shopify':        [('body','cdn.shopify.com')],
    'Next.js':        [('body','__NEXT_DATA__')],
    'React':          [('body','_react')],
    'Angular':        [('body','ng-version')],
    'Vue.js':         [('body','__vue__')],
    'jQuery':         [('body','jquery.min.js')],
    'Bootstrap':      [('body','bootstrap.min')],
    'Google Analytics':  [('body','gtag(')],
    'Google Tag Manager':[('body','googletagmanager.com/gtm.js')],
    'HubSpot':        [('body','js.hs-scripts.com')],
    'Intercom':       [('body','intercomSettings')],
    'Zendesk':        [('body','zendesk.com')],
    'Stripe':         [('body','js.stripe.com')],
    'Sentry':         [('body','browser.sentry-cdn.com')],
    'Laravel':        [('cookie','laravel_session')],
    'Django':         [('cookie','csrftoken')],
    'Rails':          [('hdr','x-powered-by','phusion passenger')],
}

SECURITY_HEADERS = [
    ('Strict-Transport-Security', 'HSTS — prevents protocol downgrade attacks'),
    ('Content-Security-Policy',   'CSP — prevents XSS and injection'),
    ('X-Frame-Options',           'Clickjacking prevention'),
    ('X-Content-Type-Options',    'MIME sniffing prevention'),
    ('Referrer-Policy',           'Referrer information control'),
    ('Permissions-Policy',        'Browser feature policy'),
    ('X-XSS-Protection',          'Legacy XSS filter'),
]

GITHUB_SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                               'AWS Access Key ID', 'CRITICAL'),
    (r'(?i)aws.{0,20}secret.{0,20}["\'][A-Za-z0-9/+]{40}["\']', 'AWS Secret Key', 'CRITICAL'),
    (r'ghp_[A-Za-z0-9]{36}',                            'GitHub PAT', 'CRITICAL'),
    (r'gho_[A-Za-z0-9]{36}',                            'GitHub OAuth Token', 'CRITICAL'),
    (r'AIza[0-9A-Za-z\-_]{35}',                         'Google API Key', 'HIGH'),
    (r'ya29\.[0-9A-Za-z\-_]+',                          'Google OAuth Token', 'HIGH'),
    (r'sk-[A-Za-z0-9]{48}',                             'OpenAI API Key', 'HIGH'),
    (r'xox[baprs]-[A-Za-z0-9\-]+',                      'Slack Token', 'HIGH'),
    (r'(?i)(db_pass|database_password|db_password)\s*[=:]\s*["\']?([^\s"\']{8,})', 'DB Password', 'CRITICAL'),
    (r'-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY',  'Private Key', 'CRITICAL'),
    (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'API Key', 'HIGH'),
    (r'mongodb(\+srv)?://[^\s"\']+',                    'MongoDB URI', 'CRITICAL'),
    (r'postgres(ql)?://[^\s"\']+',                      'PostgreSQL URI', 'CRITICAL'),
    (r'mysql://[^\s"\']+',                              'MySQL URI', 'CRITICAL'),
    (r'redis://[^\s"\']+',                              'Redis URI', 'HIGH'),
]

SENSITIVE_REPO_FILES = [
    '.env', '.env.prod', '.env.production', '.env.local', '.env.development',
    'credentials.json', 'service-account.json', '.aws/credentials',
    'terraform.tfvars', 'terraform.tfstate', 'terraform.tfstate.backup',
    'kubeconfig', '.kube/config', 'secrets.yml', 'secrets.yaml',
    'config/database.yml', 'config/secrets.yml', 'application.properties',
    'settings.py', 'local_settings.py', 'docker-compose.override.yml',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'server.key', 'private.key',
    '.htpasswd', '.git-credentials', 'netrc', '.netrc',
]

# ════════════════════════════════════════════════════════════════════════════
# DNS MODULE
# ════════════════════════════════════════════════════════════════════════════
def run_dns_audit(domain):
    hdr("DNS-01 | DNS Record Complete Audit")
    task = TASK_MAP['DNS-01']
    evidence_lines = []
    vuln_details   = []

    if not HAS_DNS:
        warn("dnspython not installed — using socket fallback")
        _dns_fallback(domain)
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 8

    record_types = ['A','AAAA','MX','NS','TXT','SOA','CAA','DNSKEY','SRV']
    all_records  = {}

    for rtype in record_types:
        try:
            ans = resolver.resolve(domain, rtype)
            recs = [str(r) for r in ans]
            all_records[rtype] = recs
            for r in recs:
                good(f"  {rtype:<8} {r}")
                evidence_lines.append(f"{rtype}: {r}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            pass

    # ── SPF analysis ──
    for txt in all_records.get('TXT', []):
        if 'v=spf1' in txt.lower():
            info(f"SPF record: {txt}")
            for pattern, desc, sev in SPF_WEAKNESS_PATTERNS:
                if re.search(pattern, txt, re.I):
                    if sev in ('CRITICAL','HIGH'):
                        vuln_details.append({'issue': desc, 'evidence': txt, 'severity': sev})
                        found(f"SPF weakness [{sev}]: {desc}")
                    else:
                        good(f"SPF [{sev}]: {desc}")

    # ── DMARC analysis ──
    try:
        dmarc_ans = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in dmarc_ans:
            txt = str(r)
            evidence_lines.append(f"DMARC: {txt}")
            for pattern, desc, sev in DMARC_WEAKNESS_PATTERNS:
                if re.search(pattern, txt, re.I):
                    if sev != 'INFO':
                        vuln_details.append({'issue': desc, 'evidence': txt, 'severity': sev})
                        found(f"DMARC weakness [{sev}]: {desc}")
                    else:
                        good(f"DMARC fully enforced: {txt}")
    except Exception:
        vuln_details.append({
            'issue': 'No DMARC record found — email spoofing fully unrestricted',
            'evidence': f'_dmarc.{domain} → NXDOMAIN',
            'severity': 'CRITICAL'
        })
        found(f"No DMARC record! Domain email can be fully spoofed.")

    # ── Mail provider detection from MX ──
    for mx in all_records.get('MX', []):
        mx_l = mx.lower()
        if 'google' in mx_l or 'googlemail' in mx_l:
            good(f"Mail provider: Google Workspace (Gmail)")
            evidence_lines.append("Mail: Google Workspace confirmed via MX")
        elif 'outlook' in mx_l or 'protection.outlook' in mx_l:
            good(f"Mail provider: Microsoft 365")
            evidence_lines.append("Mail: Microsoft 365 confirmed via MX")
        elif 'amazonses' in mx_l:
            good(f"Mail provider: AWS SES")
        elif 'mailgun' in mx_l:
            good(f"Mail provider: Mailgun")
        elif 'sendgrid' in mx_l:
            good(f"Mail provider: SendGrid")

    # ── NS / DNS provider detection ──
    for ns in all_records.get('NS', []):
        ns_l = ns.lower()
        if 'awsdns' in ns_l or 'route53' in ns_l or 'amazonaws' in ns_l:
            good(f"DNS Provider: AWS Route 53 — {ns}")
            evidence_lines.append(f"AWS Route53 NS: {ns}")
        elif 'cloudflare' in ns_l:
            good(f"DNS Provider: Cloudflare — {ns}")
        elif 'google' in ns_l:
            good(f"DNS Provider: Google Cloud DNS — {ns}")
        elif 'azure-dns' in ns_l:
            good(f"DNS Provider: Azure DNS — {ns}")

    # ── CAA record ──
    if 'CAA' not in all_records:
        vuln_details.append({
            'issue': 'No CAA record — any CA can issue SSL certs for this domain',
            'evidence': f'dig CAA {domain} → no records',
            'severity': 'LOW'
        })
        warn("No CAA record found")

    # ── Wildcard DNS check ──
    random_sub = f"thissubdomaindoesnotexist123456.{domain}"
    try:
        ans = resolver.resolve(random_sub, 'A')
        vuln_details.append({
            'issue': 'Wildcard DNS record found — all subdomains resolve (masks enumeration)',
            'evidence': f'{random_sub} → {[str(r) for r in ans]}',
            'severity': 'MEDIUM'
        })
        found("Wildcard DNS detected!")
    except Exception:
        good("No wildcard DNS record")

    # Build finding
    top_sev = 'INFO'
    for v in vuln_details:
        if SEVERITY_ORDER.get(v['severity'],99) < SEVERITY_ORDER.get(top_sev,99):
            top_sev = v['severity']

    finding_desc = "\n".join([
        f"• {v['issue']} [{v['severity']}]" for v in vuln_details
    ]) or "No critical DNS misconfigurations found."

    add_finding({
        **task,
        "target":    domain,
        "status":    "VULNERABLE" if vuln_details else "INFO",
        "severity":  top_sev,
        "evidence":  "\n".join(evidence_lines[:30]),
        "details":   finding_desc,
        "raw_records": all_records,
        "vuln_items":  vuln_details,
        "commands":  [
            f"dig {domain} ANY +noall +answer",
            f"dig {domain} TXT +short",
            f"dig {domain} MX +short",
            f"dig _dmarc.{domain} TXT +short",
            f"dig {domain} NS +short",
        ],
        "remediation": (
            "1. Enforce DMARC: p=reject with rua reporting\n"
            "2. Set SPF to -all (hard fail)\n"
            "3. Add CAA records: 0 issue \"letsencrypt.org\"\n"
            "4. Monitor all DNS changes via Route53 change log"
        ),
    })

def run_zone_transfer(domain):
    hdr("DNS-04 | DNS Zone Transfer (AXFR) Test")
    task = TASK_MAP['DNS-04']
    if not HAS_DNS:
        warn("dnspython required — pip install dnspython")
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5

    # Get nameservers
    try:
        ns_records = resolver.resolve(domain, 'NS')
        nameservers = [str(r).rstrip('.') for r in ns_records]
    except Exception as e:
        bad(f"Could not get NS records: {e}")
        return

    info(f"Testing zone transfer on {len(nameservers)} nameservers...")
    vulnerable_ns = []

    for ns in nameservers:
        info(f"  Testing AXFR against {ns}")
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8))
            # If we get here — zone transfer succeeded!
            records = []
            for name, node in z.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")

            found(f"ZONE TRANSFER SUCCESSFUL on {ns}! Got {len(records)} records")
            vulnerable_ns.append(ns)

            add_finding({
                **task,
                "target":   f"{domain} via {ns}",
                "status":   "VULNERABLE",
                "severity": "CRITICAL",
                "evidence": f"dig axfr {domain} @{ns}\n\nReturned {len(records)} DNS records:\n" + "\n".join(records[:20]),
                "details":  f"Zone transfer allowed by {ns}. Full internal DNS map disclosed ({len(records)} records).",
                "commands": [
                    f"dig axfr {domain} @{ns}",
                    f"host -l {domain} {ns}",
                ],
                "remediation": (
                    "Immediately restrict AXFR to authorised IPs only.\n"
                    "Add allow-transfer { none; }; to BIND config or equivalent.\n"
                    "Audit all exposed records for internal hostnames."
                ),
            })
        except dns.exception.FormError:
            good(f"  AXFR refused by {ns} (correct behaviour)")
        except Exception as e:
            good(f"  AXFR refused/failed on {ns}: {type(e).__name__}")

    if not vulnerable_ns:
        add_finding({
            **task,
            "target":   domain,
            "status":   "NOT VULNERABLE",
            "severity": "INFO",
            "evidence": f"Tested nameservers: {', '.join(nameservers)}\nAll refused AXFR.",
            "details":  "Zone transfers properly restricted on all nameservers.",
            "commands": [f"dig axfr {domain} @{ns}" for ns in nameservers],
            "remediation": "No action required.",
        })

def _dns_fallback(domain):
    """Basic DNS check when dnspython unavailable."""
    try:
        ip = socket.gethostbyname(domain)
        good(f"{domain} → {ip}")
    except Exception as e:
        bad(f"Could not resolve {domain}: {e}")

# ════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN ENUMERATION
# ════════════════════════════════════════════════════════════════════════════
def run_subdomain_enum(domain, threads=40):
    hdr("DNS-03 | Subdomain Enumeration")
    task = TASK_MAP['DNS-03']
    found_subs = []
    crtsh_subs = []

    # ── crt.sh ──
    info("Querying crt.sh certificate transparency logs...")
    try:
        r = SESSION.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if r.status_code == 200:
            seen = set()
            for entry in r.json():
                for name in entry.get('name_value','').split('\n'):
                    name = name.strip().lstrip('*.')
                    if domain in name and name not in seen:
                        seen.add(name)
                        crtsh_subs.append(name)
            good(f"crt.sh returned {len(seen)} unique entries")
    except Exception as e:
        bad(f"crt.sh error: {e}")

    # ── Brute force ──
    info(f"Brute forcing {len(SUBDOMAINS_COMMON)} common subdomains...")

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip, 'brute')
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check, s): s for s in SUBDOMAINS_COMMON}
        for f in as_completed(futs):
            r = f.result()
            if r:
                fqdn, ip, src = r
                found(f"Subdomain: {fqdn} → {ip}")
                found_subs.append({'subdomain': fqdn, 'ip': ip, 'source': 'brute'})

    # ── Resolve crt.sh results ──
    info(f"Resolving {len(crtsh_subs)} crt.sh subdomains...")

    def resolve_crt(name):
        try:
            ip = socket.gethostbyname(name)
            return (name, ip)
        except Exception:
            return (name, None)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(resolve_crt, s): s for s in crtsh_subs}
        for f in as_completed(futs):
            r = f.result()
            if r:
                name, ip = r
                if not any(s['subdomain'] == name for s in found_subs):
                    found_subs.append({'subdomain': name, 'ip': ip, 'source': 'crt.sh'})
                    if ip:
                        found(f"crt.sh: {name} → {ip}")

    all_subs_txt = "\n".join(
        f"{s['subdomain']} → {s['ip'] or 'NXDOMAIN'}" for s in found_subs
    )
    add_finding({
        **task,
        "target":   domain,
        "status":   "INFO",
        "severity": "MEDIUM",
        "evidence": f"Total subdomains found: {len(found_subs)}\n\n{all_subs_txt[:3000]}",
        "details":  (f"Found {len(found_subs)} subdomains "
                     f"({len([s for s in found_subs if s['source']=='brute'])} brute-force, "
                     f"{len([s for s in found_subs if s['source']=='crt.sh'])} crt.sh)."),
        "commands": [
            f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq '.[].name_value' | sort -u",
            f"for sub in $(cat wordlist.txt); do host $sub.{domain}; done",
            f"amass enum -passive -d {domain}",
            f"subfinder -d {domain}",
        ],
        "remediation": (
            "Review all discovered subdomains for decommissioned services.\n"
            "Remove DNS records for unused subdomains immediately.\n"
            "Implement DNS monitoring for new subdomain creation."
        ),
        "subdomains": found_subs,
    })
    return found_subs

# ════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN TAKEOVER
# ════════════════════════════════════════════════════════════════════════════
def run_takeover_check(subdomains, domain):
    hdr("DNS-02 | Subdomain Takeover — CNAME Dangling Detection")
    task = TASK_MAP['DNS-02']

    if not HAS_DNS:
        warn("dnspython required for takeover checks")
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4

    vulnerable = []
    info(f"Checking {len(subdomains)} subdomains for CNAME takeover...")

    def check_takeover(sub_info):
        sub = sub_info['subdomain']
        results = []
        # Get CNAME
        try:
            cname_ans = resolver.resolve(sub, 'CNAME')
            for cname in cname_ans:
                target = str(cname.target).rstrip('.')
                # Match against known takeover fingerprints
                for provider, cname_re, error_strings, severity in TAKEOVER_FINGERPRINTS:
                    if re.search(cname_re, target, re.I):
                        # Try to fetch the CNAME target
                        try:
                            r = SESSION.get(f"https://{sub}", timeout=8,
                                            allow_redirects=True)
                            body = r.text
                            for err in error_strings:
                                if err and err.lower() in body.lower():
                                    results.append({
                                        'sub': sub,
                                        'cname': target,
                                        'provider': provider,
                                        'severity': severity,
                                        'error': err,
                                    })
                                    break
                        except Exception:
                            # DNS resolves but HTTP fails = dangling
                            try:
                                socket.gethostbyname(target)
                            except Exception:
                                # CNAME target doesn't resolve = dangling!
                                results.append({
                                    'sub': sub,
                                    'cname': target,
                                    'provider': provider,
                                    'severity': severity,
                                    'error': 'CNAME target NXDOMAIN',
                                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass
        return results

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(check_takeover, s): s for s in subdomains}
        for f in as_completed(futs):
            results = f.result()
            for item in results:
                found(f"TAKEOVER [{item['severity']}]: {item['sub']} → {item['cname']} ({item['provider']})")
                vulnerable.append(item)

    if vulnerable:
        evidence = "\n".join([
            f"[{v['severity']}] {v['sub']}\n  CNAME → {v['cname']}\n  Provider: {v['provider']}\n  Indicator: {v['error']}"
            for v in vulnerable
        ])
        add_finding({
            **task,
            "target":   domain,
            "status":   "VULNERABLE",
            "severity": "CRITICAL",
            "evidence": evidence,
            "details":  (f"{len(vulnerable)} subdomain(s) vulnerable to takeover.\n"
                         "Attacker can claim these cloud resources and serve malicious content "
                         "under the company's trusted domain."),
            "commands": [
                f"dig CNAME {v['sub']} +short" for v in vulnerable[:5]
            ] + [
                f"nuclei -t takeovers/ -l subdomains.txt",
                f"subover -l subdomains.txt -o takeover_results.txt",
            ],
            "remediation": (
                "URGENT: Delete all dangling CNAME DNS records immediately.\n"
                "Audit Route53 before decommissioning any cloud resource.\n"
                "Set up automated monitoring: SubOver / nuclei takeover templates.\n"
                "DO NOT claim the resources yourself — document and report."
            ),
            "vulnerable_subs": vulnerable,
        })
    else:
        add_finding({
            **task,
            "target":   domain,
            "status":   "NOT VULNERABLE",
            "severity": "INFO",
            "evidence": f"Checked {len(subdomains)} subdomains — no dangling CNAMEs found.",
            "details":  "No subdomain takeover vulnerabilities detected.",
            "commands": ["subover -l subdomains.txt","nuclei -t takeovers/ -l subdomains.txt"],
            "remediation": "Continue monitoring. Re-check after any infrastructure changes.",
        })

# ════════════════════════════════════════════════════════════════════════════
# AWS S3 MODULE
# ════════════════════════════════════════════════════════════════════════════
def run_s3_enum(company, domains, threads=40):
    hdr("CLOUD-01/02 | AWS S3 Bucket Discovery")
    slug  = re.sub(r'[^a-z0-9\-]', '-', company.lower()).strip('-')
    slug2 = re.sub(r'[^a-z0-9]', '', company.lower())

    prefixes = ['','backup','backups','dev','prod','staging','test','data',
                'logs','assets','media','files','uploads','static','public',
                'private','internal','archive','dump','database','db',
                'config','secret','secrets','credentials','keys','terraform',
                'infra','build','releases','artifacts','docs','reports',
                'invoices','hr','finance','marketing','engineering','security',
                'images','code','source','src','app','web','api','raw','old']
    suffixes = ['','backup','dev','prod','staging','test','data','bucket',
                'storage','files','assets','-public','-private','-internal',
                '2024','2025','2023','old','new','-bucket','-storage','-data']

    candidates = set()
    for p in prefixes:
        for s in suffixes:
            for base in [slug, slug2]:
                for n in [f"{p}-{base}{s}", f"{base}-{p}{s}", f"{p}{base}{s}"]:
                    n = n.strip('-')
                    if 3 <= len(n) <= 63 and re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', n):
                        candidates.add(n)

    for d in domains[:2]:
        base = d.split('.')[0]
        for s in ['','-data','-assets','-backup','-files','-static','-media']:
            n = f"{base}{s}"
            if 3 <= len(n) <= 63:
                candidates.add(n)

    open_buckets   = []
    private_buckets = []

    info(f"Testing {len(candidates)} S3 bucket candidates...")

    def check_bucket(name):
        found_items = []
        for url in [f"https://{name}.s3.amazonaws.com",
                    f"https://s3.amazonaws.com/{name}"]:
            try:
                r = SESSION.get(url, timeout=6, allow_redirects=True)
                st = r.status_code
                if st == 200:
                    # Try to parse listing
                    files = re.findall(r'<Key>([^<]+)</Key>', r.text)
                    found_items.append({
                        'name': name, 'url': url,
                        'status': 'OPEN', 'severity': 'CRITICAL',
                        'file_count': len(files),
                        'sample_files': files[:10],
                        'response_size': len(r.content),
                    })
                elif st == 403:
                    found_items.append({
                        'name': name, 'url': url,
                        'status': 'EXISTS_PRIVATE', 'severity': 'MEDIUM',
                    })
                    break
                elif st == 301:
                    found_items.append({
                        'name': name, 'url': url,
                        'status': 'EXISTS_REDIRECT', 'severity': 'LOW',
                        'location': r.headers.get('Location',''),
                    })
                    break
            except Exception:
                pass
        return found_items

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(check_bucket, n): n for n in candidates}
        for f in as_completed(futs):
            items = f.result()
            for item in items:
                if item['status'] == 'OPEN':
                    found(f"S3 OPEN: s3://{item['name']} ({item['file_count']} files visible)")
                    open_buckets.append(item)
                elif item['status'] == 'EXISTS_PRIVATE':
                    good(f"S3 private: s3://{item['name']}")
                    private_buckets.append(item)

    # Report open buckets
    if open_buckets:
        ev = "\n".join([
            f"s3://{b['name']} — {b['file_count']} files exposed\n"
            f"  URL: {b['url']}\n"
            f"  Sample files: {', '.join(b['sample_files'][:5])}"
            for b in open_buckets
        ])
        add_finding({
            **TASK_MAP['CLOUD-01'],
            "target":   company,
            "status":   "VULNERABLE",
            "severity": "CRITICAL",
            "evidence": ev,
            "details":  (f"{len(open_buckets)} publicly accessible S3 bucket(s) found.\n"
                         "Anyone on the internet can list and download all files."),
            "commands": [
                f"aws s3 ls s3://{b['name']} --no-sign-request" for b in open_buckets[:3]
            ] + ["aws s3 sync s3://BUCKET_NAME . --no-sign-request"],
            "remediation": (
                "Immediately enable Block Public Access on all S3 buckets.\n"
                "Review bucket policies and ACLs.\n"
                "Enable S3 server-side encryption.\n"
                "Enable S3 access logging and CloudTrail."
            ),
            "open_buckets": open_buckets,
        })

    # Report private buckets (info)
    if private_buckets:
        add_finding({
            **TASK_MAP['CLOUD-02'],
            "target":   company,
            "status":   "INFO",
            "severity": "MEDIUM",
            "evidence": "\n".join([f"s3://{b['name']} (private, access denied)" for b in private_buckets[:20]]),
            "details":  f"{len(private_buckets)} private S3 bucket(s) identified. Access denied but existence confirmed.",
            "commands": [f"aws s3api head-bucket --bucket {b['name']}" for b in private_buckets[:3]],
            "remediation": "Confirm all private buckets are intentionally private. Enable MFA delete and versioning.",
            "private_buckets": private_buckets,
        })

# ════════════════════════════════════════════════════════════════════════════
# GCP + AZURE STORAGE
# ════════════════════════════════════════════════════════════════════════════
def run_cloud_storage(company):
    hdr("CLOUD-03/04 | GCP & Azure Storage Enumeration")
    slug  = re.sub(r'[^a-z0-9\-]', '-', company.lower()).strip('-')
    slug2 = re.sub(r'[^a-z0-9]', '', company.lower())
    sfx   = ['','-data','-backup','-assets','-files','-public','-prod','-dev','-storage']

    # GCP
    gcp_hits = []
    info("Checking Google Cloud Storage...")
    for base in [slug, slug2]:
        for s in sfx:
            n = f"{base}{s}".strip('-')
            if len(n) < 3: continue
            url = f"https://storage.googleapis.com/{n}"
            try:
                r = SESSION.get(url, timeout=5)
                if r.status_code == 200:
                    found(f"GCP OPEN: {n}")
                    gcp_hits.append({'bucket': n, 'url': url, 'status': 'OPEN'})
                elif r.status_code == 403:
                    good(f"GCP private: {n}")
                    gcp_hits.append({'bucket': n, 'url': url, 'status': 'PRIVATE'})
            except Exception: pass

    if gcp_hits:
        open_gcp = [g for g in gcp_hits if g['status']=='OPEN']
        sev = 'CRITICAL' if open_gcp else 'MEDIUM'
        add_finding({
            **TASK_MAP['CLOUD-03'],
            "target": company, "status": "VULNERABLE" if open_gcp else "INFO",
            "severity": sev,
            "evidence": "\n".join([f"gs://{g['bucket']} [{g['status']}]" for g in gcp_hits]),
            "details": f"{len(open_gcp)} open GCP buckets, {len(gcp_hits)-len(open_gcp)} private.",
            "commands": [f"gsutil ls gs://{g['bucket']}" for g in open_gcp[:3]] or ["gsutil ls gs://BUCKET"],
            "remediation": "Set bucket IAM to remove allUsers/allAuthenticatedUsers. Enable audit logs.",
        })

    # Azure
    az_hits = []
    info("Checking Azure Blob Storage...")
    for base in [slug, slug2]:
        for s in sfx:
            n = re.sub(r'[^a-z0-9]', '', f"{base}{s}")
            if not 3 <= len(n) <= 24: continue
            url = f"https://{n}.blob.core.windows.net"
            try:
                r = SESSION.get(url, timeout=5)
                if r.status_code in [200, 400, 409, 403]:
                    # Try to list containers
                    r2 = SESSION.get(f"{url}?comp=list", timeout=5)
                    if r2.status_code == 200 and '<Container>' in r2.text:
                        found(f"Azure OPEN: {n}")
                        az_hits.append({'account': n, 'url': url, 'status': 'OPEN'})
                    else:
                        az_hits.append({'account': n, 'url': url, 'status': 'EXISTS'})
                        good(f"Azure account exists: {n}")
            except Exception: pass

    if az_hits:
        open_az = [a for a in az_hits if a['status']=='OPEN']
        sev = 'CRITICAL' if open_az else 'MEDIUM'
        add_finding({
            **TASK_MAP['CLOUD-04'],
            "target": company, "status": "VULNERABLE" if open_az else "INFO",
            "severity": sev,
            "evidence": "\n".join([f"{a['account']}.blob.core.windows.net [{a['status']}]" for a in az_hits]),
            "details": f"{len(open_az)} open Azure storage accounts, {len(az_hits)-len(open_az)} exist.",
            "commands": [f"az storage container list --account-name {a['account']}" for a in az_hits[:3]],
            "remediation": "Set container access level to Private. Disable anonymous blob access at account level.",
        })

# ════════════════════════════════════════════════════════════════════════════
# GOOGLE WORKSPACE
# ════════════════════════════════════════════════════════════════════════════
def run_gws_recon(domain):
    hdr("GWS-01/02/03 | Google Workspace Intelligence")

    # ── Confirm GWS via MX ──
    gws_confirmed = False
    mx_provider   = None
    try:
        if HAS_DNS:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            ans = resolver.resolve(domain, 'MX')
            for r in ans:
                mx = str(r.exchange).lower()
                if 'google' in mx or 'googlemail' in mx:
                    gws_confirmed = True
                    mx_provider = 'Google Workspace'
                    found(f"Google Workspace MX confirmed: {mx}")
                elif 'outlook' in mx or 'protection.outlook' in mx:
                    mx_provider = 'Microsoft 365'
                    good(f"Microsoft 365 MX confirmed: {mx}")
    except Exception as e:
        pass

    # ── SPF / DMARC already done in DNS-01 — check GWS-specific ──
    spf_google = False
    try:
        if HAS_DNS:
            resolver = dns.resolver.Resolver()
            ans = resolver.resolve(domain, 'TXT')
            for r in ans:
                txt = str(r).lower()
                if 'include:_spf.google.com' in txt or 'google' in txt:
                    spf_google = True
                    found(f"SPF confirms Google Workspace email routing")
    except Exception:
        pass

    # ── SAML / SSO probe ──
    saml_url = None
    try:
        r = SESSION.get(
            f"https://accounts.google.com/samlredirect?domain={domain}",
            timeout=8, allow_redirects=False)
        if r.status_code in [301, 302]:
            loc = r.headers.get('Location','')
            if 'google' in loc or 'saml' in loc.lower():
                saml_url = loc
                good(f"Google SAML SSO active for {domain}: {loc[:80]}")
    except Exception:
        pass

    # ── Check for publicly shared GWS docs ──
    exposed_dorks = [
        f'site:drive.google.com "{domain}"',
        f'site:docs.google.com "{domain}"',
        f'site:sheets.google.com "{domain}"',
        f'site:docs.google.com/spreadsheets "{domain}"',
        f'site:docs.google.com/forms "{domain}"',
    ]

    if gws_confirmed or spf_google:
        add_finding({
            **TASK_MAP['GWS-01'],
            "target":   domain,
            "status":   "CONFIRMED",
            "severity": "MEDIUM",
            "evidence": (
                f"MX provider: {mx_provider or 'Unknown'}\n"
                f"SPF Google routing: {spf_google}\n"
                f"SAML SSO: {saml_url or 'Not detected'}"
            ),
            "details":  (
                f"Organisation uses Google Workspace for email and collaboration.\n"
                f"All email, Drive, Docs, Calendar, and Meet data is hosted on Google infrastructure."
            ),
            "commands": [
                f"dig MX {domain} +short",
                f"dig TXT {domain} +short | grep -i google",
                f"curl -v 'https://accounts.google.com/samlredirect?domain={domain}'",
            ],
            "remediation": (
                "Review Google Workspace sharing settings.\n"
                "Set Drive sharing default to 'Restricted' (not public).\n"
                "Enable Google Workspace audit logs.\n"
                "Enforce 2FA via Google Workspace Admin."
            ),
        })

        add_finding({
            **TASK_MAP['GWS-02'],
            "target":   domain,
            "status":   "MANUAL_CHECK_REQUIRED",
            "severity": "HIGH",
            "evidence": "Google dorks to run manually:\n" + "\n".join(exposed_dorks),
            "details":  (
                "These dorks identify publicly shared Google Drive files, Docs, Sheets, and Forms.\n"
                "Run each dork in Google to find exposed internal documents."
            ),
            "commands": [
                f"https://www.google.com/search?q={quote(d)}" for d in exposed_dorks
            ],
            "remediation": (
                "Audit all Google Drive files shared with 'Anyone with the link'.\n"
                "Use Google Workspace DLP policies to detect sensitive content in Drive.\n"
                "Remove public sharing from all internal documents."
            ),
        })

# ════════════════════════════════════════════════════════════════════════════
# GITHUB RECON
# ════════════════════════════════════════════════════════════════════════════
def run_github_recon(company, domains, github_token=None):
    hdr("LEAK-01 | GitHub Secret & Credential Leak Detection")
    task = TASK_MAP['LEAK-01']

    headers = {'Accept': 'application/vnd.github.v3+json'}
    if github_token:
        headers['Authorization'] = f"token {github_token}"
        good("GitHub token provided — 5000 req/hr available")
    else:
        warn("No GitHub token — 10 req/min. Use --github-token for full scan")

    base = "https://api.github.com"
    all_leaks = []

    # ── Find org ──
    try:
        r = SESSION.get(
            f"{base}/search/users?q={quote(company)}+type:org&per_page=5",
            headers=headers, timeout=12)
        if r.status_code == 200:
            for item in r.json().get('items',[])[:3]:
                login = item['login']
                good(f"GitHub org: {login} — {item['html_url']}")
                # Check each repo for sensitive files
                _check_org_repos(login, headers, all_leaks)
        elif r.status_code == 403:
            warn("GitHub rate limit — add --github-token")
    except Exception as e:
        bad(f"GitHub org search: {e}")

    # ── Code search for secrets ──
    queries = []
    for d in domains[:2]:
        queries += [
            f'"{d}" password',
            f'"{d}" api_key OR secret_key',
            f'"{d}" aws_access_key',
            f'"{d}" DB_PASSWORD OR database_password',
        ]
    queries += [f'"{company}" private_key', f'"{company}" credentials']

    for q in queries[:6]:
        try:
            r = SESSION.get(
                f"{base}/search/code?q={quote(q)}&per_page=10",
                headers=headers, timeout=12)
            if r.status_code == 200:
                for item in r.json().get('items',[]):
                    repo  = item.get('repository',{})
                    fname = item.get('name','')
                    url   = item.get('html_url','')

                    # Fetch raw content and scan for secret patterns
                    raw_url = item.get('url','')
                    sev = 'HIGH'
                    found_patterns = []
                    if raw_url:
                        try:
                            rc = SESSION.get(raw_url, headers=headers, timeout=6)
                            if rc.status_code == 200:
                                # decode base64 content
                                import base64
                                content_b64 = rc.json().get('content','')
                                content     = base64.b64decode(content_b64).decode('utf-8','ignore')
                                for pat, name, pat_sev in GITHUB_SECRET_PATTERNS:
                                    if re.search(pat, content, re.I):
                                        found_patterns.append((name, pat_sev))
                                        if pat_sev == 'CRITICAL':
                                            sev = 'CRITICAL'
                        except Exception:
                            pass

                    if found_patterns:
                        sev = 'CRITICAL'
                        found(f"SECRET in {repo.get('full_name')}/{fname}: {[p[0] for p in found_patterns]}")
                    else:
                        good(f"Possible leak: {repo.get('full_name')}/{fname}")

                    all_leaks.append({
                        'repo':     repo.get('full_name',''),
                        'file':     fname,
                        'url':      url,
                        'query':    q,
                        'secrets':  found_patterns,
                        'severity': sev,
                    })
            time.sleep(1)  # GitHub rate limit
        except Exception as e:
            bad(f"GitHub code search: {e}")

    if all_leaks:
        ev = "\n".join([
            f"[{l['severity']}] {l['repo']}/{l['file']}\n"
            f"  URL: {l['url']}\n"
            f"  Secrets: {[s[0] for s in l['secrets']] or 'Manual review needed'}"
            for l in all_leaks
        ])
        top_sev = 'CRITICAL' if any(l['severity']=='CRITICAL' for l in all_leaks) else 'HIGH'
        add_finding({
            **task,
            "target":   company,
            "status":   "VULNERABLE",
            "severity": top_sev,
            "evidence": ev,
            "details":  f"{len(all_leaks)} potential GitHub leaks found. {len([l for l in all_leaks if l['severity']=='CRITICAL'])} confirmed CRITICAL.",
            "commands": [
                "trufflehog github --org=ORG_NAME",
                "gitleaks detect --source=REPO_PATH",
                f"github-search-tool --query '{company} api_key'",
            ],
            "remediation": (
                "Immediately rotate any exposed credentials.\n"
                "Use GitHub secret scanning alerts (Settings → Security).\n"
                "Implement pre-commit hooks with detect-secrets.\n"
                "Use HashiCorp Vault or AWS Secrets Manager for credentials."
            ),
            "leaks": all_leaks,
        })
    else:
        add_finding({
            **task,
            "target": company, "status": "NOT_FOUND", "severity": "INFO",
            "evidence": "No GitHub leaks detected in code search.",
            "details": "No credentials or secrets found in public GitHub repositories.",
            "commands": ["trufflehog github --org=ORG_NAME"],
            "remediation": "Enable GitHub secret scanning. Use detect-secrets in CI pipeline.",
        })

def _check_org_repos(org, headers, all_leaks):
    base = "https://api.github.com"
    try:
        r = SESSION.get(
            f"{base}/orgs/{org}/repos?per_page=30&sort=updated",
            headers=headers, timeout=10)
        if r.status_code != 200: return
        repos = r.json()
        info(f"  Checking {len(repos)} repos in {org}...")
        for repo in repos[:15]:
            repo_name = repo.get('name','')
            for fname in SENSITIVE_REPO_FILES[:8]:
                try:
                    rc = SESSION.get(
                        f"{base}/repos/{org}/{repo_name}/contents/{fname}",
                        headers=headers, timeout=5)
                    if rc.status_code == 200:
                        found(f"Sensitive file: {org}/{repo_name}/{fname}")
                        all_leaks.append({
                            'repo': f"{org}/{repo_name}",
                            'file': fname,
                            'url':  f"https://github.com/{org}/{repo_name}/blob/HEAD/{fname}",
                            'query': 'file_scan',
                            'secrets': [('Sensitive Config File', 'CRITICAL')],
                            'severity': 'CRITICAL',
                        })
                    time.sleep(0.2)
                except Exception:
                    pass
    except Exception as e:
        bad(f"Repo scan error: {e}")

# ════════════════════════════════════════════════════════════════════════════
# TECH + SECURITY HEADERS
# ════════════════════════════════════════════════════════════════════════════
def run_tech_fingerprint(domains):
    hdr("RECON-01/02 | Technology & Security Header Audit")

    for domain in domains[:3]:
        url = f"https://{domain}"
        info(f"Fingerprinting: {url}")
        try:
            r = SESSION.get(url, timeout=12)
            hdrs   = {k.lower(): v for k,v in r.headers.items()}
            body   = r.text.lower()
            cookies= {c.name.lower(): c.value for c in r.cookies}

            detected = []
            for tech, sigs in TECH_SIGNATURES.items():
                for sig_type, sig_key, sig_val in sigs:
                    matched = False
                    if sig_type == 'hdr':
                        v = hdrs.get(sig_key.lower(),'')
                        matched = sig_val.lower() in v or (sig_val == '' and sig_key.lower() in hdrs)
                    elif sig_type == 'body':
                        matched = sig_key.lower() in body
                    elif sig_type == 'cookie':
                        matched = sig_key.lower() in cookies
                    if matched:
                        detected.append(tech)
                        break

            for t in set(detected):
                good(f"  Tech: {t}")

            # Version leakage
            version_leaks = []
            for h in ['server','x-powered-by','x-generator','x-aspnet-version','x-aspnetmvc-version']:
                if h in hdrs:
                    version_leaks.append(f"{h}: {hdrs[h]}")
                    warn(f"  Version leak: {h}: {hdrs[h]}")

            add_finding({
                **TASK_MAP['RECON-01'],
                "target":   domain,
                "status":   "INFO",
                "severity": "MEDIUM" if version_leaks else "LOW",
                "evidence": f"Technologies: {', '.join(set(detected))}\n\nVersion disclosures:\n" + "\n".join(version_leaks),
                "details":  f"Detected {len(set(detected))} technologies. {len(version_leaks)} version leaks.",
                "commands": [f"whatweb {url}", f"wappalyzer {url}", f"curl -I {url}"],
                "remediation": "Remove Server, X-Powered-By headers. Update all components. Enable security.txt.",
            })

            # Security headers
            missing = []
            for hdr_name, desc in SECURITY_HEADERS:
                if hdr_name.lower() not in hdrs:
                    missing.append(f"{hdr_name} ({desc})")
                    warn(f"  Missing: {hdr_name}")
                else:
                    good(f"  Present: {hdr_name}: {hdrs[hdr_name.lower()][:60]}")

            if missing:
                add_finding({
                    **TASK_MAP['RECON-02'],
                    "target":   domain,
                    "status":   "VULNERABLE",
                    "severity": "MEDIUM",
                    "evidence": f"Missing headers on {url}:\n" + "\n".join(f"• {h}" for h in missing),
                    "details":  f"{len(missing)} security header(s) missing from HTTP responses.",
                    "commands": [f"curl -I {url}", f"securityheaders.com/?q={url}"],
                    "remediation": (
                        "Add to nginx.conf / web.config:\n"
                        "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                        "  Content-Security-Policy: default-src 'self'\n"
                        "  X-Frame-Options: DENY\n"
                        "  X-Content-Type-Options: nosniff"
                    ),
                })
        except Exception as e:
            bad(f"Fingerprint error for {domain}: {e}")

# ════════════════════════════════════════════════════════════════════════════
# WHOIS
# ════════════════════════════════════════════════════════════════════════════
def run_whois(domains):
    hdr("RECON-03 | WHOIS & Domain Registration Intel")
    for domain in domains[:3]:
        info(f"RDAP lookup: {domain}")
        for rdap_url in [f"https://rdap.org/domain/{domain}",
                         f"https://rdap.verisign.com/com/v1/domain/{domain}"]:
            try:
                r = SESSION.get(rdap_url, timeout=10)
                if r.status_code != 200: continue
                data = r.json()
                registrar  = ''
                registrant = ''
                created = expires = ''
                for entity in data.get('entities',[]):
                    roles  = entity.get('roles',[])
                    vcard  = entity.get('vcardArray',[None,[]])[1]
                    name   = next((v[3] for v in vcard if v[0]=='fn'),'') if vcard else ''
                    if 'registrar'  in roles: registrar  = name
                    if 'registrant' in roles: registrant = name
                for event in data.get('events',[]):
                    if event.get('eventAction') == 'registration':
                        created = event.get('eventDate','')[:10]
                    if event.get('eventAction') == 'expiration':
                        expires = event.get('eventDate','')[:10]
                ns = [n.get('ldhName','') for n in data.get('nameservers',[])]
                good(f"Registrar: {registrar} | Created: {created} | Expires: {expires}")
                good(f"Nameservers: {', '.join(ns)}")
                add_finding({
                    **TASK_MAP['RECON-03'],
                    "target":   domain,
                    "status":   "INFO",
                    "severity": "LOW",
                    "evidence": (
                        f"Domain: {domain}\n"
                        f"Registrar:  {registrar}\n"
                        f"Registrant: {registrant}\n"
                        f"Created:    {created}\n"
                        f"Expires:    {expires}\n"
                        f"Nameservers: {', '.join(ns)}\n"
                        f"Status: {', '.join(data.get('status',[]))}"
                    ),
                    "details":  f"Domain registered via {registrar}. DNS hosted on {', '.join(ns)}.",
                    "commands": [f"whois {domain}", f"curl https://rdap.org/domain/{domain}"],
                    "remediation": "Enable domain privacy protection. Lock domain to prevent transfer. Set up expiry alerts.",
                })
                break
            except Exception as e:
                bad(f"RDAP error: {e}")

# ════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE
# ════════════════════════════════════════════════════════════════════════════
def run_ssl_audit(domains):
    hdr("RECON-04 | SSL/TLS Certificate Analysis")
    for domain in domains[:3]:
        info(f"SSL audit: {domain}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            # Parse cert
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer  = dict(x[0] for x in cert.get('issuer',  []))
            not_after  = cert.get('notAfter','')
            not_before = cert.get('notBefore','')
            sans = [v for t,v in cert.get('subjectAltName',[]) if t=='DNS']

            # Check expiry
            if not_after:
                import email.utils
                exp_dt  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_dt - datetime.datetime.utcnow()).days
                if days_left < 30:
                    warn(f"SSL expires in {days_left} days!")
                else:
                    good(f"SSL valid for {days_left} days")
            else:
                days_left = 999

            good(f"Issuer: {issuer.get('organizationName','?')}")
            good(f"Cipher: {cipher[0]} / {cipher[1]} bits")
            good(f"SANs ({len(sans)}): {', '.join(sans[:6])}")

            sev = 'CRITICAL' if days_left < 7 else 'HIGH' if days_left < 30 else 'LOW'
            add_finding({
                **TASK_MAP['RECON-04'],
                "target":   domain,
                "status":   "WARNING" if sev != 'LOW' else "INFO",
                "severity": sev,
                "evidence": (
                    f"Subject: {subject.get('commonName','')}\n"
                    f"Issuer:  {issuer.get('organizationName','?')}\n"
                    f"Valid:   {not_before} → {not_after} ({days_left} days remaining)\n"
                    f"Cipher:  {cipher[0]} {cipher[1]} bits\n"
                    f"SANs ({len(sans)}): {', '.join(sans[:10])}"
                ),
                "details":  f"SSL cert expires in {days_left} days. Cipher: {cipher[0]}.",
                "commands": [
                    f"openssl s_client -connect {domain}:443 -showcerts",
                    f"sslyze {domain}",
                    f"testssl.sh {domain}",
                ],
                "remediation": (
                    "Automate certificate renewal with Let's Encrypt / ACM.\n"
                    "Disable TLS 1.0/1.1. Use TLS 1.2 minimum (1.3 preferred).\n"
                    "Enable HSTS preloading."
                ),
            })
        except ssl.SSLError as e:
            warn(f"SSL error on {domain}: {e}")
            add_finding({
                **TASK_MAP['RECON-04'],
                "target": domain, "status": "ERROR", "severity": "HIGH",
                "evidence": f"SSL error: {e}",
                "details": f"SSL connection failed: {e}",
                "commands": [f"openssl s_client -connect {domain}:443"],
                "remediation": "Fix SSL configuration. Check certificate validity.",
            })
        except Exception as e:
            bad(f"SSL check error for {domain}: {e}")

# ════════════════════════════════════════════════════════════════════════════
# GOOGLE DORKS
# ════════════════════════════════════════════════════════════════════════════
def run_google_dorks(company, domains):
    hdr("OSINT-02 | Google Dork Generation")
    task = TASK_MAP['OSINT-02']
    domain = domains[0] if domains else f"{re.sub(r'[^a-z0-9]','',company.lower())}.com"
    slug = quote(company)

    dork_sets = {
        "🔐 Credentials & Secrets": [
            f'site:{domain} ext:env OR ext:cfg OR ext:conf',
            f'site:{domain} intext:"DB_PASSWORD" OR intext:"DB_USER" OR intext:"API_KEY"',
            f'site:github.com "{company}" password OR secret OR api_key OR credentials',
            f'site:gitlab.com "{domain}" password OR secret',
            f'site:pastebin.com "{domain}" password OR dump OR credentials',
            f'"{domain}" filetype:env OR filetype:cfg OR filetype:config',
            f'site:trello.com "{company}" password',
            f'site:gist.github.com "{domain}" key OR secret OR password',
        ],
        "📄 Exposed Documents": [
            f'site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx',
            f'site:{domain} filetype:xlsx "confidential" OR "internal only"',
            f'site:{domain} filetype:pdf "invoice" OR "contract" OR "agreement"',
            f'site:{domain} intitle:"index of" OR intitle:"directory listing"',
            f'site:{domain} "not for public release" OR "internal use only"',
            f'"{company}" filetype:pptx site:slideshare.net',
            f'"{company}" site:scribd.com confidential OR internal',
        ],
        "☁ Cloud & Infrastructure": [
            f'site:s3.amazonaws.com "{company}"',
            f'site:blob.core.windows.net "{company}"',
            f'site:storage.googleapis.com "{company}"',
            f'site:{domain} inurl:admin OR inurl:dashboard OR inurl:panel',
            f'site:{domain} inurl:jenkins OR inurl:gitlab OR inurl:jira OR inurl:confluence',
            f'site:{domain} inurl:swagger OR inurl:api-docs OR inurl:graphql',
            f'site:{domain} inurl:phpmyadmin OR inurl:wp-admin',
            f'site:{domain} inurl:.git OR inurl:.svn',
        ],
        "👤 Employee & PII": [
            f'site:linkedin.com/in "{company}"',
            f'site:linkedin.com/in "{company}" engineer OR developer OR security',
            f'site:linkedin.com/in "{company}" CTO OR CISO OR CEO OR "Cloud"',
            f'intext:"@{domain}" site:github.com',
            f'"{domain}" site:hunter.io',
            f'"{company}" site:rocketreach.co',
            f'"{domain}" "email" site:pastebin.com',
        ],
        "🔍 Sensitive Admin Panels": [
            f'site:{domain} intext:"Powered by" inurl:admin',
            f'site:{domain} intitle:"Grafana" OR intitle:"Kibana" OR intitle:"Prometheus"',
            f'site:{domain} intitle:"phpMyAdmin" OR intitle:"Adminer"',
            f'site:{domain} intitle:"Login" inurl:admin',
            f'site:{domain} intitle:"Dashboard" inurl:internal',
        ],
        "💉 SQL / Error Messages": [
            f'site:{domain} intext:"SQL syntax" OR intext:"mysql_fetch" OR intext:"ORA-"',
            f'site:{domain} intext:"Warning: mysqli" OR intext:"Traceback"',
            f'site:{domain} intext:"Error: SQLSTATE" OR intext:"Uncaught Exception"',
        ],
        "📊 Leak Sites": [
            f'site:pastebin.com "{company}"',
            f'site:pastebin.com "{domain}"',
            f'site:ghostbin.com "{domain}"',
            f'site:gist.github.com "{domain}"',
            f'"{domain}" dump OR leak OR breach',
            f'"{company}" confidential filetype:pdf -site:{domain}',
        ],
        "🌐 Google Workspace": [
            f'site:drive.google.com "{domain}"',
            f'site:docs.google.com "{domain}"',
            f'site:docs.google.com/spreadsheets "{company}"',
            f'site:docs.google.com/forms "{company}"',
            f'site:calendar.google.com "{company}"',
        ],
    }

    all_dorks = []
    for cat, dorks in dork_sets.items():
        good(f"{cat}: {len(dorks)} dorks")
        for d in dorks:
            all_dorks.append({
                'category': cat,
                'dork': d,
                'url': f"https://www.google.com/search?q={quote(d)}",
            })

    add_finding({
        **task,
        "target":   domain,
        "status":   "MANUAL_CHECK_REQUIRED",
        "severity": "HIGH",
        "evidence": "\n".join([f"[{d['category']}]\n{d['dork']}\n→ {d['url']}\n" for d in all_dorks[:15]]),
        "details":  f"Generated {len(all_dorks)} Google dorks across {len(dork_sets)} categories. Run each manually.",
        "commands": [d['url'] for d in all_dorks[:10]],
        "remediation": (
            "Remove sensitive files from public web roots.\n"
            "Implement robots.txt to prevent indexing of sensitive paths.\n"
            "Use Google Search Console to find and remove cached sensitive pages.\n"
            "Implement proper access controls on all admin panels."
        ),
        "dorks": all_dorks,
    })
    info(f"Total dorks generated: {len(all_dorks)}")

# ════════════════════════════════════════════════════════════════════════════
# OSINT — EMPLOYEE ENUM + LINKEDIN
# ════════════════════════════════════════════════════════════════════════════
def run_employee_enum(company, domains):
    hdr("OSINT-01 | Employee & LinkedIn Enumeration")
    task  = TASK_MAP['OSINT-01']
    domain = domains[0] if domains else ''

    dorks = [
        f'site:linkedin.com/in "{company}"',
        f'site:linkedin.com/in "{company}" "Security Engineer"',
        f'site:linkedin.com/in "{company}" "DevOps" OR "Cloud" OR "Infrastructure"',
        f'site:linkedin.com/in "{company}" CISO OR CTO OR "VP Engineering"',
        f'site:xing.com "{company}"',
    ]

    # Email patterns
    email_formats = [
        f"first.last@{domain}",
        f"firstlast@{domain}",
        f"flast@{domain}",
        f"first@{domain}",
        f"last.first@{domain}",
        f"f.last@{domain}",
    ]

    # Try to harvest emails from company pages
    harvested = []
    if domain:
        for path in ['/contact','/team','/about','/about-us','/people','/leadership']:
            try:
                r = SESSION.get(f"https://{domain}{path}", timeout=8)
                emails = re.findall(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), r.text)
                for e in emails:
                    if e not in harvested:
                        harvested.append(e)
                        found(f"Email found: {e} (from {path})")
            except Exception:
                pass

    # Detect pattern from harvested
    detected_pattern = None
    if harvested:
        sample_user = harvested[0].split('@')[0]
        if '.' in sample_user:
            detected_pattern = f"first.last@{domain}"
        elif len(sample_user) <= 6:
            detected_pattern = f"f.last@{domain}"
        else:
            detected_pattern = f"firstlast@{domain}"
        found(f"Email pattern detected: {detected_pattern}")

    add_finding({
        **task,
        "target":   domain,
        "status":   "INFO",
        "severity": "MEDIUM",
        "evidence": (
            f"Harvested emails ({len(harvested)}): {', '.join(harvested[:10])}\n"
            f"Detected pattern: {detected_pattern or 'Unknown — run LinkedIn dorks manually'}\n\n"
            f"LinkedIn dorks:\n" + "\n".join(dorks) + "\n\n"
            f"Common email formats to try:\n" + "\n".join(email_formats)
        ),
        "details":  (
            f"Found {len(harvested)} real email addresses. "
            f"Use LinkedIn dorks to find employee names, then generate targeted email list."
        ),
        "commands": dorks + [
            f"theHarvester -d {domain} -l 200 -b google,linkedin",
            f"linkedin2username -c '{company}' -n 2",
            f"hunter.io/domain/{domain}",
        ],
        "remediation": (
            "Remove direct email addresses from public pages.\n"
            "Use contact forms instead of exposing email addresses.\n"
            "Implement anti-phishing training for employees.\n"
            "Enable Microsoft Defender for Identity or Google Workspace alerts."
        ),
    })

# ════════════════════════════════════════════════════════════════════════════
# SHODAN DORKS
# ════════════════════════════════════════════════════════════════════════════
def run_shodan_recon(company, domains, shodan_key=None):
    hdr("OSINT-03 | Internet Exposure — Shodan Attack Surface")
    task = TASK_MAP['OSINT-03']

    if not shodan_key:
        warn("No Shodan API key — generating search links. Use --shodan-key for live data")
        shodan_searches = []
        for domain in domains[:3]:
            shodan_searches += [
                f"https://www.shodan.io/search?query=hostname%3A{domain}",
                f"https://www.shodan.io/search?query=ssl%3A{domain}",
            ]
        shodan_searches += [
            f"https://www.shodan.io/search?query=org%3A%22{quote(company)}%22",
            f"https://search.censys.io/search?resource=hosts&q={quote(domain)}",
        ]
        add_finding({
            **task,
            "target": company, "status": "MANUAL_CHECK_REQUIRED",
            "severity": "MEDIUM",
            "evidence": "Shodan search URLs (run manually):\n" + "\n".join(shodan_searches),
            "details": "No Shodan API key provided. Run searches manually to identify exposed services.",
            "commands": shodan_searches,
            "remediation": "Close all unnecessary exposed services. Use firewall rules. Enable VPN for admin access.",
        })
        return

    # With Shodan key
    hits = []
    for domain in domains[:3]:
        try:
            r = SESSION.get(
                f"https://api.shodan.io/shodan/host/search"
                f"?key={shodan_key}&query=hostname:{domain}&facets=port,product",
                timeout=12)
            if r.status_code == 200:
                data = r.json()
                for match in data.get('matches',[]):
                    ip    = match.get('ip_str','')
                    port  = match.get('port','')
                    prod  = match.get('product','')
                    vulns = list(match.get('vulns',{}).keys())
                    found(f"Shodan: {ip}:{port} {prod} {vulns}")
                    hits.append({'ip':ip,'port':port,'product':prod,'vulns':vulns,'domain':domain})
        except Exception as e:
            bad(f"Shodan API error: {e}")

    if hits:
        cve_count = sum(len(h['vulns']) for h in hits)
        ev = "\n".join([f"{h['ip']}:{h['port']} {h['product']} — CVEs: {h['vulns'] or 'None'}" for h in hits[:20]])
        add_finding({
            **task,
            "target": company, "status": "VULNERABLE" if cve_count else "INFO",
            "severity": "HIGH" if cve_count else "MEDIUM",
            "evidence": f"Total exposed services: {len(hits)}\nCVEs found: {cve_count}\n\n{ev}",
            "details": f"{len(hits)} internet-exposed services, {cve_count} known CVEs.",
            "commands": [f"shodan host {h['ip']}" for h in hits[:3]],
            "remediation": "Patch all CVEs immediately. Close unnecessary ports. Use WAF and DDoS protection.",
            "hits": hits,
        })

# ════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ════════════════════════════════════════════════════════════════════════════
def generate_report(company, domain, output_dir='.'):
    hdr("GENERATING REPORTS")
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = re.sub(r'[^a-z0-9]','_', company.lower())
    base = os.path.join(output_dir, f"redrecon_{safe}_{ts}")

    sorted_findings = sorted(
        FINDINGS,
        key=lambda f: SEVERITY_ORDER.get(f.get('severity','INFO'), 99)
    )

    # Counts
    counts = {}
    for f in sorted_findings:
        s = f.get('severity','INFO')
        counts[s] = counts.get(s, 0) + 1

    # ── JSON ──
    json_path = base + '.json'
    with open(json_path,'w') as f:
        json.dump({
            "meta": {
                "company": company,
                "domain":  domain,
                "generated": datetime.datetime.now().isoformat(),
                "tool": "RedRecon v1.0",
                "summary": counts,
                "total_findings": len(sorted_findings),
            },
            "findings": sorted_findings,
        }, f, indent=2, default=str)
    good(f"JSON: {json_path}")

    # ── CSV (task sheet format) ──
    csv_path = base + '_tasksheet.csv'
    import csv
    with open(csv_path,'w',newline='') as f:
        w = csv.writer(f)
        w.writerow(['ID','Category','Name','Tactic','Risk Type','CVSS',
                    'Priority','Severity','Status','Target','Details',
                    'Evidence (snippet)','Commands','Remediation'])
        for finding in sorted_findings:
            w.writerow([
                finding.get('id',''),
                finding.get('category',''),
                finding.get('name',''),
                finding.get('tactic',''),
                finding.get('risk_type',''),
                finding.get('cvss',''),
                finding.get('priority',''),
                finding.get('severity',''),
                finding.get('status',''),
                finding.get('target',''),
                finding.get('details','')[:300],
                finding.get('evidence','')[:300],
                '\n'.join(finding.get('commands',[])[:3]),
                finding.get('remediation','')[:300],
            ])
    good(f"CSV: {csv_path}")

    # ── HTML ──
    html_path = base + '.html'
    _write_html(html_path, company, domain, sorted_findings, counts)
    good(f"HTML: {html_path}")

    return json_path, csv_path, html_path

def _sev_color(sev):
    return {'CRITICAL':'#ff0055','HIGH':'#ff4560','MEDIUM':'#ffd060',
            'LOW':'#38bdf8','INFO':'#4a6070'}.get(sev,'#4a6070')

def _write_html(path, company, domain, findings, counts):
    sev_order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']

    cards = ""
    for sev in sev_order:
        n = counts.get(sev,0)
        c = _sev_color(sev)
        cards += f'<div class="stat"><div class="num" style="color:{c}">{n}</div><div class="lbl">{sev}</div></div>'

    rows = ""
    for i, f in enumerate(findings):
        sev  = f.get('severity','INFO')
        sc   = _sev_color(sev)
        cmds = "\n".join(f.get('commands',[])[:5])
        ev   = f.get('evidence','')[:600]
        rows += f"""
        <tr class="finding-row" onclick="toggle({i})">
          <td><span style="color:{sc};font-weight:bold">{sev}</span></td>
          <td>{f.get('id','')}</td>
          <td>{f.get('category','')}</td>
          <td>{f.get('name','')}</td>
          <td>{f.get('target','')}</td>
          <td>{f.get('status','')}</td>
          <td>{f.get('tactic','')}</td>
          <td>{f.get('cvss','')}</td>
          <td>{f.get('priority','')}</td>
        </tr>
        <tr id="detail-{i}" class="detail-row" style="display:none">
          <td colspan="9">
            <div class="detail-grid">
              <div>
                <div class="dlabel">DETAILS</div>
                <pre class="pre">{f.get('details','')}</pre>
                <div class="dlabel" style="margin-top:12px">REMEDIATION</div>
                <pre class="pre" style="color:#00ff88">{f.get('remediation','')}</pre>
              </div>
              <div>
                <div class="dlabel">EVIDENCE</div>
                <pre class="pre">{ev}</pre>
                <div class="dlabel" style="margin-top:12px">COMMANDS</div>
                <pre class="pre" style="color:#38bdf8">{cmds}</pre>
              </div>
            </div>
          </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>RedRecon — {company}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:'Courier New',monospace;background:#0a0c0f;color:#c8d8e8;padding:24px;}}
  h1{{color:#ff4560;font-size:26px;margin-bottom:4px;}}
  .meta{{color:#4a6070;font-size:12px;margin-bottom:20px;}}
  .warn{{background:rgba(255,69,96,.08);border:1px solid rgba(255,69,96,.3);border-radius:4px;
         padding:10px 16px;color:#ff4560;margin-bottom:20px;font-size:13px;}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:24px;}}
  .stat{{background:#0f1318;border:1px solid #1e2a38;border-radius:4px;padding:14px;text-align:center;}}
  .num{{font-size:36px;font-weight:bold;line-height:1;}}
  .lbl{{font-size:10px;color:#4a6070;letter-spacing:2px;margin-top:4px;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:24px;}}
  th{{background:#151b24;color:#38bdf8;padding:10px 8px;text-align:left;
      border-bottom:1px solid #1e2a38;white-space:nowrap;}}
  .finding-row{{cursor:pointer;}}
  .finding-row td{{padding:8px;border-bottom:1px solid #0f1318;}}
  .finding-row:hover td{{background:#151b24;}}
  .detail-row td{{padding:0;}}
  .detail-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;
                padding:16px;background:#0a0c0f;}}
  .dlabel{{font-size:10px;color:#4a6070;letter-spacing:2px;margin-bottom:6px;}}
  .pre{{background:#0f1318;border:1px solid #1e2a38;border-radius:3px;
        padding:10px;font-size:11px;line-height:1.7;white-space:pre-wrap;
        word-break:break-all;max-height:220px;overflow-y:auto;}}
  .filter-row{{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;}}
  .fbtn{{background:transparent;border:1px solid #1e2a38;color:#4a6070;
         font-family:'Courier New',monospace;font-size:11px;padding:5px 14px;
         border-radius:3px;cursor:pointer;transition:all .15s;}}
  .fbtn:hover,.fbtn.active{{border-color:#ff4560;color:#ff4560;}}
</style>
</head><body>
<h1>🎯 RedRecon — Red Team Report</h1>
<div class="meta">Company: <b style="color:#fff">{company}</b> | Domain: <b style="color:#fff">{domain}</b> | Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} | Tool: RedRecon v1.0</div>
<div class="warn">⚠ CONFIDENTIAL — FOR AUTHORISED RED TEAM USE ONLY. Do not distribute.</div>
<div class="stats">{cards}</div>
<div class="filter-row">
  <button class="fbtn active" onclick="filterSev('ALL')">ALL</button>
  <button class="fbtn" onclick="filterSev('CRITICAL')" style="border-color:#ff0055;color:#ff0055">CRITICAL</button>
  <button class="fbtn" onclick="filterSev('HIGH')"     style="border-color:#ff4560;color:#ff4560">HIGH</button>
  <button class="fbtn" onclick="filterSev('MEDIUM')"   style="border-color:#ffd060;color:#ffd060">MEDIUM</button>
  <button class="fbtn" onclick="filterSev('LOW')"      style="border-color:#38bdf8;color:#38bdf8">LOW</button>
  <button class="fbtn" onclick="filterSev('INFO')">INFO</button>
</div>
<table id="findingsTable">
<thead><tr>
  <th>SEVERITY</th><th>ID</th><th>CATEGORY</th><th>NAME</th>
  <th>TARGET</th><th>STATUS</th><th>TACTIC</th><th>CVSS</th><th>PRIORITY</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<script>
function toggle(i){{
  const d=document.getElementById('detail-'+i);
  d.style.display=d.style.display==='none'?'table-row':'none';
}}
function filterSev(sev){{
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-row').forEach((row,i)=>{{
    const rowSev=row.cells[0].textContent.trim();
    const show=sev==='ALL'||rowSev===sev;
    row.style.display=show?'':'none';
    const det=document.getElementById('detail-'+i);
    if(det&&!show) det.style.display='none';
  }});
}}
</script>
</body></html>"""
    with open(path,'w') as f:
        f.write(html)

# ════════════════════════════════════════════════════════════════════════════
# DOMAIN DISCOVERY
# ════════════════════════════════════════════════════════════════════════════
def discover_domains(company):
    hdr("DOMAIN DISCOVERY")
    slug  = re.sub(r'[^a-z0-9]', '',  company.lower())
    slug2 = re.sub(r'\s+', '-', company.lower().strip())
    slug2 = re.sub(r'[^a-z0-9\-]', '', slug2).strip('-')

    tlds = ['com','io','co','net','org','ai','app','dev','tech',
            'co.in','in','us','co.uk','biz','cloud','xyz']
    candidates = set()
    for tld in tlds:
        for base in [slug, slug2]:
            if base:
                candidates.update([
                    f"{base}.{tld}", f"{base}hq.{tld}",
                    f"get{base}.{tld}", f"{base}app.{tld}",
                ])

    live = []
    info(f"Testing {len(candidates)} domain candidates...")

    def check(d):
        try:
            ip = socket.gethostbyname(d)
            return (d, ip)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for r in as_completed({ex.submit(check, d): d for d in candidates}):
            res = r.result()
            if res:
                d, ip = res
                good(f"Domain alive: {d} → {ip}")
                live.append(d)

    return live

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════
def check_deps():
    missing = []
    if not HAS_REQ: missing.append('requests')
    if not HAS_DNS: missing.append('dnspython')
    if not HAS_BS4: missing.append('beautifulsoup4')
    if missing:
        warn(f"Missing packages (some features limited): pip install {' '.join(missing)}")
    return missing

def main():
    global SESSION
    parser = argparse.ArgumentParser(
        description='RedRecon — Automated Red Team Recon Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Black box — company name only
  python redrecon.py -c "Edtech India"

  # With known domain
  python redrecon.py -c "Edtech India" -d edtechindia.com

  # Full scan with API keys
  python redrecon.py -c "Edtech India" -d edtechindia.com \\
    --github-token ghp_xxx --shodan-key xxx

  # Run specific modules only
  python redrecon.py -c "Edtech India" -d edtechindia.com \\
    --modules dns,subdomains,takeover,aws,github

  # Available modules:
  # dns, subdomains, takeover, axfr, aws, gcp, gws,
  # github, tech, whois, ssl, dorks, employees, shodan

⚠  FOR AUTHORIZED PENETRATION TESTING ONLY
        """
    )
    parser.add_argument('-c','--company',      required=True, help='Company / organisation name')
    parser.add_argument('-d','--domain',       help='Target domain (skips discovery if provided)')
    parser.add_argument('-o','--output',       default='.',   help='Output directory')
    parser.add_argument('--github-token',      help='GitHub PAT (higher rate limits + code search)')
    parser.add_argument('--shodan-key',        help='Shodan API key')
    parser.add_argument('--hibp-key',          help='HaveIBeenPwned API key')
    parser.add_argument('--threads',           type=int, default=40, help='Thread count (default: 40)')
    parser.add_argument('--timeout',           type=int, default=10, help='HTTP timeout seconds')
    parser.add_argument('--modules',           default='all',
        help='Comma-separated modules: dns,subdomains,takeover,axfr,aws,gcp,gws,github,tech,whois,ssl,dorks,employees,shodan')
    args = parser.parse_args()

    banner()
    check_deps()

    SESSION = make_session(args.timeout)
    company = args.company
    mods    = set(args.modules.lower().split(','))
    run_all = 'all' in mods

    info(f"Company  : {C.BOLD}{company}{C.RST}")
    info(f"Domain   : {args.domain or 'auto-discover'}")
    info(f"Modules  : {args.modules}")
    info(f"Threads  : {args.threads}")
    info(f"Output   : {args.output}")
    print()

    os.makedirs(args.output, exist_ok=True)
    t0 = time.time()

    # ── Domains ──
    if args.domain:
        domains = [args.domain]
        try:
            ip = socket.gethostbyname(args.domain)
            good(f"Domain: {args.domain} → {ip}")
        except Exception:
            warn(f"Could not resolve {args.domain} — continuing anyway")
    else:
        domains = discover_domains(company)
        if not domains:
            slug = re.sub(r'[^a-z0-9]','',company.lower())
            domains = [f"{slug}.com"]
            warn(f"No live domains found — using {domains[0]}")

    primary = domains[0]

    # ── Module execution ──
    if run_all or 'dns'        in mods: run_dns_audit(primary)
    if run_all or 'axfr'       in mods: run_zone_transfer(primary)
    if run_all or 'whois'      in mods: run_whois(domains)
    if run_all or 'ssl'        in mods: run_ssl_audit(domains)

    subdomains = []
    if run_all or 'subdomains' in mods:
        subdomains = run_subdomain_enum(primary, threads=args.threads)

    if run_all or 'takeover'   in mods:
        run_takeover_check(subdomains, primary)

    if run_all or 'aws'        in mods: run_s3_enum(company, domains, threads=args.threads)
    if run_all or 'gcp'        in mods: run_cloud_storage(company)
    if run_all or 'gws'        in mods: run_gws_recon(primary)
    if run_all or 'github'     in mods: run_github_recon(company, domains, args.github_token)
    if run_all or 'tech'       in mods: run_tech_fingerprint(domains)
    if run_all or 'dorks'      in mods: run_google_dorks(company, domains)
    if run_all or 'employees'  in mods: run_employee_enum(company, domains)
    if run_all or 'shodan'     in mods: run_shodan_recon(company, domains, args.shodan_key)

    # ── Summary ──
    counts = {}
    for f in FINDINGS:
        s = f.get('severity','INFO')
        counts[s] = counts.get(s,0)+1

    elapsed = time.time() - t0
    hdr(f"SCAN COMPLETE in {elapsed:.1f}s — {len(FINDINGS)} findings")
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
        n = counts.get(sev,0)
        if n:
            clr = {
                'CRITICAL':C.R,'HIGH':C.R,'MEDIUM':C.Y,
                'LOW':C.B,'INFO':C.C
            }.get(sev,C.C)
            print(f"  {clr}[{sev:<8}] {n} finding(s){C.RST}")

    # ── Reports ──
    json_p, csv_p, html_p = generate_report(company, primary, args.output)
    print(f"""
  {C.BOLD}Reports:{C.RST}
  {C.G}→ {html_p}  (open in browser){C.RST}
  {C.G}→ {csv_p}   (import into spreadsheet/task tracker){C.RST}
  {C.G}→ {json_p}{C.RST}
""")

if __name__ == '__main__':
    main()
