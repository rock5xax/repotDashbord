const categories = [
  {
    id: "recon",
    label: "Reconnaissance",
    icon: "\uD83D\uDD0D",
    color: "#00d4ff",
    items: [
      {
        id: "r1", text: "Passive DNS enumeration & subdomain discovery",
        details: {
          overview: "Passive DNS enumeration involves collecting DNS records and subdomains without directly querying the target's DNS server. Exposed subdomains can reveal staging, admin, dev, or internal systems attackers can target.",
          steps: ["Use tools: amass, subfinder, assetfinder, dnsx", "Query Certificate Transparency logs via crt.sh", "Use Shodan/Censys for reverse DNS lookups", "Check VirusTotal passive DNS for historical records", "Brute-force subdomains with wordlists (gobuster dns, ffuf)"],
          remediation: "Regularly audit publicly exposed subdomains. Remove or restrict access to dev/staging/admin subdomains. Implement split-horizon DNS. Audit CT logs and use CAA records.",
          why: "Subdomains often expose forgotten or poorly secured assets. Attackers map the attack surface before exploiting it. Finding these first lets defenders reduce exposure."
        }
      },
      {
        id: "r2", text: "WHOIS & IP range identification",
        details: {
          overview: "WHOIS and IP range data reveals organizational structure, registered domains, ASN (Autonomous System Numbers), and IP blocks owned by the target. This helps attackers identify all assets in scope.",
          steps: ["Run whois on primary domain", "Identify ASN using tools like bgp.he.net or ipinfo.io", "Enumerate IP ranges using ARIN/RIPE/APNIC", "Use Shodan with 'org:' filter for the ASN", "Cross-reference with Censys for exposed services"],
          remediation: "Minimize sensitive data in WHOIS records. Use privacy protection services. Monitor for unauthorized IP block registrations.",
          why: "Attackers use IP ranges to find shadow IT, forgotten servers, and unmanaged assets. Pentesters map the full scope to avoid missing vulnerable targets."
        }
      },
      {
        id: "r3", text: "Google dorking / OSINT gathering",
        details: {
          overview: "Google dorks use advanced search operators to find sensitive data indexed by search engines - exposed login pages, configuration files, database dumps, credentials, and internal documents.",
          steps: ["Use site:target.com filetype:pdf/xls/sql", "Search for site:target.com inurl:admin/login/dashboard", "Look for site:target.com ext:env OR ext:log OR ext:bak", "Use intitle:'index of' site:target.com for directory listings", "Search GitHub/GitLab for target domain leaks (github.com/search)"],
          remediation: "Implement robots.txt properly. Remove sensitive files from public web roots. Use Google Search Console to request removal of indexed sensitive pages. Conduct regular dorking audits.",
          why: "Google has already crawled and indexed the target. This is free, passive, and zero-risk reconnaissance. Sensitive data found here requires no hacking - just knowing what to search."
        }
      },
      {
        id: "r4", text: "Email harvesting (theHarvester, Hunter.io)",
        details: {
          overview: "Email addresses leak employee names, naming conventions, and internal structure. They are primary vectors for phishing, credential stuffing, and social engineering attacks.",
          steps: ["Run: theHarvester -d target.com -l 500 -b all", "Use Hunter.io and RocketReach for email patterns", "Search LinkedIn for employees and derive email format", "Check HaveIBeenPwned for breached email accounts", "Cross-reference found emails with credential dump databases"],
          remediation: "Train employees on phishing awareness. Use email security gateways (DMARC, DKIM, SPF). Monitor for corporate email addresses in breach databases.",
          why: "Email addresses are the starting point for social engineering and phishing campaigns. Knowing the email format allows targeted spear-phishing with high success rates."
        }
      },
      {
        id: "r5", text: "Technology fingerprinting (Wappalyzer, BuiltWith)",
        details: {
          overview: "Identifying the technology stack (CMS, frameworks, server software, CDN, analytics) reveals specific CVEs applicable to the target without any active scanning.",
          steps: ["Run Wappalyzer browser extension on all target URLs", "Use whatweb CLI tool: whatweb -v target.com", "Analyze HTTP response headers (X-Powered-By, Server)", "Check HTML source for framework-specific patterns", "Use BuiltWith.com for historical technology changes"],
          remediation: "Remove or obfuscate version numbers from HTTP headers. Suppress X-Powered-By headers. Keep all software updated. Use WAF to hide technology signatures.",
          why: "Knowing the exact software versions lets attackers look up known CVEs immediately. A single outdated plugin or framework version can be the entry point for full compromise."
        }
      },
      {
        id: "r6", text: "Shodan / Censys scan for exposed assets",
        details: {
          overview: "Shodan and Censys continuously scan the entire internet and index all exposed services. They reveal open ports, service banners, SSL cert metadata, and misconfigurations accessible from the internet.",
          steps: ["Search Shodan: org:'Target Company' or hostname:target.com", "Filter by port: port:22,3389,5900 org:target", "Use Censys.io for certificate-based discovery", "Check for exposed databases: port:27017,5432,3306", "Look for industrial systems, cameras, printers on target IP ranges"],
          remediation: "Restrict internet-facing services to only what is necessary. Use firewall rules to block unauthorized port access. Remove default banners. Regularly audit internet exposure.",
          why: "Attackers use Shodan before touching the target. Services visible on Shodan are trivially discoverable. Defenders must know their internet footprint before attackers do."
        }
      },
      {
        id: "r7", text: "Social engineering surface mapping",
        details: {
          overview: "Mapping social engineering attack surfaces identifies employees, roles, communication platforms, and personal information that could be used to craft convincing pretexting scenarios.",
          steps: ["Enumerate LinkedIn employees by company", "Check company social media for physical security clues", "Review job postings for technology stack details", "Identify key executives (CEO, CFO, IT staff) for BEC targeting", "Search for employee personal social profiles that cross-reference work"],
          remediation: "Train employees on social engineering tactics. Establish verification procedures for sensitive requests. Implement DMARC to prevent email spoofing. Create a security awareness program.",
          why: "Humans are consistently the weakest link in security. Social engineering bypasses technical controls entirely. Mapping the surface helps organizations prepare targeted awareness training."
        }
      },
      {
        id: "r8", text: "Job postings & GitHub leak analysis",
        details: {
          overview: "Job postings reveal exact technology stacks, internal tools, and security maturity. GitHub repositories may contain hardcoded credentials, internal API endpoints, infrastructure configs, and source code.",
          steps: ["Review all current and archived job postings on LinkedIn/Indeed", "Search GitHub: github.com/search?q=target.com+password", "Use truffleHog or gitleaks on discovered repositories", "Search for org name in commit messages across public repos", "Look for .env files, AWS keys, database connection strings in repos"],
          remediation: "Implement pre-commit hooks to scan for secrets (gitleaks, detect-secrets). Rotate any exposed credentials immediately. Set GitHub org policies to prevent accidental public repos.",
          why: "Developers accidentally commit credentials constantly. Job postings are intentional public disclosure of internal tooling. Both provide high-value intelligence with zero risk of detection."
        }
      },
    ],
  },
  {
    id: "network",
    label: "Network & Infrastructure",
    icon: "\uD83C\uDF10",
    color: "#ff6b35",
    items: [
      {
        id: "n1", text: "Full TCP/UDP port scan (Nmap)",
        details: {
          overview: "A comprehensive port scan identifies all open services on target hosts. Unintended open ports represent unnecessary attack surface - each open service is a potential entry point.",
          steps: ["TCP full scan: nmap -sS -p- -T4 --min-rate 1000 target", "UDP top ports: nmap -sU --top-ports 200 target", "Service detection: nmap -sV -sC -O target", "Script scan: nmap --script=default,vuln target", "Save output: nmap -oA scan_results target"],
          remediation: "Close all unnecessary ports with firewall rules. Follow principle of least exposure - only expose what is required. Conduct regular port audits. Implement network access control.",
          why: "Unknown open ports mean unknown attack surface. Organizations frequently forget services running on non-standard ports. Every open port is a potential vulnerability waiting to be discovered."
        }
      },
      {
        id: "n2", text: "Service version detection & OS fingerprinting",
        details: {
          overview: "Identifying exact service versions and OS allows direct CVE lookup. Running outdated software with known exploits is one of the most common causes of breach.",
          steps: ["Run: nmap -sV --version-intensity 9 target", "Banner grabbing: nc -v target 80/22/443", "Use Metasploit auxiliary/scanner/portscan modules", "Check banners against CVE databases (NIST NVD)", "Use searchsploit for local exploit-db search by version"],
          remediation: "Implement a patch management program. Suppress version banners in service configurations. Use a vulnerability management platform (Tenable, Qualys). Establish SLA for critical patch deployment.",
          why: "Knowing exact versions enables precise exploitation with public PoC exploits. Most breaches exploit known vulnerabilities for which patches already exist - version detection confirms exposure."
        }
      },
      {
        id: "n3", text: "Firewall / IDS / IPS evasion testing",
        details: {
          overview: "Testing whether security controls can be evaded validates their effectiveness. A firewall that can be bypassed provides false security confidence.",
          steps: ["Fragment packets: nmap -f or --mtu 8", "Use decoy scans: nmap -D RND:10 target", "Test timing: nmap -T0 (paranoid) for IDS evasion", "Try firewall rules from different source ports: nmap --source-port 53", "Test with Hping3 for custom packet crafting"],
          remediation: "Tune IDS/IPS signatures regularly. Implement stateful packet inspection. Use deep packet inspection (DPI). Test controls regularly with red team exercises.",
          why: "A firewall that can be trivially bypassed provides no real protection. Organizations must validate their security controls actually work against realistic attack techniques."
        }
      },
      {
        id: "n4", text: "Network segmentation verification",
        details: {
          overview: "Proper network segmentation limits an attacker's ability to move laterally after initial compromise. Flat networks allow access to all systems from any compromised host.",
          steps: ["Map VLANs and subnets from initial access point", "Attempt cross-segment connections to sensitive VLANs", "Test if DMZ hosts can reach internal network", "Check if workstation VLANs can reach server VLANs directly", "Verify database servers are not reachable from user VLANs"],
          remediation: "Implement proper VLAN segmentation with firewall rules between segments. Place sensitive systems (databases, AD) in isolated segments. Use micro-segmentation solutions. Enforce zero-trust network access.",
          why: "Segmentation is the primary defense against lateral movement. Verifying it works prevents a single compromised workstation from becoming full network access."
        }
      },
      {
        id: "n5", text: "VLAN hopping test",
        details: {
          overview: "VLAN hopping allows an attacker to send traffic to VLANs that should be inaccessible. Switch spoofing and double-tagging are the two main techniques.",
          steps: ["Test switch spoofing: configure trunk port with yersinia", "Attempt double-tagging with native VLAN misconfiguration", "Use Yersinia: yersinia -G for graphical interface", "Test with scapy to craft double-tagged 802.1Q frames", "Verify DTP (Dynamic Trunking Protocol) is disabled on access ports"],
          remediation: "Disable DTP on all access ports (switchport nonegotiate). Set native VLAN to an unused VLAN ID. Enable VLAN access control lists (VACLs). Use private VLANs where appropriate.",
          why: "VLAN hopping can completely bypass network segmentation controls. Misconfigured switches are common in enterprise networks. It directly negates the security value of VLAN isolation."
        }
      },
      {
        id: "n6", text: "Default credentials on routers/switches",
        details: {
          overview: "Network devices shipped with default credentials (admin/admin, cisco/cisco) are frequently deployed without credential changes, providing immediate administrative access to the entire network.",
          steps: ["Use Hydra or Medusa against management interfaces", "Try common defaults: admin/admin, admin/password, cisco/cisco", "Check SNMP v1/v2 with community strings 'public' and 'private'", "Test web management GUIs on port 80/443/8080", "Try SSH/Telnet with vendor-specific defaults from documentation"],
          remediation: "Change all default credentials during device provisioning. Implement a credential management system. Disable Telnet and use SSHv2 only. Enable network device management VLAN isolation.",
          why: "Default credentials are the lowest-effort, highest-impact vulnerability. Compromising a core router or switch gives full network visibility and control - the highest privilege possible."
        }
      },
      {
        id: "n7", text: "SNMP community string enumeration",
        details: {
          overview: "SNMP v1/v2c uses plaintext community strings for authentication. The default 'public' read string and 'private' write string are widely deployed and allow full device configuration access.",
          steps: ["Scan for SNMP: nmap -sU -p 161 --script snmp-brute target", "Enumerate with default strings: snmpwalk -v2c -c public target", "Use onesixtyone for community string brute-forcing", "Extract system info: snmpget -v1 -c public target sysDescr.0", "Test SNMP write access with 'private' community string"],
          remediation: "Upgrade to SNMPv3 with authentication and encryption. Disable SNMP v1/v2c entirely if possible. Use non-default community strings. Restrict SNMP access via ACLs to management hosts only.",
          why: "SNMPv1/v2 gives unauthenticated read/write access to device configurations. 'public' community strings are present by default in millions of devices and are routinely exploited."
        }
      },
      {
        id: "n8", text: "SMB / NetBIOS enumeration",
        details: {
          overview: "SMB and NetBIOS expose Windows network resources, user accounts, shares, and system information. Misconfigurations enable unauthenticated access to files and enable attacks like EternalBlue.",
          steps: ["Enumerate shares: smbclient -L //target -N", "Use enum4linux: enum4linux -a target", "Null session test: rpcclient -U '' -N target", "Check for EternalBlue: nmap --script smb-vuln-ms17-010", "Use CrackMapExec: cme smb target -u '' -p '' --shares"],
          remediation: "Disable SMBv1 everywhere. Block port 445/139 at network perimeter. Require SMB signing. Disable null sessions. Apply MS17-010 patch. Use modern Windows authentication protocols.",
          why: "SMB is one of the most exploited protocols in history (WannaCry, NotPetya). Null session enumeration provides free intelligence about users and shares. SMBv1 exploits are still weaponized."
        }
      },
      {
        id: "n9", text: "DNS zone transfer attempt",
        details: {
          overview: "DNS zone transfers (AXFR) are designed for replication between DNS servers. If misconfigured, any host can request the entire DNS zone, revealing all internal hostnames and IP addresses.",
          steps: ["Test AXFR: dig axfr @nameserver target.com", "Try with nslookup: nslookup -type=any target.com nameserver", "Use host: host -l target.com nameserver", "Test all discovered nameservers for zone transfer", "Use DNSRecon: dnsrecon -d target.com -t axfr"],
          remediation: "Restrict zone transfers to authorized secondary DNS servers only by IP ACL. Configure TSIG authentication for zone transfers. Regularly audit DNS server configurations.",
          why: "A successful zone transfer instantly reveals the entire internal network map - every hostname and IP. This eliminates hours of reconnaissance and exposes hidden/internal systems."
        }
      },
      {
        id: "n10", text: "SSL/TLS configuration audit (SSLyze, testssl.sh)",
        details: {
          overview: "Weak SSL/TLS configurations including outdated protocols (SSLv3, TLS 1.0), weak ciphers, and certificate issues allow man-in-the-middle attacks, decryption of traffic, and BEAST/POODLE/DROWN attacks.",
          steps: ["Run testssl.sh: testssl.sh --full target.com", "Use SSLyze: sslyze --regular target.com", "Check for POODLE: test SSLv3 availability", "Test for DROWN: check if SSLv2 is supported", "Verify certificate chain, expiry, SANs, and key strength"],
          remediation: "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. Enforce TLS 1.2+ with strong cipher suites. Implement HSTS. Use 2048+ bit RSA or ECC keys. Configure proper certificate chains.",
          why: "Weak TLS allows traffic interception and decryption. Known protocol vulnerabilities (POODLE, BEAST, DROWN) have published exploits. Certificate misconfigurations enable impersonation."
        }
      },
    ],
  },
  {
    id: "webapp",
    label: "Web Application",
    icon: "\uD83D\uDD78\uFE0F",
    color: "#a855f7",
    items: [
      {
        id: "w1", text: "OWASP Top 10 assessment",
        details: {
          overview: "The OWASP Top 10 represents the most critical web application security risks. A comprehensive assessment covers injection, broken auth, sensitive data exposure, XXE, broken access control, security misconfiguration, XSS, insecure deserialization, vulnerable components, and logging failures.",
          steps: ["Map all application endpoints and functionality", "Use Burp Suite Pro for automated + manual scanning", "Test each OWASP category systematically per methodology", "Use OWASP Testing Guide (OTG) as checklist baseline", "Document all findings with reproduction steps"],
          remediation: "Follow OWASP Proactive Controls for each category. Implement security in the SDLC. Use SAST/DAST tooling in CI/CD pipelines. Conduct regular security training for developers.",
          why: "OWASP Top 10 covers the vulnerabilities present in the vast majority of breaches. It is the industry standard baseline for web application security assessments."
        }
      },
      {
        id: "w2", text: "SQL Injection (manual + automated)",
        details: {
          overview: "SQL injection allows attackers to manipulate database queries by injecting malicious SQL syntax into input fields. It can lead to authentication bypass, data theft, data deletion, and in some cases OS command execution.",
          steps: ["Test all input parameters with ' and 1=1-- -", "Use sqlmap: sqlmap -u 'https://target.com/page?id=1' --dbs", "Test for blind SQLi with time delays: 1'; WAITFOR DELAY '0:0:5'--", "Check login forms: ' OR '1'='1", "Test HTTP headers: User-Agent, Referer, X-Forwarded-For"],
          remediation: "Use parameterized queries / prepared statements exclusively. Implement input validation and whitelisting. Apply least privilege to database accounts. Use an ORM. Enable WAF SQLi rules.",
          why: "SQLi remains one of the most common and impactful vulnerabilities. A single SQLi can compromise the entire database, authentication system, and potentially the OS. It is highly automatable by attackers."
        }
      },
      {
        id: "w3", text: "Cross-Site Scripting (Reflected, Stored, DOM)",
        details: {
          overview: "XSS allows injection of malicious scripts into web pages viewed by other users. Stored XSS persists in the database, Reflected XSS is in URL parameters, and DOM XSS occurs in client-side code. XSS enables session hijacking, keylogging, and phishing.",
          steps: ["Test reflected XSS: inject <script>alert(1)<\\/script> in all inputs", "Check stored XSS in comments, profiles, form data", "Test DOM XSS via URL fragments (#) and client-side JS sinks", "Bypass filters with: <img src=x onerror=alert(1)>", "Use XSS Hunter for blind XSS detection in admin panels"],
          remediation: "Implement Content Security Policy (CSP) headers. Use output encoding (HTML entity encoding) for all user-controlled data. Use a templating engine with auto-escaping. Validate and sanitize all inputs.",
          why: "XSS is pervasive and enables account takeover without exploiting server-side code. Stored XSS in an admin panel can compromise the entire application. DOM XSS is frequently missed by automated scanners."
        }
      },
      {
        id: "w4", text: "Broken authentication & session management",
        details: {
          overview: "Flaws in authentication allow attackers to compromise passwords, keys, or session tokens to assume user identities. Weak session management enables session hijacking and fixation attacks.",
          steps: ["Test for weak session token entropy (collect 100 tokens, analyze)", "Check if session token changes after login", "Test session invalidation on logout", "Attempt session fixation by setting pre-auth session token", "Check if tokens are transmitted in URLs (GET parameters)"],
          remediation: "Use cryptographically random session IDs with 128+ bits entropy. Invalidate sessions on logout. Implement session timeout. Transmit session tokens only via cookies with Secure/HttpOnly flags. Regenerate session ID after login.",
          why: "Broken authentication directly enables account takeover. Weak session management is the primary mechanism for maintaining unauthorized access after credential theft."
        }
      },
      {
        id: "w5", text: "Insecure Direct Object References (IDOR)",
        details: {
          overview: "IDOR occurs when an application uses user-controllable input to access objects directly without proper authorization checks. Changing an ID in a request can access other users' data.",
          steps: ["Identify all endpoints with object IDs (user IDs, order IDs, file IDs)", "Create two accounts and attempt to access Account A's resources as Account B", "Manipulate IDs: increment, decrement, try negative values, GUIDs", "Check all HTTP methods: GET, POST, PUT, DELETE", "Test IDOR in headers, cookies, and JSON body parameters"],
          remediation: "Implement server-side authorization checks on every request. Use indirect references (per-user mapping). Never trust client-supplied IDs without verifying ownership. Implement object-level access control (OLAC).",
          why: "IDOR is consistently in the top 3 most impactful vulnerabilities in bug bounties. A single IDOR can expose all user data in a system. They are trivial to exploit but require manual testing to find."
        }
      },
      {
        id: "w6", text: "CSRF token validation",
        details: {
          overview: "Cross-Site Request Forgery tricks authenticated users into making unwanted requests. Without CSRF tokens, attackers can forge state-changing requests (password change, fund transfer) when a victim visits a malicious page.",
          steps: ["Intercept state-changing requests in Burp Suite", "Remove CSRF token and replay - check if request succeeds", "Change CSRF token value to arbitrary string - check if accepted", "Test if CSRF token is tied to user session or reusable", "Test for CSRF via JSON endpoints and custom request methods"],
          remediation: "Implement synchronizer token pattern or double-submit cookie pattern. Use SameSite=Strict cookie attribute. Verify Origin/Referer headers server-side. Use framework-provided CSRF protection.",
          why: "CSRF can perform any authenticated action on behalf of the victim - password changes, purchases, admin actions. It requires no authentication credentials and exploits the browser's automatic cookie inclusion."
        }
      },
      {
        id: "w7", text: "XXE injection testing",
        details: {
          overview: "XML External Entity injection exploits XML parsers that process external entity references. XXE can lead to reading arbitrary files from the server, SSRF, and in some cases remote code execution.",
          steps: ["Identify XML input points (SOAP, file upload, API)", "Inject basic XXE: <!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "Test blind XXE with out-of-band data exfiltration via DNS", "Test SSRF via XXE: SYSTEM 'http://internal-service/'", "Test with different encodings (UTF-16) to bypass filters"],
          remediation: "Disable XML external entity processing in all XML parsers. Use less complex data formats (JSON). Patch/update XML processing libraries. Implement server-side input validation. Use XML schema validation.",
          why: "XXE can read /etc/passwd, SSH keys, application source code, and internal service responses. Many legacy applications process XML and are vulnerable. Blind XXE is commonly missed by automated scanners."
        }
      },
      {
        id: "w8", text: "SSRF attack vectors",
        details: {
          overview: "Server-Side Request Forgery forces the server to make HTTP requests to attacker-specified URLs. It can access internal services, cloud metadata endpoints (AWS 169.254.169.254), and bypass firewall restrictions.",
          steps: ["Find parameters that accept URLs: url=, fetch=, webhook=, redirect=", "Test access to internal IPs: http://127.0.0.1/ and http://192.168.x.x/", "Target cloud metadata: http://169.254.169.254/latest/meta-data/", "Try DNS rebinding and URL parsing bypasses", "Test for blind SSRF using Burp Collaborator"],
          remediation: "Implement allowlist-based URL validation. Disable unused URL schemes (file://, dict://, gopher://). Block access to internal IP ranges at the application layer. Use a dedicated egress proxy with allowlisting.",
          why: "SSRF can exfiltrate AWS IAM credentials from metadata services, pivot to internal APIs, and bypass firewalls. In cloud environments, SSRF is frequently escalated to full account compromise."
        }
      },
      {
        id: "w9", text: "Open redirect vulnerabilities",
        details: {
          overview: "Open redirects allow attackers to craft URLs on trusted domains that redirect users to malicious sites. Used in phishing campaigns to bypass URL reputation filters and OAuth token theft.",
          steps: ["Find redirect parameters: ?url=, ?redirect=, ?next=, ?return=", "Test: target.com/redirect?url=https://evil.com", "Try bypass techniques: //evil.com, /\\evil.com, https://target.com.evil.com", "Check if redirect is used in OAuth flow (token theft potential)", "Test for JavaScript-based redirects: location.href = param"],
          remediation: "Avoid redirects based on user input. If required, use an allowlist of permitted redirect destinations. Validate the full URL against the allowlist. Add a warning page for external redirects.",
          why: "Open redirects enable highly convincing phishing (URL shows trusted domain). In OAuth flows, they can be used to steal authorization codes and access tokens."
        }
      },
      {
        id: "w10", text: "File upload bypass & path traversal",
        details: {
          overview: "Insecure file upload allows uploading malicious files (web shells, scripts). Path traversal (../) allows accessing files outside the intended directory, potentially reading sensitive configuration files.",
          steps: ["Upload .php/.asp shell with modified Content-Type: image/jpeg", "Test double extension: shell.php.jpg", "Try null byte: shell.php%00.jpg", "Test path traversal: ../../../etc/passwd in filename", "Upload SVG file with embedded XSS or XXE payload"],
          remediation: "Validate file type by content (magic bytes), not extension or Content-Type. Store uploads outside web root. Rename files on upload. Implement file size limits. Use CDN or separate domain for user-uploaded content.",
          why: "Successful file upload of a web shell gives direct command execution on the server. Path traversal exposes configuration files containing database credentials and API keys."
        }
      },
      {
        id: "w11", text: "HTTP security headers review",
        details: {
          overview: "Missing security headers enable numerous client-side attacks. Content-Security-Policy prevents XSS. HSTS prevents protocol downgrade. X-Frame-Options prevents clickjacking.",
          steps: ["Use securityheaders.com or curl -I target.com", "Check for CSP: Content-Security-Policy header", "Verify HSTS: Strict-Transport-Security with includeSubDomains", "Check X-Frame-Options or CSP frame-ancestors", "Verify X-Content-Type-Options: nosniff and Referrer-Policy"],
          remediation: "Implement all OWASP recommended security headers. Use a strict Content-Security-Policy. Enable HSTS with preloading. Set X-Content-Type-Options: nosniff. Remove server version headers.",
          why: "Security headers are a low-cost, high-impact defense layer. Their absence makes XSS, clickjacking, MIME sniffing, and downgrade attacks significantly easier to exploit."
        }
      },
      {
        id: "w12", text: "API endpoint enumeration & testing",
        details: {
          overview: "Applications often expose undocumented API endpoints with less security scrutiny. Enumerating these endpoints reveals hidden functionality, admin endpoints, and internal data.",
          steps: ["Spider the application with Burp Suite for all endpoints", "Check /api/, /v1/, /v2/, /internal/, /admin/ paths", "Use wordlists with gobuster/ffuf: ffuf -u target.com/FUZZ -w api_wordlist.txt", "Analyze JavaScript files for hardcoded API endpoints", "Check Swagger/OpenAPI spec at /swagger.json, /api-docs"],
          remediation: "Maintain an API inventory. Remove or restrict undocumented endpoints. Implement authentication on all API endpoints. Use API gateways for centralized access control. Disable debug/internal endpoints in production.",
          why: "Hidden API endpoints often lack the security controls applied to main application flows. They are a common source of IDOR, authentication bypass, and sensitive data exposure vulnerabilities."
        }
      },
      {
        id: "w13", text: "Rate limiting & brute-force protection",
        details: {
          overview: "Without rate limiting, login endpoints, OTP inputs, and password reset forms are vulnerable to brute-force attacks. Password spraying and credential stuffing are automated attacks against these weaknesses.",
          steps: ["Send 100+ login requests rapidly - check for lockout or CAPTCHA", "Test OTP brute-force: try all 4-6 digit combinations", "Test password spray: one password against many usernames", "Check if rate limiting is per-IP (bypass with X-Forwarded-For header)", "Test account enumeration: different responses for valid vs invalid user"],
          remediation: "Implement account lockout after N failed attempts. Add CAPTCHA for suspicious activity. Apply rate limiting per account, not just per IP. Use adaptive authentication. Implement credential stuffing protection.",
          why: "Without brute-force protection, weak or reused passwords are easily compromised. OTP bypass enables full account takeover on systems that rely on 2FA. Credential stuffing automates this at massive scale."
        }
      },
      {
        id: "w14", text: "Clickjacking / UI redressing",
        details: {
          overview: "Clickjacking embeds the target site in an iframe on a malicious page, tricking users into clicking on invisible elements. It can trigger account deletion, fund transfers, or authentication approvals.",
          steps: ["Try embedding target in iframe: <iframe src='https://target.com'>", "Check if X-Frame-Options or CSP frame-ancestors header is set", "Use Burp Suite's Clickjacking PoC generator", "Test for partial clickjacking: only sensitive pages unprotected", "Test multi-step clickjacking for complex actions"],
          remediation: "Set X-Frame-Options: DENY or SAMEORIGIN. Use Content-Security-Policy: frame-ancestors 'none'. Implement frame-busting JavaScript as defense-in-depth.",
          why: "Clickjacking requires no XSS or SQLi - just missing headers. It can trick administrators into approving actions, users into changing settings, or victims into clicking malicious links."
        }
      },
    ],
  },
  {
    id: "auth",
    label: "Authentication & Authorization",
    icon: "\uD83D\uDD10",
    color: "#10b981",
    items: [
      {
        id: "a1", text: "Password policy enforcement check",
        details: {
          overview: "Weak password policies allow users to set easily guessable passwords. This, combined with no brute-force protection, makes credential compromise trivial.",
          steps: ["Attempt to register with: password123, 12345678, aaaaaa", "Test minimum length enforcement", "Check if complexity requirements are enforced server-side", "Verify common password blocking (RockYou list)", "Test if previously used passwords can be reused"],
          remediation: "Enforce minimum 12-character passwords with complexity. Block commonly used passwords against a blocklist. Check HaveIBeenPwned API for breached passwords on registration.",
          why: "Weak passwords are the #1 cause of unauthorized access. Password policy enforcement is the first line of defense for all accounts in the system."
        }
      },
      {
        id: "a2", text: "Account lockout mechanism testing",
        details: {
          overview: "Without lockout, unlimited login attempts allow brute-forcing any account. With lockout, attackers can lock all accounts (DoS). Proper implementation balances security with availability.",
          steps: ["Submit 10+ failed login attempts - check for lockout", "Test if lockout applies per-account or per-IP only", "Attempt bypass with rotating IPs or X-Forwarded-For", "Test lockout duration and unlock mechanism", "Check if lockout applies to password reset and OTP endpoints"],
          remediation: "Implement progressive delays after failed attempts. Use soft lockout (CAPTCHA) before hard lockout. Apply rate limiting per account AND per IP. Monitor for distributed attacks.",
          why: "No lockout = brute-force possible. Poor lockout = DoS against user accounts. Both are exploitable. Testing finds the right balance and ensures the mechanism actually works."
        }
      },
      {
        id: "a3", text: "Multi-factor authentication bypass attempts",
        details: {
          overview: "MFA is the most effective account security control but is commonly implemented with bypass flaws: code reuse, no expiry, response manipulation, fallback SMS weaknesses.",
          steps: ["Test if MFA code is validated server-side or client-side", "Attempt to reuse a previously valid MFA code", "Test if OTP expires properly (try 10 minutes later)", "Response manipulation: change 'mfa_required: true' to false", "Test account recovery flow - does it bypass MFA?"],
          remediation: "Enforce MFA on all authentication flows including recovery. Make OTPs single-use and short-lived (30–60 seconds). Validate MFA server-side. Never allow recovery mechanisms to bypass MFA.",
          why: "MFA bypass fully undermines the security benefit of MFA. If the bypass exists, MFA provides no protection against credential theft - the most common attack vector."
        }
      },
      {
        id: "a4", text: "JWT token manipulation & algorithm confusion",
        details: {
          overview: "JWTs signed with weak secrets or vulnerable algorithms (none, HS256 with RS256 key confusion) allow token forgery. An attacker can modify claims to become admin without knowing the secret.",
          steps: ["Decode JWT at jwt.io and examine payload claims", "Test 'alg: none' attack: remove signature entirely", "Try algorithm confusion: sign HS256 with the RS256 public key as secret", "Brute-force weak HS256 secrets with hashcat (mode 16500)", "Test if JWT is validated for expiry (exp claim tampering)"],
          remediation: "Use only strong algorithms (RS256, ES256). Explicitly reject 'none' algorithm. Validate all claims (exp, iss, aud). Use well-maintained JWT libraries. Rotate signing keys regularly.",
          why: "JWT vulnerabilities allow complete authentication bypass and privilege escalation to admin. Algorithm confusion attacks are well-documented and exploit trust in the token's own declared algorithm."
        }
      },
      {
        id: "a5", text: "OAuth / SAML flow analysis",
        details: {
          overview: "OAuth and SAML flaws can enable account takeover via token theft, CSRF in authorization flows, redirect_uri manipulation, and XML signature wrapping attacks in SAML.",
          steps: ["Test CSRF in OAuth authorization endpoint (missing state parameter)", "Attempt redirect_uri bypass with partial matching", "Test for token leakage in Referer header", "Test SAML XML signature wrapping by modifying assertion", "Test OAuth implicit flow token theft via open redirect"],
          remediation: "Always validate the state parameter in OAuth. Use strict redirect_uri matching. Use PKCE for public clients. Validate SAML assertions including signatures, timestamps, and conditions.",
          why: "OAuth/SAML flaws are high-severity as they affect the entire authentication system. Compromise of the SSO provider means compromise of all connected applications."
        }
      },
      {
        id: "a6", text: "Privilege escalation (horizontal & vertical)",
        details: {
          overview: "Horizontal escalation accesses another user's data (same privilege). Vertical escalation gains higher privileges (user → admin). Both indicate broken access control, the #1 OWASP risk.",
          steps: ["Create regular user account and admin account", "As regular user, attempt admin-only API endpoints", "Try accessing /admin, /superuser, /manage paths", "Modify role parameter in requests: role=admin, isAdmin=true", "Test function-level authorization on all privileged operations"],
          remediation: "Implement role-based access control (RBAC) enforced server-side. Never trust client-supplied role or permission data. Audit all privileged endpoints for authorization checks. Deny by default.",
          why: "Privilege escalation is the most common way attackers gain administrative access. Horizontal escalation enables mass data theft. Both bypass the fundamental security assumption of authentication."
        }
      },
      {
        id: "a7", text: "Session fixation / hijacking",
        details: {
          overview: "Session fixation forces a user to use an attacker-controlled session ID. Session hijacking steals an existing valid session token via XSS, network sniffing, or log exposure.",
          steps: ["Check if session ID changes after authentication", "Test if pre-authentication session ID is accepted post-login", "Look for session tokens in URL parameters or logs", "Check for session tokens in Referer headers to third parties", "Test concurrent session handling (same account, multiple sessions)"],
          remediation: "Generate new session ID on authentication. Invalidate old session on login. Transmit sessions only in cookies with Secure+HttpOnly flags. Implement session rotation. Log session events.",
          why: "Session hijacking enables account takeover without knowing credentials. Session fixation allows an attacker to force a victim to authenticate into an attacker-controlled session - giving the attacker full access."
        }
      },
      {
        id: "a8", text: "Cookie security flags (HttpOnly, Secure, SameSite)",
        details: {
          overview: "Session cookies without security flags are vulnerable to theft. HttpOnly prevents JavaScript access (XSS), Secure prevents HTTP transmission, and SameSite prevents CSRF.",
          steps: ["Inspect cookies in browser DevTools for all flags", "Check Set-Cookie response header for HttpOnly, Secure, SameSite", "Test if session cookie is accessible via document.cookie (no HttpOnly)", "Test if session works over plain HTTP (no Secure flag)", "Verify SameSite attribute: Strict, Lax, or None"],
          remediation: "Set HttpOnly on all session cookies. Set Secure on all cookies. Set SameSite=Strict or Lax on session cookies. Use __Secure- and __Host- cookie prefixes for additional protection.",
          why: "Missing HttpOnly makes every XSS vulnerability an automatic session hijack. Missing Secure allows credential theft on any HTTP connection. Missing SameSite enables CSRF on all state-changing actions."
        }
      },
      {
        id: "a9", text: "Password reset flow vulnerabilities",
        details: {
          overview: "Password reset mechanisms are frequently the weakest link in authentication. Common flaws include predictable tokens, token reuse, host header injection, and account enumeration.",
          steps: ["Test if reset token is predictable (timestamp-based, sequential)", "Test if reset token can be used multiple times", "Test host header injection: Host: attacker.com - check if link goes to attacker", "Check if valid token exists after password is changed", "Test for user enumeration: different responses for valid vs invalid email"],
          remediation: "Use cryptographically random reset tokens (min 128 bits). Make tokens single-use and expire after 15–60 minutes. Validate Host header server-side. Invalidate all sessions on password reset.",
          why: "Password reset bypass is a complete authentication bypass. Host header injection sends the reset link to the attacker. Token reuse allows multiple password resets with one intercepted link."
        }
      },
    ],
  },
  {
    id: "config",
    label: "Configuration & Hardening",
    icon: "\u2699\uFE0F",
    color: "#f59e0b",
    items: [
      {
        id: "c1", text: "Default credentials on all services",
        details: {
          overview: "Software shipped with default credentials (admin/admin, admin/password) is routinely deployed without changes in production, providing immediate unauthorized access.",
          steps: ["Compile list of all exposed services and their default credentials", "Test web admin panels: Tomcat, Jenkins, Grafana, phpMyAdmin", "Try database defaults: MySQL root/'', MongoDB with no auth", "Test network device defaults: Cisco, Juniper, Fortinet", "Use DefaultCreds-cheat-sheet for comprehensive list"],
          remediation: "Change all default credentials during initial setup. Implement a provisioning checklist. Scan for default credentials using tools like Nuclei default-credentials templates. Use a PAM solution.",
          why: "Default credentials are the easiest possible compromise - no hacking required. They provide immediate admin access to databases, application servers, and infrastructure. Often found in 100% of large organizations."
        }
      },
      {
        id: "c2", text: "Unnecessary open ports & services",
        details: {
          overview: "Every open port is potential attack surface. Services like FTP, Telnet, SMTP relay, and legacy management interfaces expose the system to exploitation without providing business value.",
          steps: ["Full port scan to enumerate all open ports", "Identify business justification for each open service", "Check for legacy services: FTP (21), Telnet (23), SMTP relay (25)", "Look for development services in production: debug ports, test interfaces", "Verify firewall rules match the intended exposure"],
          remediation: "Apply principle of least exposure - only expose required services. Disable or remove unused services at the OS level. Use host-based firewall rules. Conduct quarterly port exposure audits.",
          why: "Each unnecessary service is an attack vector with no business value. A single vulnerable legacy service (OpenSSL, Apache version) can compromise the entire host."
        }
      },
      {
        id: "c3", text: "Debug mode / verbose error messages",
        details: {
          overview: "Debug mode and verbose errors expose stack traces, source code paths, database queries, internal IP addresses, framework versions, and configuration details - intelligence that directly aids exploitation.",
          steps: ["Trigger errors: send unexpected input, invalid parameters", "Check 404/500 error pages for technology disclosure", "Test with malformed JSON/XML to trigger exception handling", "Look for Django DEBUG=True, PHP error_reporting, ASP.NET customErrors", "Check HTTP response headers for server version disclosure"],
          remediation: "Disable debug mode in all production environments. Configure custom generic error pages. Implement centralized logging to capture errors internally without exposing them externally. Remove verbose banners.",
          why: "Stack traces reveal exact file paths, library versions, and code logic. Database error messages often contain schema information. This intelligence directly enables targeted exploitation."
        }
      },
      {
        id: "c4", text: "Directory listing enabled",
        details: {
          overview: "Web server directory listing displays all files in a directory when no index file exists. This reveals backup files, configuration files, source code, credentials, and hidden functionality.",
          steps: ["Browse to directories without index files: /images/, /uploads/, /backup/", "Use Burp Suite to find directories via spidering", "Check for common paths: /admin/, /config/, /logs/, /backup/", "Use gobuster/ffuf to discover directories", "Check for .htaccess files that should restrict access"],
          remediation: "Disable directory listing in web server configuration (Options -Indexes in Apache, autoindex off in Nginx). Return 403 for directory access. Store sensitive files outside web root.",
          why: "Directory listing is a zero-effort information disclosure. Exposed backup files (.bak, .old) contain source code. Exposed config files contain credentials. Combined with path traversal, it enables complete data theft."
        }
      },
      {
        id: "c5", text: "Backup & configuration file exposure (.env, .git)",
        details: {
          overview: "Accidentally exposed configuration and backup files contain database credentials, API keys, encryption secrets, and application source code. .git directories expose complete source code history.",
          steps: ["Check for /.git/: curl https://target.com/.git/HEAD", "Use GitDumper to extract accessible .git repository", "Test for: .env, .env.production, .env.backup", "Check for: config.php.bak, web.config.bak, settings.py", "Use GitDorks or grep.app to search GitHub for target-specific secrets"],
          remediation: "Block access to dotfiles in web server config. Add .git, .env to robots.txt (but also block in server config). Use secret scanning in CI/CD. Audit web root for backup files.",
          why: ".env files typically contain all application secrets. .git directories provide complete source code for white-box analysis. These are among the highest-severity configuration issues with immediate credential exposure."
        }
      },
      {
        id: "c6", text: "Outdated software & missing patches (CVE scan)",
        details: {
          overview: "Unpatched systems with known CVEs are vulnerable to published public exploits. Exploit-DB and Metasploit have ready-made exploits for thousands of CVEs that can be triggered in minutes.",
          steps: ["Run: nmap --script vulners --script-args mincvss=7.0 target", "Use Nuclei with CVE templates: nuclei -t cves/ -u target", "Run authenticated scan with Nessus/OpenVAS for comprehensive results", "Check software versions against NVD CVE database manually", "Look for end-of-life software (Windows Server 2008, PHP 5.x, Apache 2.2)"],
          remediation: "Establish a patch management program with SLAs (critical: 24–72 hours). Maintain a software inventory (CMDB). Subscribe to vendor security advisories. Use vulnerability management platforms.",
          why: "Most successful cyberattacks exploit known, patched vulnerabilities. WannaCry used an exploit with a patch available 2 months prior. Unpatched software is the most common root cause of breaches."
        }
      },
      {
        id: "c7", text: "Admin interfaces publicly accessible",
        details: {
          overview: "Management interfaces (phpMyAdmin, Tomcat Manager, Jenkins, Grafana admin, cPanel) exposed to the internet are high-value targets. Brute-force or default credentials provide administrative access.",
          steps: ["Use EyeWitness to screenshot all discovered web services", "Search Shodan for management interfaces on org IP ranges", "Check common admin paths: /admin, /manager, /phpmyadmin, /jenkins", "Test all admin interfaces for default credentials", "Verify admin interfaces require VPN/IP restriction"],
          remediation: "Restrict admin interface access to management VLANs or VPN. Implement IP allowlisting. Enable MFA on all admin interfaces. Use a bastion host for administrative access.",
          why: "Admin interfaces have the highest privilege. A compromised admin panel typically means full control of the application and potentially the infrastructure. Public exposure multiplies attack surface enormously."
        }
      },
      {
        id: "c8", text: "Cloud storage misconfiguration (S3, Azure Blob)",
        details: {
          overview: "Publicly accessible cloud storage buckets are a leading cause of data breaches. Misconfigured S3 buckets have exposed billions of records including PII, credentials, and intellectual property.",
          steps: ["Enumerate S3 buckets: target-name, target-backup, target-assets", "Test public access: aws s3 ls s3://bucket-name --no-sign-request", "Use S3Scanner or CloudBrute for bucket enumeration", "Check Azure Blob for public containers", "Test for write access: aws s3 cp test.txt s3://bucket-name/ --no-sign-request"],
          remediation: "Enable S3 Block Public Access. Use bucket policies with explicit deny for public access. Enable AWS CloudTrail for bucket access logging. Use AWS Macie to classify sensitive data. Audit all storage access controls.",
          why: "Publicly readable S3 buckets have exposed medical records, financial data, and source code for major corporations. Writable buckets enable ransomware, data injection, and supply chain attacks."
        }
      },
      {
        id: "c9", text: "Container / Docker misconfigurations",
        details: {
          overview: "Docker and Kubernetes misconfigurations enable container escape, access to host systems, lateral movement across clusters, and exposure of the container runtime API.",
          steps: ["Check for exposed Docker API: curl http://target:2375/info", "Test privileged container: --privileged flag set", "Check mounted host filesystem: look for /host/etc/passwd", "Scan for exposed Kubernetes API: curl https://target:6443/api", "Test for SSRF to 169.254.169.254 from within application"],
          remediation: "Never expose Docker daemon API without TLS. Never run containers in privileged mode. Use read-only root filesystems. Apply Kubernetes RBAC. Use Pod Security Policies/Standards. Run regular container image scans.",
          why: "Container escape converts application-level compromise into host-level compromise. Exposed Kubernetes APIs can lead to full cluster takeover. Container misconfigs are common in DevOps-heavy environments."
        }
      },
    ],
  },
  {
    id: "android",
    label: "Android Security",
    icon: "🤖",
    color: "#84cc16",
    items: [
      {
        id: "and1", text: "APK decompilation & source code review (jadx, apktool)",
        details: {
          overview: "Android APKs can be decompiled to recover Java/Kotlin source code, resources, and configuration files. This reveals hardcoded secrets, business logic flaws, and backend API endpoints.",
          steps: ["Extract APK: adb pull /data/app/com.target.app*/base.apk .", "Decompile with jadx: jadx -d output/ target.apk", "Use apktool for resources: apktool d target.apk", "Search for secrets: grep -r 'password\\|api_key\\|secret\\|token' output/", "Analyze network calls and endpoint URLs in source"],
          remediation: "Implement code obfuscation with ProGuard/R8. Move secrets to server-side. Use Android Keystore for cryptographic keys. Remove debug builds and logs from release APKs.",
          why: "APK decompilation is trivial and provides white-box access to the application. Hardcoded API keys give direct backend access. Business logic in client-side code can be manipulated by attackers."
        }
      },
      {
        id: "and2", text: "AndroidManifest.xml - exported components & permissions audit",
        details: {
          overview: "The AndroidManifest.xml declares all app components and permissions. Exported Activities, Services, and Content Providers without proper access control can be invoked by any app on the device.",
          steps: ["Extract manifest: apktool d target.apk && cat AndroidManifest.xml", "Find exported components: grep 'exported=\"true\"' AndroidManifest.xml", "List dangerous permissions: SEND_SMS, READ_CONTACTS, CAMERA, READ_CALL_LOG", "Use MobSF for automated manifest analysis", "Test exported activities via ADB: adb shell am start -n com.target/.ExportedActivity"],
          remediation: "Set exported=false on all components not intended for external use. Add android:permission attribute to exported components. Request only necessary permissions. Audit permissions in each release.",
          why: "Exported components are accessible to any app on the device, including malware. Overprivileged apps increase the impact of compromise. Unprotected exported activities often bypass authentication."
        }
      },
      {
        id: "and3", text: "Hardcoded secrets, API keys & credentials in source",
        details: {
          overview: "Developers hardcode API keys, database credentials, encryption keys, and backend URLs directly in app code or string resources. Once the APK is public, these secrets are trivially extractable.",
          steps: ["Search decompiled code: grep -rn 'apikey\\|secret\\|password\\|Bearer' output/", "Check res/values/strings.xml for secrets", "Search for cloud provider keys: AKIA (AWS), AIza (Google)", "Use truffleHog or semgrep on decompiled output", "Check for Firebase configuration in google-services.json"],
          remediation: "Never hardcode secrets in client applications. Use environment-based configuration. Store secrets in a secrets management system. Implement certificate pinning for API communication. Use dynamic key fetching.",
          why: "Hardcoded secrets provide direct backend access. AWS keys can lead to full cloud account compromise. Firebase misconfigurations have led to millions of exposed user records. These are zero-effort findings with critical impact."
        }
      },
      {
        id: "and4", text: "Insecure data storage (SharedPreferences, SQLite, external SD)",
        details: {
          overview: "Sensitive data stored insecurely on the device can be accessed by other apps, attackers with physical access, or through backup mechanisms. SharedPreferences stored in plaintext is a common issue.",
          steps: ["Root device or use emulator with root access", "Check SharedPreferences: cat /data/data/com.target.app/shared_prefs/*.xml", "Read SQLite database: sqlite3 /data/data/com.target.app/databases/*.db", "Check external storage: ls /sdcard/Android/data/com.target.app/", "Use Objection: objection -g com.target.app explore -> android filesystem"],
          remediation: "Use EncryptedSharedPreferences for sensitive data. Encrypt SQLite databases (SQLCipher). Never store sensitive data on external storage. Use Android Keystore for encryption keys. Clear data on logout.",
          why: "Device theft, physical access, or malware targeting other apps can expose sensitive user data. Banking credentials, auth tokens, and PII stored in plaintext are trivially extractable on rooted devices."
        }
      },
      {
        id: "and5", text: "Cleartext traffic / HTTP usage (network_security_config.xml)",
        details: {
          overview: "Android 9+ blocks cleartext HTTP traffic by default. Apps that re-enable it or use cleartext to specific domains allow network-level interception of credentials and session tokens.",
          steps: ["Check network_security_config.xml for clearTextTrafficPermitted=true", "Check AndroidManifest.xml for usesCleartextTraffic=true", "Intercept traffic with mitmproxy without SSL setup - check HTTP calls", "Monitor traffic during app usage for HTTP requests", "Check if specific domains are whitelisted for cleartext"],
          remediation: "Remove all cleartext network configuration. Enforce HTTPS for all connections. Do not set usesCleartextTraffic=true. Implement certificate pinning for sensitive endpoints.",
          why: "HTTP traffic on any network (coffee shop WiFi, corporate network) can be intercepted passively. Cleartext credentials are captured trivially. This is a fundamental transport security failure."
        }
      },
      {
        id: "and6", text: "SSL/TLS certificate pinning bypass (Frida, Objection)",
        details: {
          overview: "Certificate pinning prevents MITM attacks by validating the server's certificate against a pinned copy. Testing the implementation validates that it cannot be bypassed using common tools.",
          steps: ["Configure Burp Suite as proxy and attempt to intercept traffic", "If pinning is active, use Objection: android sslpinning disable", "Use Frida with universal SSL unpinning script", "Check for certificate pinning in OkHttp, Retrofit, and TrustManager", "Test against Frida-based bypass scripts for custom pinning implementations"],
          remediation: "Implement pinning using Android's network_security_config.xml with pin-set. Pin the public key hash, not the full certificate. Implement backup pins for certificate rotation. Use OkHttp CertificatePinner.",
          why: "Without pinning verification, the app is vulnerable to MITM attacks with a rogue CA. Testing confirms the implementation cannot be trivially bypassed, validating the security benefit of the control."
        }
      },
      {
        id: "and7", text: "Root detection & emulator detection bypass",
        details: {
          overview: "Root and emulator detection are security controls preventing analysis and tampering. Testing bypass validates the effectiveness of these controls and identifies gaps attackers can exploit.",
          steps: ["Run app on rooted device/Magisk - check if detection triggers", "Use Magisk Hide / Shamiko to bypass root detection", "Use Frida to hook root detection methods and return false", "Test on emulators (Android Studio AVD) - check detection", "Use Objection: android root disable"],
          remediation: "Implement multi-layered root detection (SafetyNet/Play Integrity API, file system checks, prop checks). Accept that determined attackers can bypass - use it as a risk signal, not absolute prevention. Combine with RASP.",
          why: "Root detection prevents trivial manipulation of app behavior and data extraction. Bypass indicates security controls can be circumvented. Banking and payment apps rely on these controls to prevent fraud."
        }
      },
      {
        id: "and8", text: "Tapjacking / overlay attack via exported Activity",
        details: {
          overview: "Tapjacking overlays a malicious transparent view over an exported Activity, intercepting user taps intended for the legitimate UI - enabling covert user interaction and permission grants.",
          steps: ["Create PoC app with SYSTEM_ALERT_WINDOW permission", "Draw transparent overlay over target app's exported activities", "Monitor if tap events are intercepted by overlay", "Test on Android <10 which is more susceptible", "Check if app uses filterTouchesWhenObscured for sensitive buttons"],
          remediation: "Set filterTouchesWhenObscured=true on security-sensitive views (confirm, allow, authorize). Use setFilterTouchesWhenObscured(true) programmatically. On Android 8+, use FLAG_SECURE where appropriate.",
          why: "Tapjacking enables silent permission grants and covert interaction with sensitive UI elements. Malicious apps can overlay banking authentication prompts to capture credentials or authorize transactions."
        }
      },
      {
        id: "and9", text: "Intent injection & implicit intent interception",
        details: {
          overview: "Implicit intents broadcast to all apps that register matching intent filters. Malicious apps can register to receive sensitive implicit intents, intercepting data like authentication tokens or deep link parameters.",
          steps: ["Find implicit intents in manifest: <action android:name='...'> without package", "Create PoC app with matching intent filter to intercept", "Use ADB to send crafted intents to exported components", "Test deep links with malicious parameters", "Check PendingIntents for mutability flags"],
          remediation: "Use explicit intents with explicit package names for sensitive IPC. Use LocalBroadcastManager for app-internal broadcasts. Validate all intent extras before processing. Use android:exported=false.",
          why: "Intent interception enables data theft between app components. Malicious apps can receive authentication tokens, payment information, and deep link parameters intended for the legitimate app."
        }
      },
      {
        id: "and10", text: "Content provider SQL injection via URI",
        details: {
          overview: "Content providers expose data via URIs. If they construct SQL queries using URI path segments without parameterization, SQL injection is possible, allowing access to all data in the provider.",
          steps: ["Find exported content providers in manifest", "Query provider via ADB: adb shell content query --uri content://com.target.provider/users/'%20OR%201=1--'", "Test selection argument injection", "Use Drozer: run app.provider.query content://com.target.provider/ --projection '* FROM users--'", "Test for path traversal in file-based providers"],
          remediation: "Use parameterized queries in Content Providers. Validate and sanitize all URI inputs. Set exported=false for providers not intended for inter-app use. Apply Android permissions to restrict access.",
          why: "Content provider injection gives access to all data managed by the provider - user data, credentials, and application state. It bypasses app authentication since content provider calls don't require app to be running."
        }
      },
      {
        id: "and11", text: "WebView misconfiguration (JS enabled, file access, addJavascriptInterface)",
        details: {
          overview: "WebView misconfigurations are among the most severe Android vulnerabilities. JavaScript interfaces expose Java methods to web content. File access allows reading local files via file:// URIs.",
          steps: ["Identify WebView usage in decompiled source", "Check: setJavaScriptEnabled(true), setAllowFileAccess(true)", "Look for addJavascriptInterface() calls and the exposed object", "Test file:// URI loading: inject URL to load file:///etc/hosts", "Test XSS in WebView to trigger JavaScript interface methods"],
          remediation: "Disable JavaScript unless absolutely required. Disable file access (setAllowFileAccess(false)). Remove addJavascriptInterface from production. Use @JavascriptInterface annotation. Use Safe Browsing API.",
          why: "addJavascriptInterface pre-Android 4.2 allows full RCE via XSS. File access in WebView allows local file theft. XSS in a WebView with a JS interface gives attackers access to all exposed Java methods."
        }
      },
      {
        id: "and12", text: "Broadcast receiver abuse (sticky broadcasts, exported receivers)",
        details: {
          overview: "Exported broadcast receivers without permissions can receive crafted broadcasts from any app. Sticky broadcasts persist and can be intercepted by any app that registers for them.",
          steps: ["Find exported receivers in manifest without permissions", "Send crafted broadcast: adb shell am broadcast -a com.target.ACTION_LOGIN_SUCCESS", "Test for sensitive data in broadcast extras", "Use Drozer: run app.broadcast.send --action com.target.ACTION", "Check for sticky broadcasts with sensitive data"],
          remediation: "Add android:permission to all exported broadcast receivers. Use LocalBroadcastManager for internal broadcasts. Never include sensitive data in sticky broadcasts. Use explicit broadcasts where possible.",
          why: "Broadcast receiver abuse allows privilege escalation by triggering actions without proper authentication. Intercepting broadcasts can capture session tokens and authentication events."
        }
      },
      {
        id: "and13", text: "Insecure logging - sensitive data in Logcat",
        details: {
          overview: "Excessive logging of sensitive data (passwords, tokens, PII) to Logcat allows any app with READ_LOGS permission (or ADB access) to capture this data. Pre-Android 4.1 any app could read all logs.",
          steps: ["Connect ADB: adb logcat | grep -i 'password\\|token\\|credit\\|email'", "Perform authentication and sensitive operations while monitoring logcat", "Use Objection to monitor logs dynamically", "Search decompiled code for Log.d(), Log.v() with sensitive params", "Check for custom logging frameworks that might be more verbose"],
          remediation: "Remove all sensitive data from log statements before production release. Use ProGuard to strip debug log calls. Use a logging level system - disable verbose/debug logs in release. Use Android BuildConfig.DEBUG checks.",
          why: "Logcat data is accessible via ADB (developer tools, physical access) and potentially by other installed apps. Token and password logging makes all security controls trivially bypassable."
        }
      },
      {
        id: "and14", text: "Backup flag enabled (android:allowBackup=true)",
        details: {
          overview: "When android:allowBackup=true, ADB can extract the entire application data directory - databases, SharedPreferences, files - without root access. This exposes all locally stored data.",
          steps: ["Check manifest for android:allowBackup=true (default is true)", "Extract backup via ADB: adb backup -noapk com.target.app", "Convert backup: dd if=backup.ab bs=1 skip=24 | zlib-flate -uncompress | tar xvf -", "Examine extracted data for credentials, tokens, databases", "Test on Android <12 for more permissive backup behavior"],
          remediation: "Set android:allowBackup=false in production apps with sensitive data. If backup is needed, use Android Auto Backup with encryption and include/exclude rules. Consider what data truly needs backup.",
          why: "ADB backup requires no root access - only USB access and USB debugging enabled. It bypasses all application authentication to extract stored data. This is a commonly overlooked attack vector."
        }
      },
      {
        id: "and15", text: "Clipboard data leakage of sensitive fields",
        details: {
          overview: "Any app can read clipboard content (pre-Android 10) and receive clipboard change notifications. If users copy passwords or tokens, malicious apps silently capture this data.",
          steps: ["Use a banking/payment app and copy account numbers/credentials", "Monitor clipboard with: adb shell service call clipboard 2", "Create PoC app to monitor ClipboardManager.OnPrimaryClipChangedListener", "Check if sensitive fields (password, CVV) have copyable text enabled", "Test on Android <10 for unrestricted clipboard access"],
          remediation: "Disable text selection and clipboard on sensitive fields (password, CVV, OTP). Use TYPE_TEXT_VARIATION_PASSWORD input type. Add OnPrimaryClipChangedListener detection. On Android 12+ warn about clipboard access.",
          why: "Password managers and users routinely copy sensitive data. Clipboard-reading malware is a real threat vector. Banking apps with copyable account numbers are trivially targeted."
        }
      },
      {
        id: "and16", text: "Biometric authentication bypass",
        details: {
          overview: "Biometric authentication can be bypassed if the implementation relies on client-side validation, returns a boolean result that can be hooked, or doesn't bind cryptographic operations to biometric success.",
          steps: ["Hook BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded with Frida", "Check if authentication result is a simple boolean not tied to crypto", "Test with Objection: android hooking watch class androidx.biometric.BiometricPrompt", "Analyze if CryptoObject is used to bind biometric to crypto operation", "Test behavior when biometric is unavailable - fallback PIN handling"],
          remediation: "Bind biometric authentication to a CryptoObject. Require KeyStore-backed key that requires biometric for use. Never implement biometric result as client-side boolean. Use BiometricPrompt with BIOMETRIC_STRONG.",
          why: "Biometric bypass allows full authentication bypass. If not cryptographically bound, biometric is just a UI gate that can be trivially bypassed with Frida hooks, undermining the entire authentication control."
        }
      },
      {
        id: "and17", text: "Reverse engineering protection (obfuscation, anti-tamper)",
        details: {
          overview: "Without obfuscation and tamper detection, attackers can easily read source code, understand business logic, bypass security controls, and repackage malicious versions of the app.",
          steps: ["Decompile APK with jadx - assess code readability", "Check if class/method names are obfuscated (ProGuard/R8 applied)", "Test tamper detection by repackaging APK with test certificate", "Check if app validates its own signature", "Use APKiD to detect packing and obfuscation techniques"],
          remediation: "Enable ProGuard/R8 obfuscation in release builds. Implement signature verification. Use Google Play Integrity API for tamper detection. Consider commercial RASP solutions for high-security apps.",
          why: "Obfuscation significantly raises the cost of reverse engineering. Without it, all security controls are visible to attackers. Tamper detection prevents malicious repackaging for phishing or malware distribution."
        }
      },
      {
        id: "and18", text: "Runtime permission model abuse",
        details: {
          overview: "Android's runtime permission model can be abused through permission squatting, over-privileged apps, and permission escalation via intent redirection or shared UIDs.",
          steps: ["List all permissions requested by app and evaluate necessity", "Check for dangerous permissions: CAMERA, MICROPHONE, LOCATION, READ_CONTACTS", "Verify permission is only used when necessary, not on startup", "Test if sensitive operations occur without user grant confirmation", "Check for shared UID with other packages granting elevated permissions"],
          remediation: "Request only the minimum permissions required. Request permissions at the point of use (contextual). Document justification for each dangerous permission. Use Privacy Dashboard review on Android 12+.",
          why: "Over-privileged apps increase the blast radius of compromise. Permission squatting enables apps to gain permissions they didn't earn. Users grant excessive permissions that enable surveillance and data theft."
        }
      },
      {
        id: "and19", text: "Deep link / custom URI scheme hijacking",
        details: {
          overview: "Custom URI schemes (myapp://action?param=value) can be registered by multiple apps. A malicious app registering the same scheme can intercept deep links containing OAuth tokens and sensitive parameters.",
          steps: ["Find URI schemes and intent filters in manifest", "Register same URI scheme in a test app", "Trigger deep link via web browser - check which app receives it", "Test for parameter injection in deep link handling code", "Check if authentication tokens are passed via deep links"],
          remediation: "Use Android App Links (verified HTTPS-based deep links) instead of custom URI schemes. Implement Digital Asset Links verification. Validate all deep link parameters server-side. Never pass sensitive tokens in deep link URLs.",
          why: "Custom URI scheme hijacking allows interception of OAuth authorization codes, password reset tokens, and session tokens. Android App Links are cryptographically verified and cannot be registered by malicious apps."
        }
      },
      {
        id: "and20", text: "Dynamic instrumentation with Frida (hook sensitive methods)",
        details: {
          overview: "Frida enables runtime manipulation of running apps - hooking methods, modifying return values, bypassing security controls, and extracting runtime secrets like encryption keys and authentication tokens.",
          steps: ["Start Frida server on device: ./frida-server &", "List running apps: frida-ps -U", "Hook crypto operations: frida -U -l crypto_monitor.js com.target.app", "Bypass root detection: frida -U -l bypass_root.js com.target.app", "Extract runtime keys: hook javax.crypto.spec.SecretKeySpec and log key bytes"],
          remediation: "Detect Frida server process and /proc/maps entries. Check for frida-agent libraries in loaded modules. Use Play Integrity API to detect compromised environment. Implement RASP solutions. Accept limitations against determined attackers.",
          why: "Frida can bypass virtually any client-side security control. Testing with Frida reveals whether implemented security controls can survive dynamic analysis - a mandatory test for high-security apps."
        }
      },
    ],
  },
  {
    id: "api",
    label: "API Security",
    icon: "⚡",
    color: "#e879f9",
    items: [
      {
        id: "api1", text: "API endpoint discovery & documentation review (Swagger, Postman)",
        details: {
          overview: "Complete API discovery ensures no endpoint is missed. Undocumented endpoints often have less security scrutiny. Swagger/OpenAPI specs expose the full attack surface.",
          steps: ["Check for Swagger UI: /swagger-ui, /api-docs, /openapi.json", "Import Swagger spec into Burp Suite for automatic endpoint discovery", "Spider the app to capture all API calls in Burp proxy history", "Search JavaScript files for API endpoint strings", "Check for Postman collections in GitHub repositories"],
          remediation: "Restrict API documentation access in production (authentication required). Maintain accurate API inventory. Use API gateway to enforce documented behavior. Disable introspection in production GraphQL.",
          why: "Undocumented 'shadow APIs' have the weakest security controls. API specs expose endpoint parameters and authentication requirements. Complete discovery prevents missing critical endpoints during assessment."
        }
      },
      {
        id: "api2", text: "Authentication mechanism testing (API keys, Bearer tokens, Basic auth)",
        details: {
          overview: "API authentication must be validated on every endpoint. Missing authentication on a single endpoint, token reuse across environments, or weak API keys breaks the entire security model.",
          steps: ["Test all endpoints without any authentication header", "Test with expired Bearer token", "Test with another user's valid Bearer token (horizontal access)", "Check if API keys work across environments (dev key works in prod)", "Test if API keys are scoped (read-only key can write)"],
          remediation: "Enforce authentication on every non-public endpoint. Implement token expiry and rotation. Scope API keys by functionality. Use short-lived tokens with refresh mechanism. Log all authentication events.",
          why: "A single unauthenticated endpoint can expose all data. API key theft provides persistent access until manual rotation. Unscoped keys provide excessive access when limited access was intended."
        }
      },
      {
        id: "api3", text: "Broken Object Level Authorization - BOLA/IDOR on resource IDs",
        details: {
          overview: "BOLA is the #1 OWASP API vulnerability. APIs often expose object identifiers and fail to verify the requesting user owns the object. Changing an ID accesses another user's resources.",
          steps: ["Create two test accounts: user_A and user_B", "As user_A, create a resource and note its ID", "As user_B, attempt to access/modify/delete user_A's resource ID", "Test across all resource types: user profiles, orders, documents, messages", "Test BOLA in HTTP headers, query params, and JSON body"],
          remediation: "Implement object ownership validation on every endpoint. Use authorization middleware. Never rely on obscure IDs for security. Conduct authorization unit tests. Use random UUIDs to reduce enumeration.",
          why: "BOLA is the most common API vulnerability and leads to mass data theft. A single BOLA on a user endpoint can expose all user records. It bypasses authentication because the attacker is authenticated - just not authorized."
        }
      },
      {
        id: "api4", text: "Broken Function Level Authorization - accessing admin endpoints",
        details: {
          overview: "Function-level authorization checks whether a user can call a specific function/endpoint (e.g., DELETE, admin operations), not just access the resource. Admin endpoints are often accessible to regular users.",
          steps: ["Discover admin endpoints from documentation, JS, or Swagger spec", "As regular user, call admin endpoints: /api/admin/users, /api/v1/admin/", "Test HTTP method manipulation: regular GET might be allowed but admin PUT isn't", "Test privilege escalation via parameter: ?admin=true, isAdmin=true", "Check if changing role in JWT payload grants access"],
          remediation: "Implement role-based access control at the function level. Deny by default. Separate admin and user API routes. Validate user roles server-side on every admin endpoint invocation.",
          why: "Admin endpoints control the entire application. Access to user management, configuration changes, and financial operations from a regular user account is a critical severity finding."
        }
      },
      {
        id: "api5", text: "Excessive data exposure in API responses",
        details: {
          overview: "APIs often return full object data and rely on the client to filter what to display. This exposes PII, credentials, internal system data, and other sensitive fields not needed by the client.",
          steps: ["Compare API response with what the UI displays - look for hidden fields", "Check for password hashes, internal IDs, system metadata in responses", "Test list endpoints - do they return all records or just authorized ones", "Look for sensitive fields: ssn, credit_card, password, token, internal_note", "Check GraphQL queries for field-level access control"],
          remediation: "Implement response filtering at the API layer. Never return sensitive fields by default. Use DTOs (Data Transfer Objects) to explicitly define response schemas. Apply field-level access control in GraphQL.",
          why: "Excessive data exposure leaks PII at scale. Password hashes enable offline cracking. Internal tokens provide persistent access. One over-sharing endpoint can expose data for all users in a single request."
        }
      },
      {
        id: "api6", text: "Mass assignment / parameter pollution attack",
        details: {
          overview: "Mass assignment occurs when APIs bind all request parameters to object properties without filtering. An attacker can set privileged fields like 'isAdmin', 'balance', 'role' in API requests.",
          steps: ["Review API request format and compare to response object properties", "Add extra fields to POST/PUT requests: isAdmin=true, role=admin, balance=99999", "Test with JSON: {'username':'test', 'password':'test', 'isAdmin':true}", "Check if framework automatically binds request properties to model", "Test PATCH endpoints for partial update mass assignment"],
          remediation: "Use explicit allow-list of permitted fields for binding. Use DTOs/input validation schemas. Disable automatic parameter binding on sensitive models. Audit all model-binding code.",
          why: "Mass assignment allows users to set any object property including privilege flags and financial values. It has been used to perform unauthorized fund transfers, gain admin access, and manipulate business logic."
        }
      },
      {
        id: "api7", text: "Rate limiting & resource consumption (API6:2023)",
        details: {
          overview: "Without rate limiting, APIs are vulnerable to brute-force, DoS, and data harvesting attacks. Unrestricted resource consumption (large payloads, deeply nested queries) can crash the API server.",
          steps: ["Send rapid bursts of requests (1000/sec) - check for 429 responses", "Test OTP/PIN brute-force endpoints specifically", "Send excessively large request bodies - check for size limits", "For GraphQL: send deeply nested queries (100 levels) - test complexity limits", "Test enumeration of all records via pagination without limits"],
          remediation: "Implement rate limiting per user, per IP, and per endpoint. Set request size limits. For GraphQL: implement query depth and complexity analysis. Use circuit breakers for downstream calls. Return 429 with Retry-After header.",
          why: "No rate limiting allows automated data harvesting (enumerate all users), brute-force of any credential, and application DoS. API abuse is a primary attack vector for data theft at scale."
        }
      },
      {
        id: "api8", text: "Injection attacks via API parameters (SQLi, NoSQLi, CMDi)",
        details: {
          overview: "All injection vulnerabilities apply to API parameters. REST API query parameters, JSON body fields, and GraphQL variables are injection vectors for SQL, NoSQL (MongoDB), OS command, and template injection.",
          steps: ["Test SQL injection in all query parameters and JSON fields", "Test NoSQL injection: {'username': {'$gt': ''}, 'password': {'$gt': ''}}", "Test OS command injection: parameter=value;id or value|whoami", "Test SSTI: parameter={{7*7}} - look for 49 in response", "Use sqlmap --data with JSON content-type for API SQLi"],
          remediation: "Use parameterized queries. Validate and sanitize all inputs. Use an ORM. Implement strict input type validation. Run API traffic through a WAF. Use allowlist-based input validation.",
          why: "APIs accept structured data which is passed to databases and system calls. API injection is often missed because automated scanners don't properly handle JSON/XML inputs. The impact is identical to web injection."
        }
      },
      {
        id: "api9", text: "GraphQL introspection enabled & query depth/complexity limits",
        details: {
          overview: "GraphQL introspection exposes the complete schema - all types, queries, and mutations - to any user. Combined with no complexity limits, attackers can map the entire data model and perform DoS attacks.",
          steps: ["Test introspection: send __schema query to /graphql endpoint", "Use GraphQL Voyager to visualize the schema from introspection", "Test deep nesting: query user { friends { friends { friends {...} } } }", "Test alias batching attack: 1000 aliases in a single query", "Test fragment injection for query complexity bypass"],
          remediation: "Disable introspection in production. Implement query depth limits (max 5–7 levels). Implement query complexity analysis and cost limits. Use query allowlisting for production. Use persisted queries.",
          why: "Introspection gives attackers a complete blueprint of your data model for free. Query complexity attacks can crash GraphQL servers with a single malicious query. Both are frequently misconfigured in production."
        }
      },
      {
        id: "api10", text: "GraphQL batching attacks & field-level auth bypass",
        details: {
          overview: "GraphQL allows multiple operations in a single request (batching). This enables brute-force bypassing rate limiting, IDOR across multiple objects, and bypassing field-level authorization by aliasing queries.",
          steps: ["Test query batching: send array of login mutations to bypass rate limiting", "Alias-based brute-force: {a1: login(pass:'aaa'), a2: login(pass:'aab'), ...}", "Test horizontal IDOR via batching: fetch multiple user IDs in one query", "Check field-level authorization: request admin-only fields as regular user", "Test mutation batching for state manipulation attacks"],
          remediation: "Limit batch size per request. Apply rate limiting per-operation not per-request. Implement field-level authorization resolvers. Disable batching if not required by the application.",
          why: "Batching completely bypasses per-request rate limiting. A single GraphQL request with 1000 batched operations can brute-force credentials. Field-level auth bypass exposes sensitive data that query-level auth was supposed to protect."
        }
      },
      {
        id: "api11", text: "JWT - algorithm confusion, none alg, weak secret brute-force",
        details: {
          overview: "JWT vulnerabilities are common in API authentication. Algorithm confusion (RS256→HS256 using public key as secret), 'none' algorithm, and weak secrets allow complete token forgery.",
          steps: ["Decode JWT on jwt.io - examine header.alg and payload claims", "Test alg:none - remove signature: header.payload.", "Algorithm confusion: sign with HS256 using RS256 public key as secret", "Brute-force HS256 secrets: hashcat -a 0 -m 16500 jwt.txt wordlist.txt", "Test claim manipulation: change 'role' to 'admin', 'exp' to future date"],
          remediation: "Explicitly whitelist permitted algorithms server-side. Reject 'none' algorithm unconditionally. Use strong secrets for HS256 (256+ bit random). Prefer asymmetric algorithms (RS256, ES256). Validate all JWT claims.",
          why: "JWT algorithm confusion is a critical flaw that allows signing arbitrary tokens using the server's own public key. It completely bypasses authentication and is trivially exploitable with published tools."
        }
      },
      {
        id: "api12", text: "OAuth 2.0 flow - PKCE bypass, token leakage, redirect_uri abuse",
        details: {
          overview: "OAuth 2.0 implementation flaws enable account takeover. redirect_uri manipulation allows token theft, missing state enables CSRF, missing PKCE allows authorization code interception.",
          steps: ["Test redirect_uri: add extra parameters, use partial path matches", "Check if state parameter is validated (CSRF in OAuth flow)", "Test PKCE: is code_challenge enforced for public clients?", "Check if authorization code can be used multiple times", "Test for token leakage in Referer header or browser history"],
          remediation: "Enforce exact redirect_uri matching. Always validate state parameter. Enforce PKCE for all public clients. Make authorization codes single-use and short-lived. Never expose tokens in URLs.",
          why: "OAuth flaws are common and allow account takeover at scale. redirect_uri abuse lets attackers steal tokens without touching the user's device. These are high-impact, standardized attack patterns with real-world exploitation history."
        }
      },
      {
        id: "api13", text: "API versioning - older/deprecated endpoints still accessible",
        details: {
          overview: "When new API versions are deployed, old versions are often left running but forgotten. Legacy endpoints frequently lack current security controls, authentication requirements, and patches.",
          steps: ["Test v1, v2, v0 prefixes alongside current version: /api/v1/, /api/v0/", "Check if deprecated endpoints return same data with less auth", "Test if security controls on new API are absent on old: /v1/admin vs /v2/admin", "Search for version references in JavaScript and mobile app source", "Fuzz for version numbers: /api/beta/, /api/internal/, /api/legacy/"],
          remediation: "Maintain an API lifecycle policy. Actively decommission deprecated versions. If old versions must exist, apply identical security controls. Monitor access logs for deprecated endpoint usage.",
          why: "API versioning debt is extremely common. Security patches applied to v2 may not be on v1. Authentication added to new endpoints may be absent from old ones. Attackers specifically target v1 when v2 is more hardened."
        }
      },
      {
        id: "api14", text: "HTTP verb tampering (GET vs POST vs PUT vs DELETE)",
        details: {
          overview: "Some APIs implement authorization checks only for specific HTTP methods, assuming others are safe. Changing the HTTP verb can bypass authorization, trigger unintended actions, or access different code paths.",
          steps: ["Try GET instead of POST for state-changing operations", "Try PUT/PATCH instead of DELETE for destructive actions", "Test HEAD and OPTIONS to probe server behavior", "Test method override headers: X-HTTP-Method-Override: DELETE", "Test with method tunneling: ?_method=DELETE in POST requests"],
          remediation: "Implement authorization checks that are method-agnostic - check authorization before processing any verb. Use method-specific route definitions. Validate HTTP method on every endpoint. Reject unexpected methods with 405.",
          why: "Authorization bypasses via verb tampering are simple to test and have significant impact. They exploit the assumption that GET is read-only and therefore less dangerous - which is often false in poorly designed APIs."
        }
      },
      {
        id: "api15", text: "CORS misconfiguration - wildcard or reflected origins",
        details: {
          overview: "CORS misconfigurations allow malicious websites to make authenticated API requests on behalf of users. Reflecting the Origin header or using wildcards with credentials enables full cross-origin API access.",
          steps: ["Send request with Origin: https://attacker.com - check Access-Control-Allow-Origin response", "Test null origin: Origin: null - check if accepted", "Check if Access-Control-Allow-Credentials: true is set with permissive origin", "Test subdomain trust: Origin: https://attacker.target.com", "Use CORS PoC generator to create exploitation demo"],
          remediation: "Use an explicit allowlist of trusted origins. Never reflect arbitrary Origin headers. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Implement CORS in a centralized middleware.",
          why: "A reflected CORS origin with credentials allows any website to make authenticated API calls on behalf of logged-in users - equivalent to CSRF but more powerful, bypassing SameSite cookie protections."
        }
      },
      {
        id: "api16", text: "Server-Side Request Forgery via API parameters",
        details: {
          overview: "API endpoints that accept URLs or IP addresses (webhooks, URL fetchers, integrations) are prime SSRF targets. In cloud environments, SSRF can access metadata services and steal IAM credentials.",
          steps: ["Find API parameters accepting URLs: webhook_url, callback, fetch, import", "Test with http://127.0.0.1/ and http://localhost/", "Target AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/", "Test internal service discovery: http://internal-service.local/", "Use Burp Collaborator for blind SSRF detection"],
          remediation: "Implement strict URL allowlisting. Block RFC-1918 private IP ranges. Disable URL schemas not needed (file://, gopher://). Use an egress proxy. Implement IMDS v2 on AWS instances.",
          why: "API-based SSRF is frequently used to escalate cloud application compromise to full cloud account takeover. AWS IAM credentials from the metadata service grant extensive cloud permissions."
        }
      },
      {
        id: "api17", text: "Business logic flaws (negative values, state manipulation)",
        details: {
          overview: "Business logic flaws exploit the application's intended functionality in unintended ways - negative purchase amounts, race conditions, state transitions that shouldn't be allowed, price manipulation.",
          steps: ["Test negative values: quantity=-1, amount=-100.00", "Test race conditions on purchases, transfers, and coupon applications", "Test workflow bypass: skip step 2 of a 3-step process", "Manipulate prices client-side before submission", "Test integer overflow and boundary values: 999999999, 0, MAX_INT"],
          remediation: "Validate all business rules server-side. Use state machine patterns to prevent invalid transitions. Implement idempotency for financial operations. Use database transactions for race condition protection.",
          why: "Business logic flaws are application-specific and missed by automated scanners. They can lead to free goods, unauthorized fund transfers, privilege escalation, and financial loss. Manual testing is the only way to find them."
        }
      },
      {
        id: "api18", text: "Error message verbosity - stack traces, internal paths",
        details: {
          overview: "Verbose API errors expose stack traces, framework versions, internal file paths, database queries, and server hostnames - providing detailed intelligence for targeted exploitation.",
          steps: ["Send malformed JSON: missing braces, wrong types, overflow values", "Send unexpected data types: string where int expected, null for required field", "Test with invalid authentication: malformed tokens", "Deliberately trigger 500 errors by exceeding limits", "Check if GraphQL errors expose resolver internals"],
          remediation: "Return generic error messages in production. Log detailed errors internally. Use custom error handlers that sanitize output. Disable stack traces in production configuration. Test error responses in CI/CD.",
          why: "Stack traces reveal exact code paths and library versions for targeted CVE exploitation. Internal hostnames facilitate lateral movement. Database query errors reveal schema structure for SQLi optimization."
        }
      },
      {
        id: "api19", text: "Webhook security - signature verification, SSRF via URL",
        details: {
          overview: "Webhooks receive external HTTP callbacks. Missing signature verification allows replay attacks and fake events. Webhook URLs stored by the API can be used as SSRF vectors.",
          steps: ["Register webhook URL pointing to Burp Collaborator - check for SSRF", "Send fake webhook events without valid signature - check if processed", "Modify webhook payload and resend - check if signature is verified", "Test webhook URL to internal services: http://internal-api/trigger", "Test if old webhook events can be replayed (missing timestamp validation)"],
          remediation: "Implement HMAC signature verification for all webhook deliveries. Validate timestamp in signature to prevent replay attacks. Use an allowlist for webhook destination URLs. Block internal IP ranges.",
          why: "Webhook forgery allows attackers to trigger application actions (payments, user creation, order fulfillment) without authorization. Webhook SSRF uses the application as a pivot point to attack internal services."
        }
      },
      {
        id: "api20", text: "WebSocket message tampering & authorization checks",
        details: {
          overview: "WebSocket connections bypass standard HTTP security controls. Messages sent over WebSocket may lack authentication on individual messages, enabling message injection, replay attacks, and unauthorized actions.",
          steps: ["Intercept WebSocket traffic in Burp Suite (turn on WebSocket interception)", "Modify WebSocket messages: change user IDs, amounts, action types", "Test if WebSocket connection authentication persists after token expiry", "Test cross-user message injection: send message to another user's channel", "Check if WebSocket endpoint validates authorization per-message"],
          remediation: "Authenticate WebSocket connections at the handshake. Validate authorization on each message operation, not just connection. Use signed message envelopes for sensitive operations. Implement WebSocket rate limiting.",
          why: "WebSocket connections are long-lived and their messages are often trusted without per-message authorization. Tampering can trigger admin actions, inject data for other users, and maintain unauthorized access after token expiry."
        }
      },
    ],
  },
  {
    id: "postexploit",
    label: "Post-Exploitation",
    icon: "\uD83C\uDFAF",
    color: "#ef4444",
    items: [
      {
        id: "p1", text: "Lateral movement feasibility",
        details: {
          overview: "After initial compromise, attackers move laterally to reach high-value targets. Testing lateral movement capability demonstrates the real-world impact beyond the initial entry point.",
          steps: ["From initial access, enumerate adjacent systems via ARP/DNS", "Test credential reuse across other systems (Pass-the-Hash, Pass-the-Ticket)", "Use BloodHound to map Active Directory attack paths", "Test if service accounts have excessive rights across systems", "Attempt WMI/PSExec/SMB lateral movement to adjacent hosts"],
          remediation: "Implement network segmentation. Use privileged access workstations (PAW). Apply least privilege to service accounts. Enable Credential Guard. Monitor for lateral movement with EDR/SIEM.",
          why: "Lateral movement is what turns a compromised workstation into a domain compromise. Understanding the blast radius after initial access is critical for realistic risk assessment and business impact quantification."
        }
      },
      {
        id: "p2", text: "Credential dumping & password hashes",
        details: {
          overview: "Credential dumping extracts password hashes and cleartext credentials from memory (LSASS), registry (SAM), and credential stores. Dumped hashes enable offline cracking and Pass-the-Hash attacks.",
          steps: ["Dump LSASS with Mimikatz: sekurlsa::logonpasswords", "Extract SAM hive: reg save HKLM\\SAM sam.save", "Use CrackMapExec for remote credential dumping", "Check for cleartext passwords in LSASS (WDigest enabled)", "Dump credentials from browser stores and credential manager"],
          remediation: "Enable Windows Credential Guard. Disable WDigest authentication. Restrict local admin rights. Deploy EDR with credential dumping detection. Implement privileged access management (PAM) solutions.",
          why: "Credential dumping converts local admin access into domain admin access via Pass-the-Hash or cracked domain credentials. It is the most common lateral movement technique in real-world breaches."
        }
      },
      {
        id: "p3", text: "Data exfiltration path identification",
        details: {
          overview: "Identifying viable exfiltration paths demonstrates that sensitive data can actually leave the network. Organizations often have good ingress controls but poor egress filtering.",
          steps: ["Test DNS exfiltration: encode data in DNS queries to controlled server", "Test HTTPS exfiltration to cloud services (Dropbox, GitHub, Pastebin)", "Test ICMP covert channel for data exfiltration", "Check if DLP solutions detect simulated sensitive data exfiltration", "Test exfiltration over allowed protocols: HTTP/HTTPS on port 443"],
          remediation: "Implement strict egress filtering - whitelist only necessary external connections. Deploy a DLP solution. Monitor DNS for exfiltration patterns. Use SSL inspection on egress traffic. Log and alert on large outbound transfers.",
          why: "Organizations focus on preventing intrusion but neglect exfiltration. Data theft is the primary financial impact of a breach. Proving exfiltration paths validates the real-world severity of the compromise."
        }
      },
      {
        id: "p4", text: "Persistence mechanism testing",
        details: {
          overview: "Persistence mechanisms allow attackers to maintain access after system restarts, credential changes, or initial access vector remediation. Testing ensures defensive controls can detect and prevent persistence.",
          steps: ["Test registry run keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Test scheduled tasks creation with high-privilege accounts", "Test service installation as a persistence mechanism", "Test WMI event subscriptions for fileless persistence", "Check startup folder and boot sector modifications"],
          remediation: "Monitor registry run keys with EDR. Alert on new scheduled tasks and services. Use application allowlisting to prevent unauthorized executables. Enable audit logging for persistence-related events.",
          why: "Persistence is how attackers maintain long-term access. Without detecting it, incident responders patch the entry point but leave backdoors active. Testing validates that detection controls work."
        }
      },
      {
        id: "p5", text: "AV / EDR evasion capability",
        details: {
          overview: "Testing whether security controls can be evaded validates their detection capability against realistic adversary techniques. EDR evasion reveals gaps in the defensive security posture.",
          steps: ["Test obfuscated payloads against AV: custom encoders, packers", "Test living-off-the-land binaries (LOLBins): PowerShell, WMI, certutil", "Test process injection techniques: DLL injection, process hollowing", "Test fileless execution: PowerShell in-memory execution", "Validate EDR alert generation for all tested techniques"],
          remediation: "Configure EDR behavioral detection rules. Enable Script Block Logging for PowerShell. Restrict LOLBin usage with application control. Conduct regular purple team exercises. Test AV signatures against current threat actor TTPs.",
          why: "AV/EDR tools provide false confidence if they can be easily evaded. Testing evasion capability validates the actual detection coverage and identifies gaps that advanced attackers would exploit."
        }
      },
      {
        id: "p6", text: "Pivoting through network segments",
        details: {
          overview: "Pivoting uses a compromised host as a relay to attack systems in network segments not directly accessible to the attacker. It defeats network segmentation if host-based controls are insufficient.",
          steps: ["Configure SOCKS proxy through compromised host: ssh -D 1080", "Use Metasploit route command to pivot through sessions", "Test access to internal segment systems through the pivot", "Use Chisel or ligolo-ng for sophisticated tunneling", "Measure what additional attack surface is accessible from pivot point"],
          remediation: "Enforce host-based firewall rules to limit outbound connections from servers. Use micro-segmentation. Monitor for unusual outbound connections from servers. Implement zero-trust network access.",
          why: "Pivoting is the technique that turns an internet-facing server compromise into internal network access. It demonstrates that network segmentation is insufficient without host-based controls."
        }
      },
      {
        id: "p7", text: "Log tampering / covering tracks",
        details: {
          overview: "Attackers clear logs to hinder incident response and extend dwell time. Testing whether logs can be tampered validates the integrity of the logging infrastructure.",
          steps: ["Attempt to clear Windows Event Logs: Clear-EventLog", "Test modification of Linux /var/log/auth.log", "Check if logs are being forwarded in real-time to SIEM", "Test if log deletion triggers an alert in SIEM", "Attempt to disable audit logging: auditctl -D"],
          remediation: "Forward all logs to immutable, centralized SIEM in real-time. Alert on log clearing events. Use append-only log storage. Implement Windows event forwarding with GPO. Protect syslog from modification.",
          why: "Log integrity is essential for incident response and forensics. If attackers can erase logs, breach discovery and scope determination become impossible. Testing validates that evidence is preserved even after compromise."
        }
      },
    ],
  },
  {
    id: "reporting",
    label: "Reporting & Closure",
    icon: "\uD83D\uDCCB",
    color: "#06b6d4",
    items: [
      {
        id: "rep1", text: "Executive summary drafted",
        details: {
          overview: "The executive summary communicates findings to non-technical stakeholders in business risk terms. It should convey overall security posture, critical findings, and recommended priorities without technical jargon.",
          steps: ["Identify the 3–5 most critical business risks discovered", "Translate technical findings into business impact (data breach, financial loss, regulatory)", "Provide overall risk rating: Critical/High/Medium/Low/Informational", "Include remediation investment vs. risk reduction summary", "Have a non-technical colleague review for clarity"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "Executives make resource allocation decisions based on the executive summary. A poor summary results in critical findings being deprioritized. Clear business-language reporting drives appropriate remediation investment."
        }
      },
      {
        id: "rep2", text: "Findings classified by CVSS score / severity",
        details: {
          overview: "CVSS (Common Vulnerability Scoring System) provides a standardized, objective severity rating for each finding. It enables consistent prioritization across assessment types and organizations.",
          steps: ["Calculate CVSS v3.1 base score for each finding using the calculator", "Apply temporal and environmental metrics where applicable", "Map CVSS scores to severity labels: Critical(9-10), High(7-9), Medium(4-7), Low(0-4)", "Cross-reference with OWASP Risk Rating where applicable", "Document base score metrics rationale for each finding"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "Consistent severity classification enables prioritization and SLA compliance. CVSS scores allow organizations to compare findings across assessments and apply remediation SLAs based on objective risk ratings."
        }
      },
      {
        id: "rep3", text: "Proof-of-concept screenshots/videos attached",
        details: {
          overview: "PoC evidence demonstrates that vulnerabilities are real and exploitable, not theoretical. It helps developers reproduce the issue and validates severity claims to both technical and non-technical audiences.",
          steps: ["Capture step-by-step screenshots for all findings", "Record screen capture video for complex multi-step exploits", "Include HTTP request/response for web vulnerabilities (Burp Suite)", "Redact any unnecessary sensitive data from screenshots", "Include tool output and payload used for technical reproducibility"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "Without PoC, findings can be disputed or dismissed as false positives. PoC evidence validates severity ratings, provides reproduction steps for developers, and builds stakeholder trust in the assessment quality."
        }
      },
      {
        id: "rep4", text: "Remediation recommendations included",
        details: {
          overview: "Actionable, specific remediation guidance enables developers and engineers to fix vulnerabilities without needing additional consultants. Generic recommendations add little value.",
          steps: ["Provide specific code-level fixes where applicable", "Include configuration changes with exact syntax", "Reference vendor documentation and security standards (NIST, OWASP)", "Prioritize recommendations by effort vs. risk reduction impact", "Include short-term (patch) and long-term (architecture) recommendations"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "A report that identifies problems without solutions delivers half the value. Specific remediation guidance reduces time-to-fix, prevents incorrect remediation attempts, and demonstrates tester expertise."
        }
      },
      {
        id: "rep5", text: "Risk matrix completed",
        details: {
          overview: "A risk matrix maps findings by likelihood and impact, providing a visual prioritization tool. It helps organizations understand relative risk and allocate remediation resources effectively.",
          steps: ["Plot each finding on a 5x5 likelihood vs impact matrix", "Assign likelihood based on exploitability and attacker skill required", "Assign impact based on data sensitivity and business criticality", "Use the matrix to support remediation prioritization", "Include the matrix visual in the report"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "A CVSS score alone doesn't capture business context. A risk matrix helps stakeholders visually understand which findings need immediate attention versus scheduled remediation. It facilitates executive communication."
        }
      },
      {
        id: "rep6", text: "Scope & methodology documented",
        details: {
          overview: "Documenting scope and methodology provides legal protection, ensures reproducibility, and demonstrates professional standards. It defines what was and wasn't tested to avoid false assumptions.",
          steps: ["List all in-scope assets tested with IP/URL/app version", "Document testing dates, testing methodology (OWASP, PTES, NIST)", "List tools used with versions", "Document testing approach: black-box, grey-box, white-box", "Include rules of engagement and any testing limitations/exceptions"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "Without scope documentation, clients may assume untested systems are secure. Methodology documentation demonstrates professional standards. Legal protection requires clear documentation of authorized testing activities."
        }
      },
      {
        id: "rep7", text: "Re-test / verification plan defined",
        details: {
          overview: "A re-test plan ensures remediated vulnerabilities are actually fixed and not just superficially patched. It closes the loop on the assessment and provides assurance of remediation effectiveness.",
          steps: ["List all findings requiring re-test with severity cutoff (e.g., High+)", "Define re-test window: 30/60/90 days after report delivery", "Document re-test scope: only previously identified findings or full regression", "Define pass/fail criteria for re-test", "Schedule re-test dates with client during report delivery"],
          remediation: "N/A - this is a deliverable quality check item.",
          why: "Organizations often apply incomplete fixes or introduce new vulnerabilities during remediation. Re-testing validates that fixes actually work. It provides the client with assurance and closes the remediation lifecycle."
        }
      },
    ],
  },
];

const severityMap = {
  Critical: { color: "#ef4444", bg: "rgba(239,68,68,0.15)" },
  High: { color: "#f97316", bg: "rgba(249,115,22,0.15)" },
  Medium: { color: "#f59e0b", bg: "rgba(245,158,11,0.15)" },
  Low: { color: "#10b981", bg: "rgba(16,185,129,0.15)" },
};
const severityLevels = ["Critical", "High", "Medium", "Low"];
const DETAIL_TABS = ["overview", "steps", "remediation", "why"];
const TAB_LABELS = { overview: "Overview", steps: "Test Steps", remediation: "Remediation", why: "Why Test" };
const TAB_COLORS = { overview: "#00d4ff", steps: "#f59e0b", remediation: "#10b981", why: "#a855f7" };

function VAPTChecklist() {
  const [checked, setChecked] = React.useState({});
  const [activeCategory, setActiveCategory] = React.useState("recon");
  const [notes, setNotes] = React.useState({});
  const [severity, setSeverity] = React.useState({});
  const [showNoteFor, setShowNoteFor] = React.useState(null);
  const [searchTerm, setSearchTerm] = React.useState("");
  const [expandedItem, setExpandedItem] = React.useState(null);
  const [activeTab, setActiveTab] = React.useState("overview");

  const toggle = (id) => setChecked((p) => ({ ...p, [id]: !p[id] }));
  const setItemSeverity = (itemId, level) =>
    setSeverity((prev) => {
      if (prev[itemId] === level) {
        const { [itemId]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [itemId]: level };
    });
  const setItemNote = (itemId, note) =>
    setNotes((prev) => {
      if (!note.trim()) {
        const { [itemId]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [itemId]: note };
    });

  const totalItems = categories.reduce((s, c) => s + c.items.length, 0);
  const completedItems = Object.values(checked).filter(Boolean).length;
  const progress =
    totalItems === 0 ? 0 : Math.round((completedItems / totalItems) * 100);
  const normalizedSearch = searchTerm.trim().toLowerCase();

  const activeData = categories.find((c) => c.id === activeCategory);

  const filteredItems = normalizedSearch
    ? categories.flatMap((c) =>
        c.items
          .filter((i) => i.text.toLowerCase().includes(normalizedSearch))
          .map((i) => ({ ...i, category: c.label, color: c.color }))
      )
    : activeData?.items.map((i) => ({ ...i, color: activeData.color })) || [];

  const catProgress = (cat) => {
    const done = cat.items.filter((i) => checked[i.id]).length;
    return Math.round((done / cat.items.length) * 100);
  };

  const toggleExpand = (id) => {
    setExpandedItem(expandedItem === id ? null : id);
    setActiveTab("overview");
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0a0f", color: "#e2e8f0", fontFamily: "'Courier New', monospace", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <div style={{ borderBottom: "1px solid rgba(255,255,255,0.08)", padding: "20px 28px", display: "flex", alignItems: "center", justifyContent: "space-between", background: "rgba(255,255,255,0.02)" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 10, letterSpacing: 4, color: "#ef4444", textTransform: "uppercase", fontWeight: 700 }}>CLASSIFIED</span>
            <span style={{ color: "rgba(255,255,255,0.2)", fontSize: 10 }}>///</span>
            <span style={{ fontSize: 10, letterSpacing: 3, color: "rgba(255,255,255,0.4)", textTransform: "uppercase" }}>Security Assessment</span>
          </div>
          <h1 style={{ fontSize: 24, fontWeight: 900, margin: "4px 0 0", letterSpacing: 1, color: "#fff" }}>
            VA <span style={{ color: "#ef4444" }}>/</span> PT Checklist
          </h1>
          <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: 1 }}>{categories.length} PHASES - {totalItems} CHECKS</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 32, fontWeight: 900, color: progress === 100 ? "#10b981" : "#fff", lineHeight: 1 }}>
              {progress}<span style={{ fontSize: 14, color: "rgba(255,255,255,0.4)" }}>%</span>
            </div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", letterSpacing: 2, textTransform: "uppercase" }}>{completedItems}/{totalItems}</div>
          </div>
          <svg width="56" height="56" style={{ transform: "rotate(-90deg)" }}>
            <circle cx="28" cy="28" r="22" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="4" />
            <circle cx="28" cy="28" r="22" fill="none" stroke={progress === 100 ? "#10b981" : "#ef4444"} strokeWidth="4"
              strokeDasharray={`${2 * Math.PI * 22}`} strokeDashoffset={`${2 * Math.PI * 22 * (1 - progress / 100)}`}
              strokeLinecap="round" style={{ transition: "stroke-dashoffset 0.5s ease" }} />
          </svg>
        </div>
      </div>

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Sidebar */}
        <div style={{ width: 200, borderRight: "1px solid rgba(255,255,255,0.06)", padding: "12px 0", overflowY: "auto", flexShrink: 0 }}>
          {categories.map((cat) => {
            const pct = catProgress(cat);
            const active = activeCategory === cat.id && !normalizedSearch;
            return (
              <button type="button" key={cat.id} onClick={() => { setActiveCategory(cat.id); setSearchTerm(""); setExpandedItem(null); }}
                style={{ display: "block", width: "100%", textAlign: "left", padding: "10px 16px", border: "none", cursor: "pointer", background: active ? "rgba(255,255,255,0.06)" : "transparent", borderLeft: active ? `3px solid ${cat.color}` : "3px solid transparent", transition: "all 0.15s" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                  <span style={{ fontSize: 13 }}>{cat.icon}</span>
                  <span style={{ fontSize: 11, fontWeight: active ? 700 : 400, color: active ? "#fff" : "rgba(255,255,255,0.55)", letterSpacing: 0.3 }}>{cat.label}</span>
                </div>
                <div style={{ height: 2, background: "rgba(255,255,255,0.07)", borderRadius: 2 }}>
                  <div style={{ height: "100%", width: `${pct}%`, background: cat.color, borderRadius: 2, transition: "width 0.3s ease" }} />
                </div>
                <div style={{ fontSize: 9, color: "rgba(255,255,255,0.3)", marginTop: 2 }}>
                  {cat.items.filter(i => checked[i.id]).length}/{cat.items.length}
                </div>
              </button>
            );
          })}
        </div>

        {/* Main Content */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px" }}>
          <div style={{ marginBottom: 16 }}>
            <input placeholder="Search all checks..." aria-label="Search checklist items" value={searchTerm} onChange={(e) => { setSearchTerm(e.target.value); setExpandedItem(null); }}
              style={{ width: "100%", boxSizing: "border-box", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, padding: "9px 14px", color: "#e2e8f0", fontSize: 12, outline: "none", fontFamily: "inherit" }} />
          </div>

          {!normalizedSearch && activeData && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              <span style={{ fontSize: 22 }}>{activeData.icon}</span>
              <div>
                <h2 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: activeData.color }}>{activeData.label}</h2>
                <p style={{ margin: 0, fontSize: 10, color: "rgba(255,255,255,0.35)", letterSpacing: 1, textTransform: "uppercase" }}>{activeData.items.length} security checks</p>
              </div>
            </div>
          )}
          {normalizedSearch && <div style={{ marginBottom: 12, fontSize: 11, color: "rgba(255,255,255,0.4)" }}>{filteredItems.length} results for "{searchTerm.trim()}"</div>}

          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {normalizedSearch && filteredItems.length === 0 && (
              <div style={{ border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "12px 14px", color: "rgba(255,255,255,0.5)", fontSize: 12, background: "rgba(255,255,255,0.03)" }}>
                No checks matched this search.
              </div>
            )}
            {filteredItems.map((item) => {
              const isChecked = !!checked[item.id];
              const itemSeverity = severity[item.id];
              const sev = itemSeverity ? severityMap[itemSeverity] : null;
              const isExpanded = expandedItem === item.id;

              return (
                <div key={item.id} style={{ background: isChecked ? "rgba(255,255,255,0.02)" : "rgba(255,255,255,0.04)", border: `1px solid ${isExpanded ? item.color + '55' : isChecked ? "rgba(255,255,255,0.05)" : "rgba(255,255,255,0.09)"}`, borderRadius: 8, overflow: "hidden", transition: "all 0.2s" }}>
                  {/* Item Header Row */}
                  <div style={{ padding: "11px 14px", display: "flex", alignItems: "flex-start", gap: 10 }}>
                    <button type="button" aria-label={isChecked ? `Mark ${item.text} as not done` : `Mark ${item.text} as done`} aria-pressed={isChecked} onClick={() => toggle(item.id)} style={{ width: 18, height: 18, borderRadius: 4, flexShrink: 0, border: `2px solid ${isChecked ? item.color : "rgba(255,255,255,0.2)"}`, background: isChecked ? item.color : "transparent", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", marginTop: 1, transition: "all 0.15s" }}>
                      {isChecked && <svg width="9" height="7" viewBox="0 0 9 7" fill="none"><path d="M1 3.5L3 5.5L8 1" stroke="#000" strokeWidth="2" strokeLinecap="round" /></svg>}
                    </button>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 12, color: isChecked ? "rgba(255,255,255,0.3)" : "#e2e8f0", textDecoration: isChecked ? "line-through" : "none", transition: "all 0.2s" }}>{item.text}</span>
                        {normalizedSearch && item.category && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 100, background: "rgba(255,255,255,0.07)", color: item.color, letterSpacing: 0.5 }}>{item.category}</span>}
                        {sev && <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 100, background: sev.bg, color: sev.color }}>{itemSeverity}</span>}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 5, flexWrap: "wrap" }}>
                        {severityLevels.map((s) => (
                          <button type="button" key={s} aria-label={`Set ${item.text} severity to ${s}`} aria-pressed={itemSeverity === s} onClick={() => setItemSeverity(item.id, s)}
                            style={{ fontSize: 9, padding: "1px 6px", borderRadius: 100, border: `1px solid ${itemSeverity === s ? severityMap[s].color : "rgba(255,255,255,0.1)"}`, background: itemSeverity === s ? severityMap[s].bg : "transparent", color: itemSeverity === s ? severityMap[s].color : "rgba(255,255,255,0.3)", cursor: "pointer", letterSpacing: 0.5, fontFamily: "inherit", transition: "all 0.15s" }}>{s}</button>
                        ))}
                        <button type="button" aria-label={showNoteFor === item.id ? "Hide note input" : "Show note input"} onClick={() => setShowNoteFor(showNoteFor === item.id ? null : item.id)}
                          style={{ fontSize: 9, padding: "1px 6px", borderRadius: 100, border: "1px solid rgba(255,255,255,0.1)", background: notes[item.id] ? "rgba(255,255,255,0.06)" : "transparent", color: notes[item.id] ? "rgba(255,255,255,0.7)" : "rgba(255,255,255,0.3)", cursor: "pointer", letterSpacing: 0.5, fontFamily: "inherit" }}>
                          {notes[item.id] ? "Note added" : "+ note"}
                        </button>
                        <button type="button" aria-label={isExpanded ? `Hide details for ${item.text}` : `Show details for ${item.text}`} onClick={() => toggleExpand(item.id)}
                          style={{ fontSize: 9, padding: "1px 8px", borderRadius: 100, border: `1px solid ${isExpanded ? item.color : "rgba(255,255,255,0.15)"}`, background: isExpanded ? item.color + "22" : "transparent", color: isExpanded ? item.color : "rgba(255,255,255,0.5)", cursor: "pointer", letterSpacing: 0.5, fontFamily: "inherit", transition: "all 0.15s" }}>
                          {isExpanded ? "Hide details" : "Show details"}
                        </button>
                      </div>
                      {showNoteFor === item.id && (
                        <textarea autoFocus placeholder="Add finding notes, CVE references, tool output..." value={notes[item.id] || ""} onChange={(e) => setItemNote(item.id, e.target.value)}
                          style={{ width: "100%", boxSizing: "border-box", marginTop: 6, background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, padding: "7px 10px", color: "#e2e8f0", fontSize: 11, resize: "vertical", minHeight: 50, outline: "none", fontFamily: "inherit" }} />
                      )}
                    </div>
                  </div>

                  {/* Expanded Details Panel */}
                  {isExpanded && item.details && (
                    <div style={{ borderTop: `1px solid ${item.color}33`, background: "rgba(0,0,0,0.3)" }}>
                      {/* Tab Bar */}
                      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                        {DETAIL_TABS.map((tab) => (
                          <button type="button" key={tab} onClick={() => setActiveTab(tab)}
                            style={{ flex: 1, padding: "8px 4px", border: "none", cursor: "pointer", background: activeTab === tab ? "rgba(255,255,255,0.06)" : "transparent", borderBottom: activeTab === tab ? `2px solid ${TAB_COLORS[tab]}` : "2px solid transparent", color: activeTab === tab ? TAB_COLORS[tab] : "rgba(255,255,255,0.4)", fontSize: 10, fontFamily: "inherit", letterSpacing: 0.5, transition: "all 0.15s" }}>
                            {TAB_LABELS[tab]}
                          </button>
                        ))}
                      </div>

                      {/* Tab Content */}
                      <div style={{ padding: "14px 16px" }}>
                        {activeTab === "overview" && (
                          <p style={{ margin: 0, fontSize: 12, lineHeight: 1.7, color: "rgba(255,255,255,0.75)" }}>{item.details.overview}</p>
                        )}
                        {activeTab === "steps" && (
                          <ol style={{ margin: 0, paddingLeft: 18 }}>
                            {item.details.steps.map((step, i) => (
                              <li key={i} style={{ fontSize: 11, lineHeight: 1.7, color: "rgba(255,255,255,0.75)", marginBottom: 4 }}>
                                {step}
                              </li>
                            ))}
                          </ol>
                        )}
                        {activeTab === "remediation" && (
                          <p style={{ margin: 0, fontSize: 12, lineHeight: 1.7, color: "rgba(255,255,255,0.75)", borderLeft: `3px solid #10b981`, paddingLeft: 12 }}>{item.details.remediation}</p>
                        )}
                        {activeTab === "why" && (
                          <p style={{ margin: 0, fontSize: 12, lineHeight: 1.7, color: "rgba(255,255,255,0.75)", borderLeft: `3px solid #a855f7`, paddingLeft: 12 }}>{item.details.why}</p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", padding: "8px 28px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(0,0,0,0.3)", fontSize: 9, color: "rgba(255,255,255,0.2)", letterSpacing: 1 }}>
        <span>VA/PT SECURITY CHECKLIST - USE FOR AUTHORIZED TESTING ONLY</span>
        <span>{completedItems} / {totalItems} COMPLETED</span>
      </div>
    </div>
  );
}




