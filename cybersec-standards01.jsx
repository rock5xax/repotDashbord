
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DATA
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const standards = [
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // ISO 27001
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "iso27001", short: "ISO 27001", name: "Information Security Management System",
    org: "ISO/IEC", region: "ðŸŒ Global", type: "Certifiable", mandatory: "Voluntary",
    focus: "ISMS", color: "#3b82f6", icon: "ðŸ†", category: "iso",
    overview: "ISO/IEC 27001:2022 is the world's most recognised information security management standard. It gives organisations a systematic framework to manage sensitive information and protect it from threats. The standard follows a Plan-Do-Check-Act (PDCA) cycle and requires organisations to identify risks, select appropriate controls from Annex A, and continually improve their security posture. Certification is issued by accredited third-party bodies after a two-stage audit, and is valid for three years with annual surveillance audits.",
    clauses: [
      { num: "4", title: "Context of Organization", desc: "Understand internal/external issues, stakeholder needs, and define the ISMS scope" },
      { num: "5", title: "Leadership", desc: "Top management commitment, security policy, assigned roles and responsibilities" },
      { num: "6", title: "Planning", desc: "Risk assessment methodology, Statement of Applicability (SoA), risk treatment plan" },
      { num: "7", title: "Support", desc: "Resources, competence, awareness, communication, and documented information" },
      { num: "8", title: "Operation", desc: "Executing risk treatment plans, change management, supplier security" },
      { num: "9", title: "Performance Evaluation", desc: "Internal audit programme, management review, KPIs and metrics" },
      { num: "10", title: "Improvement", desc: "Nonconformity handling, root cause analysis, continual improvement" },
    ],
    controls: "93 Annex A controls (2022) across 4 themes: Organisational (37), People (8), Physical (14), Technological (34)",
    toolkit: [
      { name: "ISMS.online", purpose: "End-to-end ISO 27001 platform: policies, risk register, audits", type: "Paid", url: "https://www.isms.online" },
      { name: "Vanta", purpose: "Automated compliance monitoring and evidence collection", type: "Paid", url: "https://www.vanta.com" },
      { name: "OpenRMF", purpose: "Open-source risk management framework tool", type: "Free", url: "https://github.com/Cingulara/openrmf-docs" },
      { name: "SimpleRisk", purpose: "Open-source GRC platform for risk management", type: "Free", url: "https://www.simplerisk.com" },
      { name: "Eramba", purpose: "Open-source GRC with ISO 27001 templates", type: "Free/Paid", url: "https://www.eramba.org" },
      { name: "Microsoft Compliance Manager", purpose: "ISO 27001 control mapping for Azure environments", type: "Paid", url: "https://compliance.microsoft.com" },
      { name: "ISO 27001 Toolkit (IT Governance)", purpose: "Documentation templates, policies, procedures pack", type: "Paid", url: "https://www.itgovernance.co.uk" },
    ],
    implementation: [
      { phase: 1, title: "Project Initiation & Scoping", duration: "2â€“4 weeks", tasks: ["Get top management buy-in and appoint ISMS project owner", "Define ISMS scope (locations, departments, assets, services)", "Identify interested parties and their requirements", "Establish project plan with milestones and budget", "Conduct initial gap assessment against ISO 27001:2022"] },
      { phase: 2, title: "Risk Assessment", duration: "3â€“6 weeks", tasks: ["Build asset inventory (hardware, software, data, people, processes)", "Identify threats and vulnerabilities for each asset", "Assess likelihood and impact to calculate risk score", "Produce risk register with owner for each risk", "Define risk acceptance criteria and risk appetite"] },
      { phase: 3, title: "Risk Treatment & SoA", duration: "3â€“4 weeks", tasks: ["Select treatment option: accept, mitigate, transfer, avoid", "Map selected controls to ISO 27001 Annex A", "Draft Statement of Applicability (SoA) with justifications", "Develop Risk Treatment Plan (RTP) with owners and deadlines", "Obtain management approval for RTP"] },
      { phase: 4, title: "Control Implementation", duration: "8â€“16 weeks", tasks: ["Implement all applicable Annex A controls", "Write required policies and procedures (access control, incident response, etc.)", "Deploy technical controls (MFA, encryption, patch management)", "Conduct security awareness training for all staff", "Implement supplier security assessment process"] },
      { phase: 5, title: "Internal Audit & Management Review", duration: "2â€“3 weeks", tasks: ["Train/appoint internal auditor (must be independent)", "Conduct internal audit against all clauses 4â€“10", "Record nonconformities and observations", "Conduct management review meeting", "Close nonconformities with corrective actions"] },
      { phase: 6, title: "Certification Audit", duration: "2â€“4 weeks", tasks: ["Select accredited certification body (BSI, Bureau Veritas, DNV, SGS)", "Stage 1 audit: document review and readiness assessment", "Stage 2 audit: on-site verification of implementation", "Close any nonconformities raised by auditor", "Receive ISO 27001 certificate (valid 3 years)"] },
    ],
    industries: [
      { name: "IT/SaaS Startup", icon: "ðŸ’»", priority: "High", plan: "Start with scope limited to core product. Focus on cloud security (27017), access management, and incident response. Use Vanta for automation. Target 6-month implementation." },
      { name: "Banking & Finance", icon: "ðŸ¦", priority: "Critical", plan: "Full ISMS scope covering all branches. Integrate with RBI cybersecurity framework. Focus on segregation of duties, data classification, and 24/7 SOC. 12â€“18 month timeline." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "Critical", plan: "Scope includes all patient data systems. Align with HIPAA safeguards and ISO 27701 for privacy. Focus on medical device security, EHR access controls, audit trails." },
      { name: "Manufacturing", icon: "ðŸ­", priority: "Medium", plan: "Scope IT + OT/ICS systems separately. Focus on physical security, supply chain controls, and IP protection. ISO 27001 + IEC 62443 for OT environments." },
      { name: "E-Commerce/Retail", icon: "ðŸ›’", priority: "High", plan: "Scope covers payment systems (link with PCI-DSS), customer data, and web infrastructure. Focus on access control, secure development, and third-party vendor risk." },
      { name: "Government", icon: "ðŸ›", priority: "Critical", plan: "Full scope across all departments. Align with national cybersecurity frameworks. Focus on classified data handling, privileged access, and business continuity." },
    ],
    usecases: ["Enterprise compliance certification", "Winning enterprise customer contracts", "Cyber insurance premium reduction", "Regulatory compliance foundation", "Vendor/supply chain trust building"],
    related: ["iso27002", "iso27017", "iso27701", "nist-csf"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // ISO 27002
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "iso27002", short: "ISO 27002", name: "Security Controls Implementation Guide",
    org: "ISO/IEC", region: "ðŸŒ Global", type: "Guideline", mandatory: "Voluntary",
    focus: "Control implementation", color: "#60a5fa", icon: "ðŸ“˜", category: "iso",
    overview: "ISO/IEC 27002:2022 is the companion standard to ISO 27001, providing detailed implementation guidance for each of the 93 Annex A controls. It describes the purpose, implementation guidance, and other information for every control â€” making it the go-to reference when writing security policies and procedures. The 2022 edition reorganised controls into 4 themes (down from 14 categories) and introduced 11 new controls including threat intelligence, cloud security, data masking, and secure coding.",
    clauses: [
      { num: "5", title: "Organisational Controls (37)", desc: "Policies, roles, threat intelligence, asset management, supplier relationships, incident management, BCP, compliance" },
      { num: "6", title: "People Controls (8)", desc: "Screening, terms of employment, security awareness, disciplinary process, remote working" },
      { num: "7", title: "Physical Controls (14)", desc: "Physical security perimeters, clean desk, screen, equipment maintenance, secure disposal" },
      { num: "8", title: "Technological Controls (34)", desc: "IAM, endpoint security, cryptography, network security, SIEM, vulnerability management, SDLC security" },
    ],
    controls: "New in 2022: Threat Intelligence (5.7), ICT Readiness for BC (5.30), Physical Security Monitoring (7.4), Configuration Management (8.9), Information Deletion (8.10), Data Masking (8.11), Data Leakage Prevention (8.12), Monitoring Activities (8.16), Web Filtering (8.23), Secure Coding (8.28)",
    toolkit: [
      { name: "ISO 27002 Policy Templates (SANS)", purpose: "Free policy and procedure templates aligned to controls", type: "Free", url: "https://www.sans.org/information-security-policy/" },
      { name: "CIS Benchmarks", purpose: "Technical hardening guides mapping to ISO 27002 technological controls", type: "Free", url: "https://www.cisecurity.org/cis-benchmarks" },
      { name: "OpenSCAP", purpose: "Automated technical control verification for servers/endpoints", type: "Free", url: "https://www.open-scap.org" },
      { name: "IT Governance ISO 27002 Toolkit", purpose: "Full documentation pack: policies, procedures, work instructions", type: "Paid", url: "https://www.itgovernance.co.uk" },
      { name: "Confluence/SharePoint", purpose: "Knowledge management for publishing policies and procedures", type: "Paid", url: "" },
    ],
    implementation: [
      { phase: 1, title: "Control Selection (SoA)", duration: "1â€“2 weeks", tasks: ["Map risk treatment decisions to ISO 27002 controls", "Mark each control as Applicable/Not Applicable in SoA", "Document justification for exclusions", "Assign control owner for each applicable control"] },
      { phase: 2, title: "Policy & Procedure Writing", duration: "4â€“8 weeks", tasks: ["Write Information Security Policy (mandatory)", "Write acceptable use, access control, and data classification policies", "Create operational procedures for each control", "Define metrics/KPIs for each control"] },
      { phase: 3, title: "Technical Implementation", duration: "6â€“12 weeks", tasks: ["Deploy controls mapped to Clause 8 (technological)", "Harden all endpoints to CIS Benchmark baseline", "Implement SIEM, DLP, and vulnerability scanner", "Enforce MFA and privileged access management"] },
      { phase: 4, title: "Verification & Evidence", duration: "2â€“4 weeks", tasks: ["Collect implementation evidence for each control", "Run automated compliance scans (OpenSCAP, Nessus)", "Conduct control effectiveness review", "Update SoA with implementation status"] },
    ],
    industries: [
      { name: "IT/SaaS", icon: "ðŸ’»", priority: "High", plan: "Focus on Clause 8 (technological) controls first â€” IAM, endpoint, cloud config, secure coding. Use automated tooling (OpenSCAP, Vanta) to reduce manual effort." },
      { name: "Professional Services", icon: "ðŸ‘”", priority: "Medium", plan: "Prioritise people controls (Clause 6) and organisational controls for client data handling, NDAs, and third-party access." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "High", plan: "Emphasise data masking (8.11), access control, and monitoring. Map to HIPAA technical safeguards." },
    ],
    usecases: ["Security policy writing reference", "Control implementation guidance", "Internal audit evidence framework", "Secure architecture design"],
    related: ["iso27001", "iso27017"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // ISO 27017
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "iso27017", short: "ISO 27017", name: "Cloud Security Controls",
    org: "ISO/IEC", region: "ðŸŒ Global", type: "Guideline", mandatory: "Voluntary",
    focus: "Cloud security", color: "#93c5fd", icon: "â˜ï¸", category: "iso",
    overview: "ISO/IEC 27017:2015 provides cloud-specific security guidance extending ISO 27001/27002. It addresses the shared responsibility model between Cloud Service Providers (CSPs) and Cloud Service Customers (CSCs), defining who is responsible for what security control. It includes 7 new cloud-specific controls not found in ISO 27002 and adapts 37 existing controls with cloud-specific implementation guidance.",
    clauses: [
      { num: "6.3", title: "Shared Roles in Cloud", desc: "Clarification of responsibilities between CSP and CSC" },
      { num: "8.5", title: "CSC Admin Operations", desc: "Monitoring and managing cloud environments" },
      { num: "9.5.1", title: "Access Control in Cloud", desc: "Virtual machine user access management" },
      { num: "9.5.2", title: "VM Hardening", desc: "Secure configuration and protection of virtual machines" },
      { num: "12.1.5", title: "Admin Activity Monitoring", desc: "Monitoring cloud admin operations for anomalies" },
      { num: "12.4.5", title: "Cloud Monitoring", desc: "Logging and monitoring cloud infrastructure" },
      { num: "13.1.4", title: "Virtual Network Segregation", desc: "Network isolation in multi-tenant cloud environments" },
    ],
    controls: "7 additional controls: CLD.6.3.1 (shared roles), CLD.8.5.1 (segregation in virtual environments), CLD.9.5.1 (VM user access), CLD.9.5.2 (VM hardening), CLD.12.1.5 (admin monitoring), CLD.12.4.5 (cloud monitoring), CLD.13.1.4 (virtual network segregation)",
    toolkit: [
      { name: "AWS Security Hub", purpose: "Centralised security posture management for AWS with ISO 27017 checks", type: "Paid", url: "https://aws.amazon.com/security-hub" },
      { name: "Microsoft Defender for Cloud", purpose: "Cloud security posture for Azure/multi-cloud with compliance dashboard", type: "Paid", url: "https://azure.microsoft.com/en-us/products/defender-for-cloud" },
      { name: "Google Security Command Center", purpose: "GCP security posture management and misconfiguration detection", type: "Paid", url: "https://cloud.google.com/security-command-center" },
      { name: "Prowler", purpose: "Open-source AWS/GCP/Azure security assessments against best practices", type: "Free", url: "https://github.com/prowler-cloud/prowler" },
      { name: "ScoutSuite", purpose: "Multi-cloud security auditing tool for AWS, Azure, GCP", type: "Free", url: "https://github.com/nccgroup/ScoutSuite" },
      { name: "CloudSploit", purpose: "Open-source cloud security configuration scanner", type: "Free", url: "https://github.com/aquasecurity/cloudsploit" },
    ],
    implementation: [
      { phase: 1, title: "Cloud Inventory & RACI", duration: "1â€“2 weeks", tasks: ["List all cloud services and providers (AWS, Azure, GCP)", "Build RACI matrix for each service: CSP vs CSC responsibilities", "Review CSP compliance certifications (SOC 2, ISO 27017)", "Identify where CSC must implement additional controls"] },
      { phase: 2, title: "Cloud Security Baseline", duration: "3â€“6 weeks", tasks: ["Enable cloud security posture management (CSPM) tool", "Implement CIS Benchmark hardening for all cloud services", "Enable comprehensive logging (CloudTrail, Azure Monitor, Cloud Audit Logs)", "Configure network security groups and virtual network isolation"] },
      { phase: 3, title: "VM & Container Security", duration: "2â€“4 weeks", tasks: ["Define approved VM/container image baseline", "Implement image scanning in CI/CD pipeline", "Enforce privileged access management for cloud admins", "Implement just-in-time (JIT) access for VMs"] },
      { phase: 4, title: "Ongoing Monitoring", duration: "Continuous", tasks: ["Daily automated CSPM scans with alerting", "Monthly cloud security review against ISO 27017 controls", "Quarterly review of CSP shared responsibility mapping", "Annual cloud penetration test"] },
    ],
    industries: [
      { name: "SaaS/Cloud Native", icon: "â˜ï¸", priority: "Critical", plan: "ISO 27017 is the primary framework. Implement CSPM from day 1. Use Prowler for continuous assessment. Every engineer trained on cloud security basics." },
      { name: "Banking", icon: "ðŸ¦", priority: "High", plan: "Apply to all cloud workloads. Integrate with RBI cloud guidelines. Maintain data residency requirements. Implement cloud SOC monitoring." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "Critical", plan: "Focus on patient data isolation in multi-tenant environments. Enforce encryption at rest and in transit. HIPAA-compliant cloud regions only." },
    ],
    usecases: ["Multi-cloud security governance", "Cloud VAPT scope definition", "CSP contract security requirements", "Cloud architecture design"],
    related: ["iso27001", "iso27002", "iso27018"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // OWASP Top 10
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "owasp-top10", short: "OWASP Top 10", name: "Web Application Security Risks",
    org: "OWASP", region: "ðŸŒ Global", type: "Best Practice", mandatory: "No",
    focus: "Web app security", color: "#f97316", icon: "ðŸ”¥", category: "owasp",
    overview: "The OWASP Top 10 (2021 edition) is the most widely referenced web application security standard. Updated every 3â€“4 years based on data from hundreds of organisations and thousands of applications, it represents the consensus view of the most critical web security risks. Each risk includes CVE examples, attack scenarios, prevention techniques, and mapping to CWEs. It is referenced in PCI-DSS Requirement 6, ISO 27001, and most enterprise security policies.",
    clauses: [
      { num: "A01:2021", title: "Broken Access Control", desc: "94% of applications tested. IDOR, privilege escalation, CORS misconfig, missing function-level authorisation" },
      { num: "A02:2021", title: "Cryptographic Failures", desc: "Data transmitted in cleartext, weak crypto algorithms, improper key management, missing HTTPS" },
      { num: "A03:2021", title: "Injection", desc: "SQL, NoSQL, OS, LDAP injection. Hostile data sent as part of a command or query. Includes XSS" },
      { num: "A04:2021", title: "Insecure Design", desc: "New 2021 category. Missing security controls at design phase, threat modelling gaps, insecure design patterns" },
      { num: "A05:2021", title: "Security Misconfiguration", desc: "89% of apps tested. Default credentials, unnecessary features, verbose errors, cloud misconfigs, missing headers" },
      { num: "A06:2021", title: "Vulnerable & Outdated Components", desc: "Libraries, frameworks, OS with known CVEs. No software composition analysis in SDLC" },
      { num: "A07:2021", title: "ID & Authentication Failures", desc: "Weak passwords, no MFA, exposed session tokens, broken credential recovery, credential stuffing" },
      { num: "A08:2021", title: "Software & Data Integrity Failures", desc: "Insecure deserialization, CI/CD pipeline integrity, unsigned software updates, SolarWinds-style supply chain" },
      { num: "A09:2021", title: "Security Logging Failures", desc: "No audit trail, insufficient log detail, logs not monitored, no alerting on security events" },
      { num: "A10:2021", title: "Server-Side Request Forgery (SSRF)", desc: "Server makes requests to attacker-controlled URLs. Critical in cloud environments (metadata API access)" },
    ],
    controls: "Each risk includes: CWE mappings, example attack scenarios, verification requirements, and specific prevention techniques by technology stack",
    toolkit: [
      { name: "Burp Suite Professional", purpose: "Web app VAPT â€” scanner, proxy, intruder, repeater. Gold standard", type: "Paid", url: "https://portswigger.net/burp" },
      { name: "Burp Suite Community", purpose: "Free version â€” manual testing proxy, essential for every pentester", type: "Free", url: "https://portswigger.net/burp/communitydownload" },
      { name: "OWASP ZAP", purpose: "Open-source DAST scanner, CI/CD integration, good for automation", type: "Free", url: "https://www.zaproxy.org" },
      { name: "Nikto", purpose: "Web server scanner for misconfigurations and outdated software", type: "Free", url: "https://github.com/sullo/nikto" },
      { name: "SQLMap", purpose: "Automated SQL injection detection and exploitation", type: "Free", url: "https://sqlmap.org" },
      { name: "Semgrep", purpose: "SAST â€” static code analysis for OWASP Top 10 patterns in source code", type: "Free/Paid", url: "https://semgrep.dev" },
      { name: "Snyk", purpose: "SCA â€” dependency vulnerability scanning (A06) in CI/CD", type: "Free/Paid", url: "https://snyk.io" },
      { name: "OWASP Dependency-Check", purpose: "Open-source SCA for known vulnerable components", type: "Free", url: "https://owasp.org/www-project-dependency-check/" },
      { name: "XSStrike", purpose: "Advanced XSS detection and exploitation framework", type: "Free", url: "https://github.com/s0md3v/XSStrike" },
    ],
    implementation: [
      { phase: 1, title: "Threat Modelling & Scope", duration: "1â€“2 weeks", tasks: ["Map all application entry points (APIs, forms, file uploads, headers)", "Prioritise components by data sensitivity and user exposure", "Create data flow diagrams (DFDs) for threat modelling (STRIDE)", "Define OWASP testing scope for current sprint/release"] },
      { phase: 2, title: "SAST Integration (Shift Left)", duration: "1â€“2 weeks", tasks: ["Integrate Semgrep or Checkmarx into CI/CD pipeline", "Configure rules for OWASP Top 10 patterns", "Set pipeline to fail on Critical/High findings", "Train developers on reading and fixing SAST findings"] },
      { phase: 3, title: "SCA â€” Dependency Scanning", duration: "1 week", tasks: ["Integrate Snyk or OWASP Dependency-Check into build pipeline", "Establish SLA for patching vulnerable dependencies: Critical 24h, High 7d", "Maintain approved library whitelist", "Subscribe to CVE feeds for used frameworks"] },
      { phase: 4, title: "DAST â€” Dynamic Testing", duration: "2â€“4 weeks per release", tasks: ["Run OWASP ZAP baseline scan on staging environment", "Manual testing with Burp Suite for business logic and auth flaws", "Test each OWASP Top 10 category per the Testing Guide", "Document all findings with CVSS scores and PoC"] },
      { phase: 5, title: "Remediation & Verification", duration: "1â€“3 weeks", tasks: ["Assign findings to developers with specific fix guidance", "Re-test all fixed findings with original tool and manual confirmation", "Update security acceptance criteria for future releases", "Conduct developer training on most common findings"] },
    ],
    industries: [
      { name: "FinTech/Banking", icon: "ðŸ¦", priority: "Critical", plan: "Full OWASP Top 10 assessment before every major release. Focus on A01 (access control for transactions), A02 (encryption), A07 (authentication). PCI-DSS requires DAST annually." },
      { name: "Healthcare/MedTech", icon: "ðŸ¥", priority: "Critical", plan: "Prioritise A01 (patient record access), A02 (PHI encryption), A09 (audit logging for HIPAA). Assess all APIs that handle ePHI." },
      { name: "E-Commerce", icon: "ðŸ›’", priority: "High", plan: "Focus on A02 (payment data), A01 (order/account IDOR), A07 (account takeover). PCI-DSS mandates web app scan or WAF." },
      { name: "SaaS B2B", icon: "ðŸ’¼", priority: "High", plan: "Prioritise A01 (tenant isolation), A08 (CI/CD integrity), A06 (dependency management). SOC 2 customers will ask for pentest reports." },
      { name: "Government/Education", icon: "ðŸ›", priority: "Medium", plan: "Focus on A05 (misconfiguration), A07 (authentication), A09 (logging). Comply with CERT-In reporting requirements for incidents." },
    ],
    usecases: ["VAPT report baseline", "Bug bounty scope definition", "Developer security training", "Security acceptance criteria for SDLC", "WAF rule configuration"],
    related: ["owasp-asvs", "owasp-mobile", "nist-csf", "iso27001"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // OWASP ASVS
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "owasp-asvs", short: "OWASP ASVS", name: "Application Security Verification Standard",
    org: "OWASP", region: "ðŸŒ Global", type: "Best Practice", mandatory: "No",
    focus: "Secure SDLC", color: "#fb923c", icon: "ðŸ”", category: "owasp",
    overview: "OWASP ASVS v4.0 provides a comprehensive catalogue of security requirements and controls (286 requirements) for building and testing secure web applications. It defines three verification levels allowing teams to adopt security requirements proportional to their risk profile. ASVS maps every requirement to CWEs, OWASP Top 10, and NIST 800-63, making it an excellent tool for setting security acceptance criteria in Agile SDLC.",
    clauses: [
      { num: "V1", title: "Architecture & Design", desc: "Secure design principles, threat modelling, network segmentation" },
      { num: "V2", title: "Authentication", desc: "Password security, credential recovery, MFA, authentication protocols" },
      { num: "V3", title: "Session Management", desc: "Session token security, binding, cookie attributes, session termination" },
      { num: "V4", title: "Access Control", desc: "Least privilege, deny by default, RBAC, path traversal" },
      { num: "V5", title: "Validation, Sanitisation & Encoding", desc: "Input validation, output encoding, injection prevention" },
      { num: "V6", title: "Stored Cryptography", desc: "Algorithms, key management, random values, certificate management" },
      { num: "V7", title: "Error Handling & Logging", desc: "Error messages, audit log content, log integrity" },
      { num: "V8", title: "Data Protection", desc: "Data classification, client-side data exposure, sensitive data in transit" },
      { num: "V9", title: "Communications Security", desc: "Transport layer security, network config, pinning" },
      { num: "V10", title: "Malicious Code", desc: "Backdoors, integrity, anti-automation, memory safety" },
      { num: "V11", title: "Business Logic", desc: "Logic flow, rate limiting, anti-automation, workflow security" },
      { num: "V12", title: "Files & Resources", desc: "File upload security, path traversal, SSRF prevention" },
      { num: "V13", title: "API & Web Services", desc: "REST/GraphQL/SOAP security, API gateway, service authentication" },
      { num: "V14", title: "Configuration", desc: "Build pipeline security, dependency management, HTTP security headers" },
    ],
    controls: "L1: 117 requirements (pen-test verifiable) | L2: 196 requirements (design + code review needed) | L3: 286 requirements (formal verification for critical apps)",
    toolkit: [
      { name: "OWASP ASVS Excel Tracker", purpose: "Official ASVS spreadsheet for tracking compliance level per requirement", type: "Free", url: "https://github.com/OWASP/ASVS" },
      { name: "Burp Suite Pro", purpose: "Verify L1 requirements through automated + manual web testing", type: "Paid", url: "https://portswigger.net/burp" },
      { name: "Checkmarx SAST", purpose: "Static analysis mapping to ASVS requirements in source code", type: "Paid", url: "https://checkmarx.com" },
      { name: "Veracode", purpose: "Cloud-based SAST/DAST with ASVS reporting", type: "Paid", url: "https://www.veracode.com" },
      { name: "testssl.sh", purpose: "Verify V9 TLS/transport security requirements", type: "Free", url: "https://testssl.sh" },
      { name: "OWASP SAMM", purpose: "Software Assurance Maturity Model â€” complements ASVS for programme-level", type: "Free", url: "https://owaspsamm.org" },
    ],
    implementation: [
      { phase: 1, title: "Level Selection & Scope", duration: "1 week", tasks: ["Map applications to ASVS levels: L1 (all), L2 (apps with sensitive data), L3 (banking, healthcare, critical)", "Import ASVS Excel tracker and assign owners per chapter", "Define verification methods: automated scan, manual test, code review"] },
      { phase: 2, title: "L1 â€” Automated Baseline", duration: "2â€“3 weeks", tasks: ["Run DAST scan (OWASP ZAP / Burp) against all L1 requirements", "Verify HTTP security headers (V14)", "Confirm TLS configuration (V9)", "Check for verbose error messages and information disclosure"] },
      { phase: 3, title: "L2 â€” Code & Design Review", duration: "3â€“6 weeks per app", tasks: ["Conduct source code review for V2 (auth), V4 (access control), V5 (validation)", "Review session management implementation (V3)", "Audit logging and error handling (V7)", "Test API security requirements (V13)"] },
      { phase: 4, title: "Remediation & Regression", duration: "Ongoing", tasks: ["Integrate ASVS requirements as Definition of Done in Jira/Scrum", "Add ASVS check to PR review process", "Conduct quarterly ASVS re-assessment for critical applications", "Track compliance percentage trend over releases"] },
    ],
    industries: [
      { name: "FinTech", icon: "ðŸ’³", priority: "Critical", plan: "All banking apps at L3. Payment flows at minimum L2. Include ASVS V6 (crypto) for all financial calculations. Required for RBI and PCI compliance." },
      { name: "Healthcare SaaS", icon: "ðŸ¥", priority: "Critical", plan: "L2 minimum for all PHI-handling apps, L3 for EHR platforms. Map V8 (data protection) to HIPAA technical safeguards." },
      { name: "Enterprise B2B SaaS", icon: "ðŸ¢", priority: "High", plan: "L2 across the board. Publish ASVS compliance status in security documentation for enterprise customers. SOC 2 customers require this." },
    ],
    usecases: ["Security acceptance criteria in Agile sprints", "Penetration test scope and success criteria", "Third-party application assessment", "Secure code review framework"],
    related: ["owasp-top10", "owasp-mobile"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // OWASP Mobile Top 10
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "owasp-mobile", short: "OWASP Mobile Top 10", name: "Mobile Application Security Risks",
    org: "OWASP", region: "ðŸŒ Global", type: "Best Practice", mandatory: "No",
    focus: "Mobile security", color: "#fdba74", icon: "ðŸ“±", category: "owasp",
    overview: "The OWASP Mobile Top 10 (2024 edition) identifies the 10 most critical mobile application security risks for both Android and iOS. It is the mobile equivalent of the OWASP Top 10 and forms the foundation of any mobile application penetration test. The 2024 edition reflects modern threats including supply chain, privacy concerns, and binary protection gaps.",
    clauses: [
      { num: "M1:2024", title: "Improper Credential Usage", desc: "Hardcoded credentials, insecure credential transmission, weak storage" },
      { num: "M2:2024", title: "Inadequate Supply Chain Security", desc: "Third-party SDKs with malicious code or vulnerabilities, build process tampering" },
      { num: "M3:2024", title: "Insecure Auth & Authorization", desc: "Client-side auth checks, broken session management, insecure deep links" },
      { num: "M4:2024", title: "Insufficient Input/Output Validation", desc: "SQL injection via content providers, JavaScript injection in WebViews" },
      { num: "M5:2024", title: "Insecure Communication", desc: "HTTP traffic, invalid certificate validation, missing certificate pinning" },
      { num: "M6:2024", title: "Inadequate Privacy Controls", desc: "Excessive data collection, third-party tracking, missing privacy disclosures" },
      { num: "M7:2024", title: "Insufficient Binary Protections", desc: "Lack of obfuscation, anti-debugging, root/jailbreak detection, anti-tampering" },
      { num: "M8:2024", title: "Security Misconfiguration", desc: "Backup enabled, debug flags, exported components without permissions" },
      { num: "M9:2024", title: "Insecure Data Storage", desc: "SharedPreferences/NSUserDefaults with PII, unencrypted SQLite, Keychain misuse" },
      { num: "M10:2024", title: "Insufficient Cryptography", desc: "Weak algorithms (MD5, SHA1), hardcoded keys, ECB mode, improper key storage" },
    ],
    controls: "Prevention guidance provided for both Android and iOS per risk, including platform-specific API recommendations and configuration settings",
    toolkit: [
      { name: "MobSF (Mobile Security Framework)", purpose: "All-in-one mobile VAPT platform â€” static + dynamic analysis for Android/iOS", type: "Free", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF" },
      { name: "Frida", purpose: "Dynamic instrumentation â€” hook methods, bypass security controls at runtime", type: "Free", url: "https://frida.re" },
      { name: "Objection", purpose: "Frida-based mobile exploration â€” SSL pinning bypass, runtime manipulation", type: "Free", url: "https://github.com/sensepost/objection" },
      { name: "jadx", purpose: "Android APK decompiler â€” recover Java/Kotlin source code from APK", type: "Free", url: "https://github.com/skylot/jadx" },
      { name: "apktool", purpose: "APK reverse engineering â€” decode resources, repackage, smali analysis", type: "Free", url: "https://apktool.org" },
      { name: "Drozer", purpose: "Android security assessment framework â€” content providers, intents, activities", type: "Free", url: "https://github.com/WithSecureLabs/drozer" },
      { name: "Needle", purpose: "iOS security testing framework â€” binary analysis, runtime manipulation", type: "Free", url: "https://github.com/WithSecureLabs/needle" },
      { name: "Checkra1n / Unc0ver", purpose: "iOS jailbreak tools for setting up iOS test environment", type: "Free", url: "" },
      { name: "Android Studio Emulator", purpose: "Android test environment with root access for security testing", type: "Free", url: "https://developer.android.com/studio" },
    ],
    implementation: [
      { phase: 1, title: "Static Analysis (SAST)", duration: "1â€“2 weeks", tasks: ["Decompile APK with jadx and apktool", "Run MobSF automated static analysis", "Review AndroidManifest.xml for exported components and permissions", "Search for hardcoded secrets: API keys, credentials, certificates", "Analyse network_security_config.xml and SSL configuration"] },
      { phase: 2, title: "Dynamic Analysis (DAST)", duration: "1â€“2 weeks", tasks: ["Set up test device (rooted Android / jailbroken iOS)", "Bypass SSL pinning with Objection: android sslpinning disable", "Proxy all traffic through Burp Suite", "Test authentication flows, session management, deep links", "Use Frida to hook sensitive methods and extract runtime data"] },
      { phase: 3, title: "Platform-Specific Testing", duration: "1 week", tasks: ["Android: Test content providers, broadcast receivers, intent injection", "iOS: Test Keychain storage, URL schemes, ATS configuration", "Test backup restoration attack (android:allowBackup)", "Test root/jailbreak detection bypass", "Test for clipboard data leakage"] },
      { phase: 4, title: "Remediation & SDLC Integration", duration: "Ongoing", tasks: ["Integrate MobSF into CI/CD pipeline for every build", "Add ProGuard/R8 obfuscation to release build", "Implement Play Integrity API / DeviceCheck for integrity attestation", "Add secrets scanning to git pre-commit hooks"] },
    ],
    industries: [
      { name: "FinTech/Banking Apps", icon: "ðŸ’³", priority: "Critical", plan: "All 10 risks apply at maximum severity. Mandatory VAPT before App Store submission. Focus on M9 (data storage), M5 (communication), M7 (binary protection). Integrate with RBI mobile banking guidelines." },
      { name: "Healthcare Apps", icon: "ðŸ¥", priority: "Critical", plan: "M9 (patient data), M6 (privacy), M3 (auth). All apps handling PHI require HIPAA-aligned mobile assessment. Encrypt all local storage." },
      { name: "Retail/E-Commerce", icon: "ðŸ›’", priority: "High", plan: "M1 (payment credentials), M5 (communication), M3 (account security). Annual VAPT required for PCI-DSS compliance of mobile payment flows." },
      { name: "Gaming Apps", icon: "ðŸŽ®", priority: "Medium", plan: "M1 (in-app purchase credentials), M3 (score/rank manipulation), M7 (cheat prevention). Focus on anti-tampering and binary protection." },
    ],
    usecases: ["Android/iOS VAPT scope definition", "Secure mobile SDLC checklist", "App store security review preparation", "Mobile security training for developers"],
    related: ["owasp-top10", "owasp-asvs"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // NIST CSF
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "nist-csf", short: "NIST CSF 2.0", name: "Cybersecurity Framework",
    org: "NIST", region: "ðŸ‡ºðŸ‡¸ US (Global Adoption)", type: "Framework", mandatory: "Voluntary",
    focus: "Risk management", color: "#22c55e", icon: "ðŸ›", category: "nist",
    overview: "NIST CSF 2.0 (released February 2024) is a risk-based cybersecurity framework designed for organisations of all sizes and sectors. It adds the GOVERN function (making 6 total), emphasises supply chain risk, and makes the framework more accessible to SMEs. Unlike ISO 27001, CSF does not require certification â€” it is a management tool for measuring and improving cybersecurity posture. It maps to hundreds of other standards including ISO 27001, NIST 800-53, CIS Controls, and COBIT.",
    clauses: [
      { num: "GV", title: "GOVERN (NEW in 2.0)", desc: "Organisational context, cybersecurity risk strategy, supply chain risk management, policies, oversight" },
      { num: "ID", title: "IDENTIFY", desc: "Asset management, risk assessment, improvement activities, business environment understanding" },
      { num: "PR", title: "PROTECT", desc: "Identity management, data security, training, platform security, technology infrastructure resilience" },
      { num: "DE", title: "DETECT", desc: "Continuous monitoring, adverse event analysis, detection process effectiveness" },
      { num: "RS", title: "RESPOND", desc: "Incident management, analysis, mitigation, communication, improvements" },
      { num: "RC", title: "RECOVER", desc: "Recovery planning, improvements, communication during recovery events" },
    ],
    controls: "Framework Core with 6 Functions, 22 Categories, and 106 Subcategories. Profiles allow customisation. Implementation Tiers (1-4) measure maturity. CSF 2.0 Quick Start Guides available for SMEs.",
    toolkit: [
      { name: "NIST CSF 2.0 Reference Tool", purpose: "Official NIST tool for exploring and mapping CSF subcategories", type: "Free", url: "https://www.nist.gov/cyberframework" },
      { name: "CISA Cyber Resilience Review", purpose: "Free assessment based on NIST CSF for critical infrastructure", type: "Free", url: "https://www.cisa.gov/cyber-resilience-review" },
      { name: "RSA Archer GRC", purpose: "Enterprise GRC platform with NIST CSF mapping and reporting", type: "Paid", url: "https://www.archerirm.com" },
      { name: "ServiceNow GRC", purpose: "Integrated GRC with NIST CSF continuous control monitoring", type: "Paid", url: "https://www.servicenow.com/products/governance-risk-and-compliance.html" },
      { name: "NIST CSF Excel Workbook", purpose: "Free official Excel tool for conducting CSF assessments", type: "Free", url: "https://www.nist.gov/cyberframework/csf-20-supporting-documents" },
      { name: "Axio360", purpose: "CSF-based cyber risk quantification and board reporting platform", type: "Paid", url: "https://axio.com" },
    ],
    implementation: [
      { phase: 1, title: "Current State Profile", duration: "2â€“4 weeks", tasks: ["Download NIST CSF 2.0 Excel workbook", "Rate current state for each subcategory (Tier 1â€“4)", "Identify critical business functions and their dependencies", "Review existing policies and map to CSF subcategories", "Present Current State Profile to leadership"] },
      { phase: 2, title: "Target State Profile", duration: "1â€“2 weeks", tasks: ["Define target maturity tier per function based on risk appetite", "Prioritise gaps between current and target state", "Align target profile with regulatory requirements (PCI, HIPAA, CERT-In)", "Estimate resource investment required for each gap"] },
      { phase: 3, title: "Gap Analysis & Roadmap", duration: "2â€“3 weeks", tasks: ["Produce gap analysis report with priority and effort matrix", "Create 12â€“24 month security roadmap", "Map roadmap items to specific NIST 800-53 controls for implementation detail", "Present to board/management for budget approval"] },
      { phase: 4, title: "Implementation & Measurement", duration: "12â€“24 months", tasks: ["Implement controls per roadmap priority", "Track KPIs for each CSF subcategory monthly", "Annual CSF assessment to measure progress", "Report to board using CSF dashboard (Current vs Target tier)"] },
    ],
    industries: [
      { name: "Critical Infrastructure", icon: "âš¡", priority: "Critical", plan: "NIST CSF was designed for this sector. Map GOVERN function to CISA guidelines. Prioritise IDENTIFY and PROTECT for ICS/SCADA environments. Use Tiers 3â€“4." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "High", plan: "Map CSF to HIPAA Security Rule categories. Focus on PROTECT (PHI security), DETECT (breach detection), and RESPOND (breach notification within 60 days)." },
      { name: "SME/Startup", icon: "ðŸš€", priority: "Medium", plan: "Use CSF Quick Start Guide for SMEs. Start with Tier 1 across all functions and target Tier 2 in 12 months. Focus PROTECT and IDENTIFY first." },
      { name: "Financial Services", icon: "ðŸ¦", priority: "High", plan: "Map to FFIEC Cybersecurity Assessment Tool (CAT). Align GOVERN function with board-level reporting. Use CSF for SWIFT CSCF mapping." },
    ],
    usecases: ["Executive cybersecurity risk communication", "Board-level security reporting", "Security programme gap assessment", "Vendor/supply chain risk scoring"],
    related: ["nist-800-53", "nist-800-61", "iso27001", "cis"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // NIST 800-53
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "nist-800-53", short: "NIST SP 800-53", name: "Security & Privacy Controls",
    org: "NIST", region: "ðŸ‡ºðŸ‡¸ US Federal", type: "Control Catalog", mandatory: "Mandatory (Federal)",
    focus: "Federal system controls", color: "#4ade80", icon: "ðŸ“˜", category: "nist",
    overview: "NIST SP 800-53 Rev 5 is the most comprehensive security and privacy control catalogue in existence with 1,000+ controls across 20 families. Mandatory for all US federal agencies and contractors under FISMA. Rev 5 integrates privacy controls directly (previously separate in SP 800-53B), added supply chain risk management (SCRM), and updated controls for cloud, mobile, and AI systems. It forms the basis of FedRAMP, CMMC, and FISMA compliance.",
    clauses: [
      { num: "AC", title: "Access Control (20)", desc: "Account management, access enforcement, least privilege, remote access, wireless access" },
      { num: "AT", title: "Awareness & Training (6)", desc: "Security awareness, role-based training, insider threat awareness" },
      { num: "AU", title: "Audit & Accountability (16)", desc: "Audit events, log content, log protection, audit review, timestamps" },
      { num: "CA", title: "Assessment, Authorization & Monitoring (9)", desc: "System assessment, penetration testing, ATO process, continuous monitoring" },
      { num: "CM", title: "Configuration Management (14)", desc: "Baseline config, configuration change control, software usage restrictions, user-installed software" },
      { num: "CP", title: "Contingency Planning (13)", desc: "BCP, BIA, backup, recovery, alternate processing sites" },
      { num: "IA", title: "Identification & Authentication (13)", desc: "User/device auth, authenticator management, MFA, PKI" },
      { num: "IR", title: "Incident Response (10)", desc: "IR policy, training, testing, handling, monitoring, reporting" },
      { num: "MA", title: "Maintenance (6)", desc: "Controlled maintenance, maintenance tools, remote maintenance" },
      { num: "MP", title: "Media Protection (8)", desc: "Media access, marking, storage, transport, sanitisation, destruction" },
      { num: "PE", title: "Physical & Environmental (23)", desc: "Physical access authorisation, monitoring, visitor control, emergency power" },
      { num: "PL", title: "Planning (11)", desc: "System security plan, rules of behaviour, privacy plan" },
      { num: "PM", title: "Programme Management (32)", desc: "Information security programme plan, risk management strategy, SCRM" },
      { num: "PS", title: "Personnel Security (9)", desc: "Position risk designation, screening, termination, transfer, sanctions" },
      { num: "PT", title: "PII Processing & Transparency (8)", desc: "Authority, purpose specification, information sharing" },
      { num: "RA", title: "Risk Assessment (10)", desc: "Risk assessment policy, risk assessment, vulnerability monitoring, criticality analysis" },
      { num: "SA", title: "System & Services Acquisition (23)", desc: "Secure SDLC, developer security testing, supply chain, developer training" },
      { num: "SC", title: "System & Comms Protection (51)", desc: "Network segmentation, cryptographic protection, denial of service, boundary protection" },
      { num: "SI", title: "System & Information Integrity (23)", desc: "Flaw remediation, malware protection, security alerts, spam protection, memory protection" },
      { num: "SR", title: "Supply Chain Risk Management (12)", desc: "Supply chain risk plan, acquisition, component authenticity, tamper resistance" },
    ],
    controls: "Impact baselines: Low (125 controls), Moderate (325 controls), High (422 controls). Rev 5 adds 66 new controls focused on supply chain, privacy, and cyber-physical systems",
    toolkit: [
      { name: "OpenSCAP / SCAP Workbench", purpose: "Automated NIST 800-53 control verification for Linux/Windows systems", type: "Free", url: "https://www.open-scap.org" },
      { name: "Tenable.sc / Nessus", purpose: "Vulnerability scanning with 800-53 compliance plugin reporting", type: "Paid", url: "https://www.tenable.com" },
      { name: "IBM OpenPages GRC", purpose: "Enterprise GRC platform for 800-53 control management", type: "Paid", url: "https://www.ibm.com/products/openpages-with-watson" },
      { name: "NIST 800-53 Control Navigator", purpose: "Official NIST tool for browsing, filtering and exporting controls", type: "Free", url: "https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/controls" },
      { name: "FedRAMP Marketplace", purpose: "Pre-authorised cloud services meeting 800-53 Moderate/High baseline", type: "Free", url: "https://marketplace.fedramp.gov" },
    ],
    implementation: [
      { phase: 1, title: "System Categorisation", duration: "1â€“2 weeks", tasks: ["Determine system impact level: Low/Moderate/High per FIPS 199", "Document system boundary and interconnections", "Identify authorised users and data types processed", "Select applicable control baseline"] },
      { phase: 2, title: "Control Selection & Tailoring", duration: "2â€“4 weeks", tasks: ["Start with NIST 800-53B baseline for selected impact level", "Apply organisation-defined parameters (ODPs) for each control", "Add overlay controls for specific environments (cloud, healthcare)", "Document tailoring rationale in System Security Plan (SSP)"] },
      { phase: 3, title: "Control Implementation", duration: "3â€“12 months", tasks: ["Implement all selected controls and document in SSP", "Assign control owners and evidence collectors", "Implement technical controls with configuration documentation", "Implement procedural controls with policy documentation"] },
      { phase: 4, title: "Assessment & Authorisation (ATO)", duration: "2â€“4 months", tasks: ["Engage Security Assessment Organisation (SAO) / 3PAO", "Conduct Security Assessment per SP 800-53A", "Address findings in Plan of Action & Milestones (POA&M)", "Submit to Authorizing Official (AO) for Authority to Operate"] },
    ],
    industries: [
      { name: "US Federal Agencies", icon: "ðŸ¦…", priority: "Mandatory", plan: "Full FISMA compliance required. Select Moderate or High baseline per FIPS 199. Annual assessment, continuous monitoring (ConMon), and ATO renewal every 3 years." },
      { name: "Defence Contractors", icon: "ðŸª–", priority: "Critical", plan: "CMMC Level 2/3 is directly derived from NIST 800-53 and 800-171. Required to win DoD contracts. Engage C3PAO for assessment." },
      { name: "Healthcare (FedRAMP Cloud)", icon: "ðŸ¥", priority: "High", plan: "Healthcare clouds serving federal customers need FedRAMP authorisation. Map to HIPAA + 800-53 Moderate baseline." },
    ],
    usecases: ["FedRAMP authorisation", "FISMA compliance", "CMMC Level 2/3 compliance", "Federal contract requirements"],
    related: ["nist-csf", "nist-800-61"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // NIST 800-61
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "nist-800-61", short: "NIST SP 800-61", name: "Incident Response Guide",
    org: "NIST", region: "ðŸ‡ºðŸ‡¸ US (Global Reference)", type: "Guideline", mandatory: "Voluntary",
    focus: "Incident response", color: "#86efac", icon: "ðŸ“—", category: "nist",
    overview: "NIST SP 800-61 Rev 2 is the definitive reference for building and operating an incident response programme. It covers the complete incident lifecycle, team structures, escalation procedures, evidence handling, and coordination with external parties (law enforcement, CERT). The four-phase IR lifecycle defined in this document (Preparation â†’ Detection â†’ Containment â†’ Recovery â†’ Post-Incident) has become the industry standard and is referenced by ISO 27001, SOC 2, PCI-DSS, and every SIEM playbook framework.",
    clauses: [
      { num: "Phase 1", title: "Preparation", desc: "IR policy, team structure (CSIRT), communication plans, tools, training, tabletop exercises, contact lists" },
      { num: "Phase 2", title: "Detection & Analysis", desc: "Precursor/indicator identification, incident prioritisation, triage, documentation, evidence collection" },
      { num: "Phase 3", title: "Containment, Eradication & Recovery", desc: "Short/long-term containment, system rebuilding, evidence preservation, removing malware, restoring services" },
      { num: "Phase 4", title: "Post-Incident Activity", desc: "Lessons learned meeting, evidence retention, metrics, process improvement, updating IR runbooks" },
    ],
    controls: "Incident categories: DoS, Malicious Code, Unauthorized Access, Inappropriate Usage, Multiple Component. Severity levels, escalation timelines, and CSIRT operating models (internal, outsourced, hybrid)",
    toolkit: [
      { name: "TheHive", purpose: "Open-source SOAR platform for incident case management and orchestration", type: "Free", url: "https://thehive-project.org" },
      { name: "Cortex XSOAR (Palo Alto)", purpose: "Enterprise SOAR with 900+ playbook integrations", type: "Paid", url: "https://www.paloaltonetworks.com/cortex/xsoar" },
      { name: "Splunk SIEM", purpose: "Log aggregation, correlation rules, and incident alerting", type: "Paid", url: "https://www.splunk.com" },
      { name: "Elastic SIEM", purpose: "Open-source SIEM with detection rules and timeline investigation", type: "Free/Paid", url: "https://www.elastic.co/security/siem" },
      { name: "Velociraptor", purpose: "Open-source DFIR tool for endpoint forensics and hunt operations", type: "Free", url: "https://www.velocidex.com" },
      { name: "Volatility", purpose: "Memory forensics framework for malware analysis during incidents", type: "Free", url: "https://www.volatilityfoundation.org" },
      { name: "MISP", purpose: "Threat intelligence platform for sharing IOCs during/after incidents", type: "Free", url: "https://www.misp-project.org" },
      { name: "IR Playbook Templates (PagerDuty)", purpose: "Free IR playbook templates for common incident types", type: "Free", url: "https://response.pagerduty.com" },
    ],
    implementation: [
      { phase: 1, title: "Build IR Capability", duration: "4â€“8 weeks", tasks: ["Write IR Policy approved by management", "Define CSIRT team structure and escalation matrix", "Create incident classification and severity matrix (P1â€“P4)", "Set up SIEM for centralised log collection", "Implement SOAR platform (TheHive or XSOAR)"] },
      { phase: 2, title: "Playbook Development", duration: "4â€“6 weeks", tasks: ["Write playbooks for top 10 incident types: ransomware, data breach, phishing, DDoS, insider threat", "Define containment decision trees per incident type", "Create evidence collection checklists (chain of custody)", "Document external contact list: CERT-In, ISP, law enforcement, legal counsel", "Define communication templates (internal, customer, regulatory)"] },
      { phase: 3, title: "Testing & Training", duration: "2â€“4 weeks", tasks: ["Conduct tabletop exercise with leadership team", "Run red team/blue team exercise for technical staff", "Test SIEM alert rules against simulated attacks", "Measure Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR)"] },
      { phase: 4, title: "Continuous Improvement", duration: "Ongoing", tasks: ["Conduct post-incident review after every P1/P2 incident", "Update playbooks quarterly based on new threat intelligence", "Annual IR programme audit against NIST 800-61", "Participate in industry ISAC for threat intelligence sharing"] },
    ],
    industries: [
      { name: "Banking/Finance", icon: "ðŸ¦", priority: "Critical", plan: "CERT-In 6-hour reporting + RBI 2-6 hour reporting requires automated detection. War room setup mandatory. SWIFT-related incidents need specific playbooks. Cyber insurance requires documented IR programme." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "Critical", plan: "HIPAA Breach Notification Rule (60-day report to HHS). Focus playbooks on ransomware (top healthcare threat) and EHR access incidents. Include patient safety escalation in IR process." },
      { name: "E-Commerce", icon: "ðŸ›’", priority: "High", plan: "PCI-DSS requires incident response plan. Focus on card data breach playbook with immediate card scheme notification. Customer notification within 72 hours (GDPR)." },
      { name: "SaaS/Tech", icon: "ðŸ’»", priority: "High", plan: "SOC 2 requires documented IR programme. Customer breach notification SLAs in contracts drive urgency. Infrastructure-as-code enables faster recovery. Focus on supply chain attack playbooks." },
    ],
    usecases: ["SOC playbook development", "CSIRT establishment", "CERT-In breach reporting preparation", "Cyber insurance requirement", "Post-breach forensics framework"],
    related: ["nist-csf", "nist-800-53", "iso27001"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // PCI-DSS
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "pci-dss", short: "PCI-DSS v4.0", name: "Payment Card Industry Data Security Standard",
    org: "PCI SSC", region: "ðŸŒ Global", type: "Compliance Standard", mandatory: "Yes (card processing)",
    focus: "Cardholder data", color: "#eab308", icon: "ðŸ¦", category: "compliance",
    overview: "PCI-DSS v4.0 (effective March 2024, v3.2.1 retired March 2024) is the mandatory standard for any organisation storing, processing, or transmitting payment card data. Maintained by the PCI Security Standards Council (Visa, Mastercard, Amex, Discover). Non-compliance can result in fines of $5,000â€“$100,000/month, increased transaction fees, and ultimately loss of card processing rights. v4.0 introduces customised implementation approach, adds 13 new requirements, and strengthens MFA requirements.",
    clauses: [
      { num: "Req 1", title: "Network Security Controls", desc: "Firewalls, routers, network segmentation, CDE boundary definition, documentation" },
      { num: "Req 2", title: "Secure Configurations", desc: "Vendor defaults changed, unnecessary services removed, system component inventory" },
      { num: "Req 3", title: "Protect Stored Account Data", desc: "Data retention policy, PAN masking, encryption, key management, SAD protection" },
      { num: "Req 4", title: "Protect Data in Transit", desc: "TLS 1.2+ for all PAN transmission, certificate management, no unprotected PANs" },
      { num: "Req 5", title: "Protect Against Malicious Software", desc: "Anti-malware on all systems, anti-phishing, periodic malware scans, logging" },
      { num: "Req 6", title: "Develop & Maintain Secure Systems", desc: "Vulnerability management, patching SLAs, WAF requirement, secure coding (OWASP)" },
      { num: "Req 7", title: "Restrict Access by Need-to-Know", desc: "Access control systems, least privilege, approval workflow for access" },
      { num: "Req 8", title: "Identify Users & Authenticate Access", desc: "MFA for non-console admin + remote access, password policy, shared accounts prohibited" },
      { num: "Req 9", title: "Restrict Physical Access", desc: "Facility entry controls, badge systems, visitor logs, media protection, PoS device protection" },
      { num: "Req 10", title: "Log & Monitor All Access", desc: "Audit logs for CDE access, tamper-evident log storage, daily log review, SIEM" },
      { num: "Req 11", title: "Test Security Systems & Processes", desc: "Quarterly vulnerability scans (ASV), annual internal pentest, annual external pentest, IDS/IPS" },
      { num: "Req 12", title: "Support Security with Policies", desc: "Security policy, risk assessment, awareness programme, incident response plan" },
    ],
    controls: "v4.0: 64 new sub-requirements, 13 additional new requirements. Highlights: MFA for all CDE access, targeted risk analysis for customised approach, phishing-resistant MFA for privileged users",
    toolkit: [
      { name: "Nessus / Tenable.io", purpose: "PCI-DSS vulnerability scanning with ASV-ready reports", type: "Paid", url: "https://www.tenable.com/products/nessus" },
      { name: "Trustwave PCI Compliance Manager", purpose: "End-to-end PCI-DSS compliance management and SAQ automation", type: "Paid", url: "https://www.trustwave.com" },
      { name: "ControlCase", purpose: "Unified compliance platform for PCI-DSS, ISO 27001, SOC 2", type: "Paid", url: "https://www.controlcase.com" },
      { name: "Qualys PCI Compliance", purpose: "Cloud-based PCI scanning and compliance monitoring", type: "Paid", url: "https://www.qualys.com/compliance/pci-compliance/" },
      { name: "OSSEC / Wazuh", purpose: "Open-source HIDS for PCI Req 10 log monitoring and file integrity", type: "Free", url: "https://wazuh.com" },
      { name: "Tripwire Enterprise", purpose: "File integrity monitoring for PCI Req 10.3 (log tamper evidence)", type: "Paid", url: "https://www.tripwire.com" },
      { name: "Metasploit", purpose: "Penetration testing for Req 11 internal pentest", type: "Free/Paid", url: "https://www.metasploit.com" },
    ],
    implementation: [
      { phase: 1, title: "Scope Definition", duration: "2â€“4 weeks", tasks: ["Define Cardholder Data Environment (CDE) boundary", "Map all flows of cardholder data (network diagrams)", "Identify all system components in CDE scope", "Determine applicable SAQ (Self-Assessment Questionnaire) level", "Engage QSA (Qualified Security Assessor) if needed"] },
      { phase: 2, title: "Scope Reduction", duration: "2â€“4 weeks", tasks: ["Implement network segmentation to isolate CDE", "Tokenise cardholder data where possible (reduces scope significantly)", "Use Point-to-Point Encryption (P2PE) validated solution", "Remove unnecessary storage of PAN and SAD"] },
      { phase: 3, title: "Control Implementation (Req 1â€“12)", duration: "8â€“16 weeks", tasks: ["Deploy and configure firewall rules for CDE", "Harden all CDE systems against PCI-DSS Req 2", "Implement MFA for all access to CDE (Req 8)", "Deploy SIEM and file integrity monitoring (Req 10)", "Conduct security awareness training (Req 12)"] },
      { phase: 4, title: "Validation & Report", duration: "4â€“8 weeks", tasks: ["Engage Approved Scanning Vendor (ASV) for external scans", "Conduct internal and external penetration test", "QSA conducts on-site assessment for SAQ D / ROC", "Remediate all Req 6 High-risk vulnerabilities", "Submit Report on Compliance (ROC) or SAQ to acquiring bank"] },
    ],
    industries: [
      { name: "Payment Gateways", icon: "ðŸ’³", priority: "Mandatory", plan: "Full SAQ D / QSA ROC required. Annual assessment mandatory. Quarterly ASV scans. 24/7 monitoring of CDE. Network segmentation is key to scope reduction." },
      { name: "E-Commerce Merchants", icon: "ðŸ›’", priority: "Mandatory", plan: "Use hosted payment pages or tokenisation to reduce to SAQ A. Still requires annual pentest and quarterly scans. Integrate WAF for Req 6.4." },
      { name: "FinTech Startups", icon: "ðŸš€", priority: "Mandatory", plan: "Engage QSA early. Build PCI compliance into architecture from day one â€” retro-fitting is expensive. SAQ A-EP for e-commerce with JS payment pages." },
      { name: "Retail/PoS", icon: "ðŸª", priority: "Mandatory", plan: "Physical security of PoS devices (Req 9) is critical. Use P2PE-validated solutions to reduce scope. SAQ B or B-IP for PoS merchants." },
    ],
    usecases: ["Payment gateway compliance", "E-commerce merchant compliance", "Acquiring bank requirements", "FinTech product security"],
    related: ["iso27001", "nist-csf", "owasp-top10"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // GDPR
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "gdpr", short: "GDPR", name: "General Data Protection Regulation",
    org: "European Union", region: "ðŸ‡ªðŸ‡º EU (Extraterritorial)", type: "Regulation", mandatory: "Yes (EU data subjects)",
    focus: "Personal data protection", color: "#6366f1", icon: "ðŸ‡ªðŸ‡º", category: "compliance",
    overview: "GDPR (EU 2016/679) is the world's most comprehensive data protection law, effective May 2018. It applies to any organisation worldwide that processes personal data of EU/EEA residents. Maximum penalties: â‚¬20 million or 4% of global annual turnover (whichever is higher). The UK has a near-identical UK GDPR post-Brexit. Key principles: lawfulness, fairness and transparency, purpose limitation, data minimisation, accuracy, storage limitation, integrity and confidentiality, and accountability.",
    clauses: [
      { num: "Art. 5", title: "Principles of Processing", desc: "Lawfulness, fairness, transparency, purpose limitation, data minimisation, accuracy, storage limitation, integrity" },
      { num: "Art. 6", title: "Lawful Basis for Processing", desc: "6 bases: consent, contract performance, legal obligation, vital interests, public task, legitimate interests" },
      { num: "Art. 9", title: "Special Category Data", desc: "Health, biometric, genetic, race, religion data requires explicit consent or specific legal basis" },
      { num: "Art. 13/14", title: "Privacy Notices", desc: "Clear, plain-language privacy notices at point of data collection" },
      { num: "Art. 15â€“22", title: "Data Subject Rights", desc: "Right of access, rectification, erasure (right to be forgotten), portability, objection, automated decision-making" },
      { num: "Art. 25", title: "Privacy by Design & Default", desc: "Embed privacy controls at design stage; default settings must be most privacy-friendly" },
      { num: "Art. 28", title: "Data Processors", desc: "DPA required with all processors; processors can only act on controller instructions" },
      { num: "Art. 32", title: "Security of Processing", desc: "Appropriate technical and organisational measures including encryption, pseudonymisation, testing" },
      { num: "Art. 33", title: "Breach Notification to Authority", desc: "72-hour notification to supervisory authority (e.g., ICO, DPC) unless unlikely to result in risk" },
      { num: "Art. 34", title: "Notification to Data Subjects", desc: "Without undue delay if breach likely to result in high risk to individuals" },
      { num: "Art. 35", title: "Data Protection Impact Assessment", desc: "DPIA mandatory before high-risk processing (surveillance, profiling, sensitive data at scale)" },
      { num: "Art. 37", title: "Data Protection Officer", desc: "DPO mandatory for public authorities, large-scale systematic monitoring, or special category data processing" },
    ],
    controls: "Technical measures: encryption, pseudonymisation, access controls, audit logging. Organisational: DPO, ROPA, DPA agreements, privacy notices, consent management, DPIA process",
    toolkit: [
      { name: "OneTrust", purpose: "Enterprise privacy management â€” consent, DSAR, ROPA, DPIA, cookie management", type: "Paid", url: "https://www.onetrust.com" },
      { name: "TrustArc", purpose: "Privacy compliance platform with GDPR assessment and consent management", type: "Paid", url: "https://trustarc.com" },
      { name: "Cookiebot", purpose: "GDPR/ePrivacy cookie consent management and scanning", type: "Free/Paid", url: "https://www.cookiebot.com" },
      { name: "DataGrail", purpose: "Data subject request (DSAR) automation platform", type: "Paid", url: "https://www.datagrail.io" },
      { name: "Microsoft Purview", purpose: "Data classification, DLP, information protection for GDPR", type: "Paid", url: "https://learn.microsoft.com/en-us/purview/" },
      { name: "GDPR.eu Documentation Templates", purpose: "Free privacy notice, ROPA, DPA templates", type: "Free", url: "https://gdpr.eu/checklist/" },
      { name: "CNIL GDPR Guide", purpose: "French DPA's practical GDPR implementation guides", type: "Free", url: "https://www.cnil.fr/en/gdpr-developers-guide" },
    ],
    implementation: [
      { phase: 1, title: "Data Mapping & ROPA", duration: "3â€“6 weeks", tasks: ["Conduct data discovery across all systems (interviews + technical scan)", "Build Record of Processing Activities (ROPA) with: data types, purposes, legal basis, recipients, retention", "Identify all third-party processors and sub-processors", "Map cross-border data transfers (EU â†’ India/US)"] },
      { phase: 2, title: "Lawful Basis & Consent", duration: "2â€“4 weeks", tasks: ["Assign lawful basis for each processing activity in ROPA", "Implement consent management platform for website cookies", "Rewrite privacy notices in plain language", "Build consent records database with timestamps and evidence"] },
      { phase: 3, title: "Rights Management", duration: "2â€“4 weeks", tasks: ["Build DSAR (Data Subject Access Request) process (30-day SLA)", "Implement erasure workflow across all systems", "Build data portability export capability", "Create internal intake form for rights requests"] },
      { phase: 4, title: "Technical Controls", duration: "4â€“8 weeks", tasks: ["Implement pseudonymisation/encryption for stored personal data", "Deploy DLP solutions to detect PII leaving the organisation", "Configure data retention and automated deletion schedules", "Implement breach detection and response plan with 72h notification workflow"] },
      { phase: 5, title: "DPIA & Ongoing Compliance", duration: "Ongoing", tasks: ["Conduct DPIAs before any high-risk new processing", "Appoint DPO if required (or privacy lead)", "Annual GDPR compliance audit", "Update ROPA quarterly for new processing activities"] },
    ],
    industries: [
      { name: "SaaS/Tech Companies", icon: "ðŸ’»", priority: "Critical", plan: "GDPR applies if any EU users. Key: privacy by design in product, DPA with all cloud providers (AWS, GCP), cookie consent on website, DSAR process, 72h breach notification workflow." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "Critical", plan: "Health data is special category (Art. 9). DPO mandatory. DPIAs required for all new health data processing. Strict data minimisation and access controls required." },
      { name: "E-Commerce/Retail", icon: "ðŸ›’", priority: "High", plan: "Focus on cookie consent, marketing consent, purchase data retention, DSAR process for customer data. Right to erasure must work across all systems including analytics." },
      { name: "HR/Recruitment", icon: "ðŸ‘¥", priority: "High", plan: "Employee data is heavily regulated. Define retention for CVs (unsuccessful candidates: 6â€“12 months typical). Lawful basis for employee monitoring. DSAR process for employee data." },
      { name: "Banking/Finance", icon: "ðŸ¦", priority: "Critical", plan: "Balance GDPR with AML/KYC legal obligations (Art. 6(1)(c) legal obligation). Data retention driven by regulatory requirements. Profiling for credit decisions requires explicit rules." },
    ],
    usecases: ["EU market access", "Enterprise privacy compliance", "Data breach response", "Vendor DPA agreements", "Privacy by design architecture"],
    related: ["iso27701", "iso27001", "cert-in"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // CERT-IN
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "cert-in", short: "CERT-In", name: "Indian Cybersecurity Directions 2022",
    org: "MeitY (India)", region: "ðŸ‡®ðŸ‡³ India", type: "Regulation", mandatory: "Yes (India)",
    focus: "Incident reporting", color: "#f43f5e", icon: "ðŸ‡®ðŸ‡³", category: "india",
    overview: "CERT-In (Indian Computer Emergency Response Team) issued binding directions in April 2022 under the IT Act 2000, creating the most stringent incident reporting requirements globally â€” a 6-hour reporting window. Applicable to all 'service providers, intermediaries, data centres, corporates and government organisations' in India. Non-compliance is a criminal offence under Section 70B(7) of the IT Act, punishable with imprisonment up to 1 year or fine up to â‚¹1 lakh.",
    clauses: [
      { num: "Dir. 1", title: "6-Hour Incident Reporting", desc: "Mandatory report to CERT-In within 6 hours of detection for 20 incident types including data breaches, ransomware, unauthorised access, website defacement, malicious code" },
      { num: "Dir. 2", title: "ICT Log Retention", desc: "All ICT system logs must be maintained for a rolling 180 days within Indian jurisdiction. Logs must be provided to CERT-In on demand." },
      { num: "Dir. 3", title: "NTP Time Synchronisation", desc: "All ICT systems must synchronise clocks with NTP servers of NPTI (National Physical Laboratory, India) or NIC. Essential for log correlation." },
      { num: "Dir. 4", title: "Virtual Asset Service Providers", desc: "Crypto exchanges and wallet providers must maintain KYC records and transaction data for 5 years" },
      { num: "Dir. 5", title: "VPN Provider Requirements", desc: "VPN service providers must maintain validated subscriber names, IPs, dates, purpose for 5 years" },
      { num: "Dir. 6", title: "Cloud Service Providers", desc: "CSPs must collect and maintain account data, usage logs, and subscriber information" },
    ],
    controls: "24 reportable incident types including: targeted attacks, compromise of critical systems, website defacement, malicious code attacks, attacks on internet infrastructure, identity theft, data breaches, ransomware",
    toolkit: [
      { name: "CERT-In Official Reporting Portal", purpose: "Mandatory reporting portal at incident@cert-in.org.in / https://www.cert-in.org.in", type: "Free", url: "https://www.cert-in.org.in" },
      { name: "Wazuh SIEM", purpose: "Open-source SIEM for 180-day log retention and real-time alerting", type: "Free", url: "https://wazuh.com" },
      { name: "Graylog", purpose: "Open-source log management platform for centralised log retention", type: "Free/Paid", url: "https://graylog.org" },
      { name: "ELK Stack (Elastic)", purpose: "Elasticsearch/Logstash/Kibana for log storage, search and analysis", type: "Free/Paid", url: "https://www.elastic.co/elastic-stack" },
      { name: "Chrony / ntpd", purpose: "NTP synchronisation daemon for CERT-In NTP compliance (Indian NTP servers)", type: "Free", url: "https://chrony.tuxfamily.org" },
      { name: "TheHive", purpose: "Incident case management for documenting and tracking CERT-In reportable incidents", type: "Free", url: "https://thehive-project.org" },
    ],
    implementation: [
      { phase: 1, title: "Incident Classification Setup", duration: "1â€“2 weeks", tasks: ["Map CERT-In 24 incident types to internal incident classification matrix", "Define detection sources: SIEM, EDR, cloud alerts, manual reports", "Build automated detection rules for ransomware, data breach, defacement", "Configure SIEM alerts to trigger IR workflow for CERT-In incidents"] },
      { phase: 2, title: "6-Hour Reporting Workflow", duration: "1â€“2 weeks", tasks: ["Build CERT-In report template pre-populated from SIEM data", "Define approval chain for report (CISO â†’ Legal â†’ CERT-In)", "Automate initial incident detection â†’ SIEM alert â†’ CSIRT notification chain", "Test end-to-end workflow: time from detection to report submission"] },
      { phase: 3, title: "180-Day Log Retention", duration: "2â€“4 weeks", tasks: ["Audit all ICT systems for logging capability", "Deploy centralised SIEM with 180-day hot/warm storage", "Configure log forwarding from all systems: Windows events, Linux syslog, network devices, cloud", "Implement log tamper detection (hash chaining, WORM storage)"] },
      { phase: 4, title: "NTP Synchronisation", duration: "1 week", tasks: ["Configure all servers to use NPTI NTP (time.npli.res.in) as primary", "Use NIC NTP (time.nic.in) as secondary", "Verify synchronisation: chronyc tracking", "Document NTP configuration for audit evidence"] },
    ],
    industries: [
      { name: "IT Companies (India)", icon: "ðŸ’»", priority: "Mandatory", plan: "All IT companies must comply. Build SIEM from day 1 for log retention. Automated detection is essential â€” 6 hours is too short for manual processes. Engage legal counsel for breach determination process." },
      { name: "Banking/NBFC", icon: "ðŸ¦", priority: "Critical", plan: "CERT-In + RBI 2-6h reporting + PCI-DSS creates a complex reporting landscape. Build single IR workflow that satisfies all three. Prioritise automated detection over manual." },
      { name: "Cloud/Data Centre", icon: "â˜ï¸", priority: "Critical", plan: "VPN providers, CSPs, and data centres have specific subscriber data retention requirements. Implement data governance for 5-year retention. Review contracts with foreign customers for India data residency." },
      { name: "Crypto/Web3", icon: "ðŸª™", priority: "Critical", plan: "VASPs must maintain 5-year KYC records. Significant technical infrastructure required for transaction monitoring and record keeping. CERT-In applies regardless of whether coins are 'Indian'." },
    ],
    usecases: ["India operations legal compliance", "SOC reporting procedures", "Enterprise compliance for India HQ", "Cloud provider India compliance"],
    related: ["rbi", "iso27001", "gdpr"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // RBI
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "rbi", short: "RBI Cyber Framework", name: "Reserve Bank of India Cybersecurity Framework",
    org: "Reserve Bank of India", region: "ðŸ‡®ðŸ‡³ India (BFSI)", type: "Regulation", mandatory: "Yes (Banks/NBFCs)",
    focus: "Banking cybersecurity", color: "#fb7185", icon: "ðŸ›", category: "india",
    overview: "The RBI Cybersecurity Framework (2016, updated with circulars through 2023) mandates comprehensive cybersecurity controls for scheduled commercial banks, Urban Cooperative Banks (UCBs), NBFCs, and payment system operators. Key additions include SOC requirements (2017), SWIFT Customer Security Controls (2018), internet banking security (2020), and payment aggregator/gateway security (2021). Non-compliance can result in supervisory action, fines, and restrictions on operations.",
    clauses: [
      { num: "1", title: "Cybersecurity Policy & Governance", desc: "Board-approved cybersecurity policy, CISO role, cyber risk appetite, annual review" },
      { num: "2", title: "Baseline Controls", desc: "Inventory management, patch management, secure configurations, change management" },
      { num: "3", title: "Advanced Measures", desc: "Defence-in-depth architecture, privileged access management, endpoint security, DLP" },
      { num: "4", title: "Application Security", desc: "Secure SDLC, pre-go-live VAPT, WAF, API security, mobile banking security" },
      { num: "5", title: "Cyber Resilience", desc: "BCP/DR, cyber crisis management plan (CCMP), cyber simulation exercises, recovery testing" },
      { num: "6", title: "SOC Requirement", desc: "24/7 Security Operations Centre monitoring all critical systems, threat intelligence integration" },
      { num: "7", title: "Third-Party Risk", desc: "IT outsourcing policy, vendor risk assessment, right to audit, exit clauses in contracts" },
      { num: "8", title: "Incident Reporting", desc: "Report cyber incidents to RBI within 2â€“6 hours; near-miss incidents reported within 24 hours" },
      { num: "9", title: "SWIFT CSP", desc: "SWIFT Customer Security Programme (CSP) for SWIFT-connected banks â€” annual self-assessment" },
      { num: "10", title: "ATM/PoS Security", desc: "ATM security: cameras, PIN pad replacement, blackbox attack prevention, software whitelisting" },
    ],
    controls: "RBI requires banks to classify controls as Basic, Intermediate, and Advanced. Small banks start with Basic controls. Large commercial banks require Advanced controls including SOC, PAM, UEBA, and deception technology.",
    toolkit: [
      { name: "IBM QRadar SIEM", purpose: "SOC SIEM platform widely used in Indian banking sector for RBI compliance", type: "Paid", url: "https://www.ibm.com/products/qradar-siem" },
      { name: "RSA NetWitness", purpose: "Network detection and response for SOC operations in banking", type: "Paid", url: "https://www.rsa.com/netwitness/" },
      { name: "CyberArk PAM", purpose: "Privileged Access Management for RBI requirement on privileged users", type: "Paid", url: "https://www.cyberark.com" },
      { name: "Forcepoint DLP", purpose: "Data Loss Prevention for customer and financial data protection", type: "Paid", url: "https://www.forcepoint.com" },
      { name: "Nessus Professional", purpose: "Vulnerability scanning and patch compliance monitoring for RBI baseline", type: "Paid", url: "https://www.tenable.com" },
      { name: "SWIFT CSP Assessment Tool", purpose: "Official SWIFT tool for Customer Security Programme self-assessment", type: "Free (SWIFT members)", url: "https://www.swift.com/swift-resource/248586/download" },
      { name: "Burp Suite Pro", purpose: "VAPT tool for pre-go-live application security testing (RBI SDLC requirement)", type: "Paid", url: "https://portswigger.net/burp" },
    ],
    implementation: [
      { phase: 1, title: "Governance & Policy", duration: "4â€“6 weeks", tasks: ["Appoint CISO and define reporting structure (direct to Board/Audit Committee)", "Write Board-approved Cybersecurity Policy", "Conduct cyber risk assessment and define risk appetite", "Establish Cyber Crisis Management Plan (CCMP)", "Brief Board on RBI requirements and allocate budget"] },
      { phase: 2, title: "Baseline Controls", duration: "8â€“12 weeks", tasks: ["Complete hardware/software inventory with business criticality rating", "Implement patch management: Critical <48h, High <7d, Medium <30d", "Deploy endpoint protection on all bank-managed devices", "Implement email security gateway (anti-spam, anti-phishing, DMARC)", "Harden all systems to CIS Benchmark baselines"] },
      { phase: 3, title: "SOC Establishment", duration: "12â€“24 weeks", tasks: ["Define SOC scope: critical systems, internet-facing systems, SWIFT", "Deploy SIEM with use cases for banking threats: account takeover, fraudulent transactions, insider threat", "Hire or outsource SOC analysts (24/7 coverage)", "Integrate threat intelligence feeds (CERT-In, FS-ISAC, RBI advisories)", "Define and test escalation procedures for P1 incidents (2-hour RBI notification)"] },
      { phase: 4, title: "Application Security & VAPT", duration: "Ongoing", tasks: ["Implement SDLC security gating (SAST/DAST before go-live)", "Conduct pre-go-live VAPT for all new internet-facing applications", "Deploy WAF for all internet-banking and API services", "Annual comprehensive VAPT by CERT-In empanelled organisation"] },
      { phase: 5, title: "SWIFT CSP & Third-Party", duration: "4â€“6 weeks", tasks: ["Complete SWIFT CSP self-assessment (mandatory for SWIFT-connected banks)", "Audit all IT outsourcing arrangements against RBI guidelines", "Implement vendor risk tiering and quarterly reviews", "Conduct annual cyber simulation/war game exercise"] },
    ],
    industries: [
      { name: "Scheduled Commercial Banks", icon: "ðŸ¦", priority: "Mandatory", plan: "Full framework applies. Board-level ownership. Advanced controls required. Mandatory SOC. Annual VAPT by CERT-In empanelled firm. 2-6h incident reporting to RBI." },
      { name: "Urban Cooperative Banks", icon: "ðŸ˜", priority: "Mandatory", plan: "Simplified framework for smaller banks. Basic controls mandatory. SOC can be outsourced. Leverage shared services for cost efficiency. Monthly reporting to RBI regional offices." },
      { name: "NBFCs (Systemically Important)", icon: "ðŸ’¼", priority: "Mandatory", plan: "SI-NBFCs (assets > â‚¹500 crore) require full framework. Basic and Intermediate controls at minimum. Annual audit by internal team." },
      { name: "Payment Aggregators/Gateways", icon: "ðŸ’³", priority: "Critical", plan: "RBI PA Guidelines (2020) apply. PCI-DSS + RBI cybersecurity framework mandatory. Application security testing before go-live. Merchant onboarding security requirements." },
    ],
    usecases: ["RBI audit preparation", "Banking licence cybersecurity compliance", "NBFC regulatory compliance", "Payment system operator licensing"],
    related: ["cert-in", "pci-dss", "iso27001", "nist-800-61"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // CIS Controls
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "cis", short: "CIS Controls v8", name: "Center for Internet Security Controls",
    org: "CIS", region: "ðŸŒ Global", type: "Best Practice", mandatory: "No",
    focus: "Practical security baseline", color: "#14b8a6", icon: "ðŸ› ", category: "practical",
    overview: "CIS Controls v8 (released May 2021) is the most implementation-focused cybersecurity framework with 18 controls and 153 safeguards. Its Implementation Groups (IG1/IG2/IG3) allow any organisation â€” from a 5-person startup to a Fortune 500 â€” to adopt controls proportional to their risk. IG1 (56 safeguards) covers basic cyber hygiene applicable to all organisations. Studies show implementing CIS IG1 alone prevents 85%+ of common attacks. Each safeguard maps to NIST CSF, ISO 27001, PCI-DSS, and HIPAA.",
    clauses: [
      { num: "1", title: "Inventory & Control of Enterprise Assets", desc: "IG1: Active discovery, passive discovery, DHCP logging, asset classification â€” know every device" },
      { num: "2", title: "Inventory & Control of Software Assets", desc: "IG1: Software inventory, authorised software list, review â€” prevent shadow IT and unauthorised software" },
      { num: "3", title: "Data Protection", desc: "IG1: Data classification, data retention/disposal, encryption, DLP â€” protect sensitive data" },
      { num: "4", title: "Secure Configuration", desc: "IG1: Secure configurations for all assets, hardening guides, configuration management â€” CIS Benchmarks" },
      { num: "5", title: "Account Management", desc: "IG1: Account inventory, disable dormant accounts, restrict admin privileges â€” control identities" },
      { num: "6", title: "Access Control Management", desc: "IG1: Least privilege, MFA, role-based access â€” control who can do what" },
      { num: "7", title: "Continuous Vulnerability Management", desc: "IG1: Patch management SLA, vulnerability scanning â€” find and fix weaknesses" },
      { num: "8", title: "Audit Log Management", desc: "IG1: Centralised log collection, retention, review â€” detect and investigate incidents" },
      { num: "9", title: "Email & Web Browser Protections", desc: "IG1: DNS filtering, email gateway, anti-phishing â€” block the most common attack vectors" },
      { num: "10", title: "Malware Defenses", desc: "IG1: Anti-malware on all endpoints, automatic updates, centralised management" },
      { num: "11", title: "Data Recovery", desc: "IG1: Automated backups, immutable backups, restoration testing â€” prepare for ransomware" },
      { num: "12", title: "Network Infrastructure Management", desc: "IG2: Secure network devices, network diagrams, patch network devices" },
      { num: "13", title: "Network Monitoring & Defense", desc: "IG2: IDS/IPS, network flow monitoring, SIEM â€” detect intrusions" },
      { num: "14", title: "Security Awareness & Skills Training", desc: "IG1: Security awareness programme, phishing simulation â€” address human risk" },
      { num: "15", title: "Service Provider Management", desc: "IG2: Vendor inventory, vendor due diligence, contract security requirements" },
      { num: "16", title: "Application Software Security", desc: "IG2: Secure SDLC, code review, SAST/DAST, web app pentest" },
      { num: "17", title: "Incident Response Management", desc: "IG2: IR plan, tabletop exercises, post-incident reviews â€” respond effectively" },
      { num: "18", title: "Penetration Testing", desc: "IG3: External + internal pentest, red team exercises, physical pentest" },
    ],
    controls: "IG1: 56 safeguards (basic cyber hygiene) | IG2: 74 additional safeguards | IG3: 23 additional safeguards = 153 total. CIS Benchmarks provide technical implementation for CIS Control 4.",
    toolkit: [
      { name: "CIS-CAT Pro", purpose: "Official CIS tool for automated CIS Benchmarks assessment across 100+ platforms", type: "Paid (free CIS-CAT Lite)", url: "https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/" },
      { name: "Tenable.io / Nessus", purpose: "Vulnerability scanning (CIS Control 7) with CIS Benchmark compliance plugins", type: "Paid", url: "https://www.tenable.com" },
      { name: "OpenSCAP", purpose: "Open-source CIS Benchmark compliance checking for Linux systems", type: "Free", url: "https://www.open-scap.org" },
      { name: "Wazuh", purpose: "SIEM + EDR + log management covering CIS Controls 1, 4, 7, 8, 10, 13", type: "Free", url: "https://wazuh.com" },
      { name: "Veeam Backup", purpose: "Enterprise backup and recovery for CIS Control 11", type: "Paid", url: "https://www.veeam.com" },
      { name: "KnowBe4", purpose: "Security awareness training and phishing simulation (CIS Control 14)", type: "Paid", url: "https://www.knowbe4.com" },
      { name: "Qualys CSAM", purpose: "Cyber Security Asset Management covering CIS Controls 1 and 2", type: "Paid", url: "https://www.qualys.com" },
    ],
    implementation: [
      { phase: 1, title: "IG1 â€” Basic Cyber Hygiene (ALL orgs)", duration: "4â€“8 weeks", tasks: ["Deploy asset discovery tool and build hardware + software inventory (Controls 1, 2)", "Apply CIS Benchmark hardening to all endpoints and servers (Control 4)", "Enable MFA for all accounts; remove dormant accounts (Controls 5, 6)", "Deploy endpoint protection and ensure automatic updates (Control 10)", "Configure automated backups with offline/immutable copies (Control 11)", "Implement DNS filtering and email security gateway (Control 9)"] },
      { phase: 2, title: "IG2 â€” For Most Organisations", duration: "8â€“16 weeks", tasks: ["Deploy vulnerability scanner with weekly scans and patching SLA (Control 7)", "Implement centralised SIEM for log collection and analysis (Control 8)", "Deploy network IDS/IPS and network flow monitoring (Control 13)", "Implement security awareness training with quarterly phishing simulations (Control 14)", "Build secure SDLC process for internally developed applications (Control 16)", "Develop Incident Response Plan and conduct annual tabletop (Control 17)"] },
      { phase: 3, title: "IG3 â€” For High-Risk Organisations", duration: "12â€“24 weeks", tasks: ["Conduct annual external + internal penetration test (Control 18)", "Implement full PAM solution for privileged accounts", "Deploy advanced EDR with behavioural detection", "Implement zero-trust network access for remote workers", "Build red team exercise capability"] },
    ],
    industries: [
      { name: "Startups/SMEs", icon: "ðŸš€", priority: "High", plan: "Start with IG1 only (56 safeguards). Free tools cover most: Wazuh (SIEM), OpenSCAP (hardening), Veeam Community (backup). Can be implemented in 4â€“6 weeks with 1 engineer." },
      { name: "Mid-Market Companies", icon: "ðŸ¢", priority: "High", plan: "IG1 + IG2 (130 safeguards). Invest in Tenable for vuln management, SIEM for logging, KnowBe4 for training. 3â€“6 month programme with dedicated security team." },
      { name: "Enterprise", icon: "ðŸ™", priority: "High", plan: "Full IG3 (153 safeguards). Annual pen test mandatory. Full SOC required. Advanced EDR and PAM investment. CIS-CAT Pro for continuous benchmark compliance." },
      { name: "Healthcare (India)", icon: "ðŸ¥", priority: "High", plan: "IG1 is minimum viable. Map to CERT-In requirements for log retention (Control 8). Focus on ransomware resilience: Control 10 (malware) + Control 11 (backup) are critical." },
    ],
    usecases: ["Security programme foundation for SMEs", "Quick win roadmap for CISOs", "Board-level risk reporting", "Cyber insurance pre-assessment", "Vendor security assessment baseline"],
    related: ["nist-csf", "iso27001", "pci-dss"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // SOC 2
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "soc2", short: "SOC 2", name: "System and Organization Controls 2",
    org: "AICPA", region: "ðŸ‡ºðŸ‡¸ US (SaaS Global)", type: "Audit Report", mandatory: "Market-driven",
    focus: "SaaS trust & security", color: "#8b5cf6", icon: "ðŸ”", category: "compliance",
    overview: "SOC 2 is an auditing procedure for technology service providers, developed by the American Institute of CPAs (AICPA). It demonstrates that a company's information systems meet the Trust Services Criteria (TSC). Type I: point-in-time design assessment. Type II: 6â€“12 month operating effectiveness audit. SOC 2 Type II is increasingly required to win enterprise B2B contracts â€” particularly in the US, UK, and EU markets. The report is confidential (shared under NDA) unlike ISO 27001 which is a public certificate.",
    clauses: [
      { num: "CC1", title: "Control Environment", desc: "COSO framework control environment: ethics, competence, oversight, org structure" },
      { num: "CC2", title: "Communication & Information", desc: "Information quality, internal and external communication of security matters" },
      { num: "CC3", title: "Risk Assessment", desc: "Risk identification, analysis, fraud risk, and change risk assessment" },
      { num: "CC4", title: "Monitoring Activities", desc: "Ongoing and separate evaluation of controls; remediation of deficiencies" },
      { num: "CC5", title: "Control Activities", desc: "Controls selected and developed; technology general controls" },
      { num: "CC6", title: "Logical & Physical Access", desc: "Access provisioning, authentication, authorisation, removal, physical security" },
      { num: "CC7", title: "System Operations", desc: "Detecting and monitoring, incident identification, response, and recovery" },
      { num: "CC8", title: "Change Management", desc: "Infrastructure, data, software, and procedure change management process" },
      { num: "CC9", title: "Risk Mitigation", desc: "Risk mitigation activities including vendor/partner management" },
      { num: "A1", title: "Availability (Add-on)", desc: "Availability commitments and SLA performance monitoring" },
      { num: "PI1", title: "Processing Integrity (Add-on)", desc: "Complete, valid, accurate, timely, authorised processing" },
      { num: "C1", title: "Confidentiality (Add-on)", desc: "Confidentiality of information as committed to customers" },
      { num: "P-TSC", title: "Privacy (Add-on)", desc: "Collection, use, retention, disposal of personal information" },
    ],
    controls: "Common Criteria (CC) is mandatory. Availability, Processing Integrity, Confidentiality, Privacy are optional add-ons selected based on commitments in customer contracts. Evidence required for every control over audit period.",
    toolkit: [
      { name: "Vanta", purpose: "Automated SOC 2 evidence collection, continuous monitoring, readiness dashboard", type: "Paid", url: "https://www.vanta.com" },
      { name: "Drata", purpose: "Continuous compliance automation for SOC 2 with 200+ integrations", type: "Paid", url: "https://drata.com" },
      { name: "Secureframe", purpose: "SOC 2 compliance automation with built-in audit workflow", type: "Paid", url: "https://secureframe.com" },
      { name: "Tugboat Logic (OneTrust)", purpose: "AI-powered SOC 2 readiness assessment and policy library", type: "Paid", url: "https://www.onetrust.com/products/grc-risk-assessments/" },
      { name: "AWS Audit Manager", purpose: "Automated evidence collection for SOC 2 in AWS environments", type: "Paid", url: "https://aws.amazon.com/audit-manager/" },
      { name: "SOC 2 Policy Templates (Laika)", purpose: "Free SOC 2 policy templates to get started quickly", type: "Free", url: "https://heylaika.com/posts/soc2-policies" },
    ],
    implementation: [
      { phase: 1, title: "Readiness Assessment", duration: "2â€“4 weeks", tasks: ["Map all in-scope systems to Trust Services Criteria", "Conduct gap assessment against all CC criteria", "Identify evidence gaps and control gaps", "Select Add-on criteria based on customer commitments", "Engage CPA audit firm and agree on audit window"] },
      { phase: 2, title: "Control Implementation", duration: "8â€“16 weeks", tasks: ["Implement all CC6 access controls (MFA, access reviews, offboarding)", "Build change management process (CC8) with approval workflows", "Implement vulnerability management and patching programme (CC7)", "Create formal risk assessment process (CC3)", "Write all required policies (10+ policies): security, access, encryption, incident response, etc."] },
      { phase: 3, title: "Evidence Collection (Type II period)", duration: "6â€“12 months", tasks: ["Use automation tool (Vanta/Drata) to collect continuous evidence", "Collect quarterly access reviews as evidence", "Document every change in change management system", "Collect infrastructure configuration screenshots/exports monthly", "Run monthly vulnerability scans and remediation evidence"] },
      { phase: 4, title: "Audit & Report", duration: "4â€“8 weeks", tasks: ["Auditor conducts walkthroughs and samples evidence", "Respond to auditor information requests within SLA", "Remediate any control gaps identified during fieldwork", "Review draft SOC 2 report before finalisation", "Share final Type II report with customers under NDA"] },
    ],
    industries: [
      { name: "B2B SaaS Startups", icon: "ðŸ’»", priority: "High", plan: "SOC 2 Type II is required for most enterprise deals >$50k ACV. Start at Series A or when enterprise deals begin. Use Vanta/Drata to reduce effort by 70%. Target 6-month Type II period." },
      { name: "Data Analytics/AI Companies", icon: "ðŸ¤–", priority: "High", plan: "Add Processing Integrity criteria. Enterprise customers require evidence of data accuracy and completeness. AI model governance increasingly included in audit scope." },
      { name: "Healthcare SaaS (US)", icon: "ðŸ¥", priority: "Critical", plan: "SOC 2 + HIPAA BAA required for healthcare customers. Overlap is significant â€” shared evidence. Add Availability criteria for uptime commitments." },
      { name: "FinTech/Payment Tech", icon: "ðŸ’³", priority: "Critical", plan: "SOC 2 + PCI-DSS + SOX IT controls for public companies. Add Confidentiality criteria for financial data. Consider SOC 1 Type II for financial reporting impact." },
    ],
    usecases: ["Enterprise B2B sales enablement", "Vendor security questionnaire responses", "Cyber insurance qualification", "Customer trust and transparency"],
    related: ["iso27001", "nist-csf", "pci-dss"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // COBIT
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "cobit", short: "COBIT 2019", name: "Control Objectives for Information Technology",
    org: "ISACA", region: "ðŸŒ Global", type: "IT Governance Framework", mandatory: "Voluntary",
    focus: "IT governance & risk", color: "#a78bfa", icon: "ðŸ”„", category: "practical",
    overview: "COBIT 2019 (released 2018) is ISACA's flagship IT governance framework. It provides a comprehensive model for governing and managing enterprise IT, bridging the gap between technical security controls and board-level business objectives. COBIT is used by internal auditors, CISOs, and CIOs to demonstrate alignment between IT and business strategy, manage risk, and ensure compliance. It integrates with ISO 38500 (IT governance), ITIL (IT service management), TOGAF (enterprise architecture), and ISO 27001 (security).",
    clauses: [
      { num: "EDM01", title: "Ensure Governance Framework Setting & Maintenance", desc: "Governance framework analysis and design; stakeholder needs evaluation; governance components" },
      { num: "EDM02", title: "Ensure Benefits Delivery", desc: "Value optimisation; portfolio and programme management; benefits realisation" },
      { num: "EDM03", title: "Ensure Risk Optimisation", desc: "Risk management strategy; enterprise risk appetite; risk tolerance setting" },
      { num: "EDM04", title: "Ensure Resource Optimisation", desc: "Resource requirements; resource allocation; resource performance optimisation" },
      { num: "EDM05", title: "Ensure Stakeholder Transparency", desc: "Stakeholder reporting; communication of IT performance and compliance" },
      { num: "APO12", title: "Managed Risk", desc: "Risk data collection; risk profile; risk response; risk awareness" },
      { num: "APO13", title: "Managed Security", desc: "Security requirements; ISMS establishment; monitor and review security" },
      { num: "BAI06", title: "Managed IT Changes", desc: "Change management process; emergency change; change review" },
      { num: "DSS05", title: "Managed Security Services", desc: "Protect endpoints, manage network/connectivity security, manage sensitive documents" },
      { num: "DSS06", title: "Managed Business Process Controls", desc: "Define business process controls; manage errors and exceptions; secure information" },
      { num: "MEA01", title: "Managed Performance & Conformance Monitoring", desc: "Monitor and evaluate IT performance against targets; compliance reporting" },
      { num: "MEA02", title: "Managed System of Internal Control", desc: "Monitor internal controls effectiveness; perform control assessments" },
      { num: "MEA03", title: "Managed Compliance", desc: "Identify external compliance requirements; optimise compliance response" },
    ],
    controls: "40 governance and management objectives across 5 domains. 6 Design Factors for tailoring: enterprise strategy, risk profile, IT-related issues, threat landscape, compliance, IT adoption source (in-house/outsourced)",
    toolkit: [
      { name: "ISACA COBIT 2019 Online", purpose: "Official COBIT 2019 framework, guides, and process reference documents", type: "Paid (ISACA member discount)", url: "https://www.isaca.org/resources/cobit" },
      { name: "RSA Archer GRC", purpose: "Enterprise GRC platform supporting COBIT objective mapping and maturity assessment", type: "Paid", url: "https://www.archerirm.com" },
      { name: "ServiceNow IRM", purpose: "Integrated Risk Management with COBIT process alignment", type: "Paid", url: "https://www.servicenow.com/products/integrated-risk-management.html" },
      { name: "ISACA COBIT Assessment Programme", purpose: "Official maturity capability assessment tool for all 40 objectives", type: "Paid", url: "https://www.isaca.org/resources/cobit" },
      { name: "MetricStream GRC", purpose: "GRC platform with COBIT process controls and audit management", type: "Paid", url: "https://www.metricstream.com" },
    ],
    implementation: [
      { phase: 1, title: "Governance Design", duration: "4â€“6 weeks", tasks: ["Apply 6 Design Factors to tailor COBIT to your organisation", "Identify governance and management objectives in scope", "Define target capability levels (0â€“5 scale) for each objective", "Map COBIT objectives to existing frameworks (ISO 27001, NIST CSF)", "Present governance design to board for approval"] },
      { phase: 2, title: "Current State Assessment", duration: "3â€“4 weeks", tasks: ["Assess current capability level for each in-scope objective", "Interview process owners for evidence of current practices", "Document gaps between current and target capability", "Prioritise objectives by business impact and risk"] },
      { phase: 3, title: "Improvement Roadmap", duration: "2â€“3 weeks", tasks: ["Create roadmap from capability gaps", "Estimate effort, cost, and timeline for each improvement", "Align roadmap with enterprise strategy and risk appetite", "Define KGIs (Key Goal Indicators) and KPIs for each objective"] },
      { phase: 4, title: "Implement & Measure", duration: "12â€“24 months", tasks: ["Implement prioritised improvements per roadmap", "Track KGI/KPI metrics monthly", "Annual COBIT maturity reassessment", "Report progress to board via IT governance dashboard"] },
    ],
    industries: [
      { name: "Large Enterprises/Banks", icon: "ðŸ¦", priority: "High", plan: "COBIT is ideal for organisations where IT governance maturity needs to be demonstrated to boards and regulators. Banking boards require visibility into IT risk that COBIT provides structurally." },
      { name: "Government & Public Sector", icon: "ðŸ›", priority: "High", plan: "COBIT aligns with public sector IT governance requirements. MEA03 (compliance) supports regulatory reporting. APO12 (risk) supports Treasury risk reporting." },
      { name: "IT Auditors (CISA)", icon: "ðŸ”", priority: "High", plan: "CISA exam and auditing work heavily uses COBIT. MEA01, MEA02, MEA03 are core audit domains. Understanding COBIT is essential for IT audit career." },
    ],
    usecases: ["Board-level IT governance reporting", "IT audit framework (CISA)", "ISACA certification study", "Enterprise risk management", "IT-business alignment"],
    related: ["nist-csf", "iso27001", "soc2"],
  },

  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  // ISO 27701
  // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
  {
    id: "iso27701", short: "ISO 27701", name: "Privacy Information Management System",
    org: "ISO/IEC", region: "ðŸŒ Global", type: "Certifiable Extension", mandatory: "Voluntary",
    focus: "Privacy ISMS", color: "#dbeafe", icon: "ðŸ”’", category: "iso",
    overview: "ISO/IEC 27701:2019 extends ISO/IEC 27001 to establish a Privacy Information Management System (PIMS). It defines additional controls for both PII Controllers (entities that decide why and how data is processed) and PII Processors (entities that process data on behalf of controllers). It maps directly to GDPR, making it a powerful tool for demonstrating GDPR accountability. Organisations certified to ISO 27001 can extend their certification to include ISO 27701.",
    clauses: [
      { num: "6.2", title: "ISO 27001 PIMS Additions", desc: "Privacy-specific context, objectives, and risk considerations added to existing ISO 27001 ISMS" },
      { num: "7", title: "PIMS-Specific Controls for All Orgs", desc: "Privacy conditions in contracts, privacy impact assessment, privacy notices, data minimisation, consent" },
      { num: "8", title: "PII Controller Controls", desc: "Consent management, data subject rights (access, erasure, portability), purpose limitation, third-party disclosure" },
      { num: "9", title: "PII Processor Controls", desc: "Processor-specific obligations, sub-processor management, cross-border transfer mechanisms, customer instructions" },
      { num: "Annex A", title: "PIMS Controls Mapping", desc: "Extension of ISO 27002 controls with privacy-specific implementation guidance" },
      { num: "Annex C", title: "GDPR Mapping", desc: "Direct mapping between ISO 27701 controls and GDPR Articles 5, 6, 9, 13, 14, 15-20, 25, 28, 32, 33, 35" },
    ],
    controls: "31 additional controls for PII controllers + 18 additional controls for PII processors, extending ISO 27002 Annex A with privacy implementation guidance",
    toolkit: [
      { name: "OneTrust Privacy Management", purpose: "PIMS workflow support: ROPA, DPIA, consent, DSAR management", type: "Paid", url: "https://www.onetrust.com" },
      { name: "ISMS.online (ISO 27701 module)", purpose: "ISO 27701 certification documentation alongside ISO 27001", type: "Paid", url: "https://www.isms.online" },
      { name: "Privacy Impact Assessment Tools (ICO)", purpose: "Free DPIA toolkit from UK Information Commissioner's Office", type: "Free", url: "https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/accountability-and-governance/data-protection-impact-assessments/" },
      { name: "CNIL GDPR Guide for Developers", purpose: "Technical privacy controls implementation guide", type: "Free", url: "https://www.cnil.fr/en/gdpr-developers-guide" },
    ],
    implementation: [
      { phase: 1, title: "Extend ISO 27001 ISMS", duration: "2â€“4 weeks", tasks: ["Review existing ISO 27001 ISMS for privacy gaps", "Update ISMS scope to include personal data processing", "Identify PII Controller vs Processor roles for each processing activity", "Assign privacy roles: DPO, privacy officer, data owners"] },
      { phase: 2, title: "Privacy Risk Assessment", duration: "2â€“4 weeks", tasks: ["Extend ISO 27001 risk assessment to include privacy risks", "Conduct DPIAs for high-risk processing (Art. 35 GDPR)", "Map all personal data flows (data mapping/ROPA)", "Assess cross-border transfer mechanisms adequacy"] },
      { phase: 3, title: "Implement Privacy Controls", duration: "6â€“12 weeks", tasks: ["Implement consent management and preferences centre", "Build data subject rights portal (access, erasure, portability)", "Update processor contracts with GDPR-compliant DPA clauses (Art. 28)", "Implement data minimisation and retention/deletion automation"] },
      { phase: 4, title: "Certification Extension", duration: "4â€“8 weeks", tasks: ["Engage existing ISO 27001 certification body for 27701 extension", "Stage 1: Document review of PIMS additions", "Stage 2: On-site assessment of privacy control implementation", "Obtain combined ISO 27001/27701 certification"] },
    ],
    industries: [
      { name: "SaaS/Tech (EU market)", icon: "ðŸ’»", priority: "High", plan: "ISO 27701 + GDPR compliance package. Demonstrates accountability to EU enterprise customers. Combined with ISO 27001 it becomes a powerful trust signal." },
      { name: "Healthcare", icon: "ðŸ¥", priority: "High", plan: "Patient data as PII. ISO 27701 controller controls for direct patient care, processor controls for healthcare IT vendors." },
      { name: "HR Tech / Payroll", icon: "ðŸ‘¥", priority: "High", plan: "Employee data is high-sensitivity PII. ISO 27701 processor controls for payroll processors. GDPR Art. 28 DPA requirements." },
    ],
    usecases: ["GDPR accountability demonstration", "Privacy certification for enterprise", "Data processor contract framework", "Privacy by design evidence"],
    related: ["iso27001", "gdpr", "iso27018"],
  },
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// CATEGORY GROUPS
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const categoryGroups = [
  { id: "iso", label: "ISO Standards", color: "#3b82f6", icon: "ðŸŒ" },
  { id: "owasp", label: "OWASP", color: "#f97316", icon: "ðŸ”¥" },
  { id: "nist", label: "NIST", color: "#22c55e", icon: "ðŸ›" },
  { id: "compliance", label: "Compliance", color: "#eab308", icon: "âš–ï¸" },
  { id: "india", label: "India", color: "#f43f5e", icon: "ðŸ‡®ðŸ‡³" },
  { id: "practical", label: "Practical", color: "#14b8a6", icon: "ðŸ› " },
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ROADMAP
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const roadmap = [
  { step: 1, title: "Foundation", color: "#f97316", duration: "0â€“3 months", items: [
    { label: "OWASP Top 10", id: "owasp-top10" }, { label: "OWASP Mobile Top 10", id: "owasp-mobile" },
    { label: "CIS Controls IG1", id: "cis" }, { label: "NIST CSF Basics", id: "nist-csf" }
  ]},
  { step: 2, title: "Governance", color: "#3b82f6", duration: "3â€“9 months", items: [
    { label: "ISO 27001 ISMS", id: "iso27001" }, { label: "ISO 27002 Controls", id: "iso27002" },
    { label: "OWASP ASVS", id: "owasp-asvs" }, { label: "NIST SP 800-61 IR", id: "nist-800-61" }
  ]},
  { step: 3, title: "Operations", color: "#22c55e", duration: "6â€“18 months", items: [
    { label: "CIS Controls IG2", id: "cis" }, { label: "NIST CSF Mapping", id: "nist-csf" },
    { label: "CERT-In Compliance", id: "cert-in" }, { label: "SOC 2 Type II", id: "soc2" }
  ]},
  { step: 4, title: "Cloud & Privacy", color: "#8b5cf6", duration: "12â€“24 months", items: [
    { label: "ISO 27017 Cloud", id: "iso27017" }, { label: "ISO 27701 Privacy", id: "iso27701" },
    { label: "GDPR Compliance", id: "gdpr" }, { label: "NIST SP 800-53", id: "nist-800-53" }
  ]},
  { step: 5, title: "Industry-Specific", color: "#eab308", duration: "18â€“30 months", items: [
    { label: "PCI-DSS v4.0", id: "pci-dss" }, { label: "RBI Framework", id: "rbi" },
    { label: "COBIT 2019", id: "cobit" }, { label: "CIS Controls IG3", id: "cis" }
  ]},
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DETAIL TABS
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const TABS = [
  { id: "overview", label: "Overview", icon: "ðŸ“„" },
  { id: "structure", label: "Structure", icon: "ðŸ—" },
  { id: "toolkit", label: "Toolkit", icon: "ðŸ§°" },
  { id: "implement", label: "Implement", icon: "ðŸ—º" },
  { id: "industries", label: "Industries", icon: "ðŸ­" },
  { id: "related", label: "Related", icon: "ðŸ”—" },
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// MAIN COMPONENT
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function CybersecStandards() {
  const [activeCat, setActiveCat] = React.useState("all");
  const [selected, setSelected] = React.useState(null);
  const [detailTab, setDetailTab] = React.useState("overview");
  const [view, setView] = React.useState("grid");
  const [search, setSearch] = React.useState("");

  const selectedStd = standards.find(s => s.id === selected);
  const filtered = standards.filter(s => {
    const matchCat = activeCat === "all" || s.category === activeCat;
    const matchSearch = !search || s.short.toLowerCase().includes(search.toLowerCase()) || s.name.toLowerCase().includes(search.toLowerCase());
    return matchCat && matchSearch;
  });

  const selectStd = (id) => { setSelected(id); setDetailTab("overview"); setView("grid"); };

  return (
    <div style={{ minHeight: "100vh", background: "#060b12", color: "#e2e8f0", fontFamily: "Georgia, serif", display: "flex", flexDirection: "column" }}>

      {/* â”€â”€ HEADER â”€â”€ */}
      <div style={{ background: "linear-gradient(135deg,#0d1b2e,#0f1923,#07111c)", borderBottom: "1px solid rgba(255,255,255,0.07)", padding: "24px 28px" }}>
        <div style={{ maxWidth: 1400, margin: "0 auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
            <div>
              <div style={{ fontSize: 9, letterSpacing: 5, color: "#6366f1", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 4 }}>CYBERSECURITY REFERENCE ATLAS</div>
              <h1 style={{ margin: 0, fontSize: 26, fontWeight: 400, color: "#f8fafc", lineHeight: 1.1 }}>
                Global Security Standards <span style={{ fontStyle: "italic", color: "#64748b", fontSize: 20 }}>& Frameworks</span>
              </h1>
              <p style={{ margin: "6px 0 0", fontSize: 10, color: "#334155", fontFamily: "monospace", letterSpacing: 1 }}>
                {standards.length} STANDARDS Â· TOOLKITS Â· IMPLEMENTATION PLANS Â· INDUSTRY ROADMAPS
              </p>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end" }}>
              <div style={{ display: "flex", gap: 6 }}>
                {[["grid", "âŠž Standards"], ["roadmap", "âŸ¶ Roadmap"], ["compare", "âŠ™ Compare"]].map(([v, l]) => (
                  <button key={v} onClick={() => { setView(v); setSelected(null); }}
                    style={{ padding: "6px 12px", fontSize: 10, fontFamily: "monospace", letterSpacing: 1, cursor: "pointer", border: `1px solid ${view === v ? "#6366f1" : "rgba(255,255,255,0.1)"}`, background: view === v ? "rgba(99,102,241,0.15)" : "transparent", color: view === v ? "#818cf8" : "#475569", borderRadius: 6, transition: "all 0.2s" }}>
                    {l}
                  </button>
                ))}
              </div>
              {view === "grid" && (
                <input value={search} onChange={e => { setSearch(e.target.value); setSelected(null); }}
                  placeholder="Search standardsâ€¦"
                  style={{ padding: "5px 12px", fontSize: 11, fontFamily: "monospace", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, color: "#e2e8f0", outline: "none", width: 180 }} />
              )}
            </div>
          </div>
          {view === "grid" && (
            <div style={{ display: "flex", gap: 6, marginTop: 16, flexWrap: "wrap" }}>
              <button onClick={() => setActiveCat("all")}
                style={{ padding: "4px 12px", fontSize: 9, fontFamily: "monospace", letterSpacing: 1, cursor: "pointer", border: `1px solid ${activeCat === "all" ? "#fff" : "rgba(255,255,255,0.1)"}`, background: activeCat === "all" ? "rgba(255,255,255,0.1)" : "transparent", color: activeCat === "all" ? "#fff" : "#475569", borderRadius: 100, transition: "all 0.15s" }}>
                ALL ({standards.length})
              </button>
              {categoryGroups.map(g => (
                <button key={g.id} onClick={() => setActiveCat(g.id)}
                  style={{ padding: "4px 12px", fontSize: 9, fontFamily: "monospace", letterSpacing: 1, cursor: "pointer", border: `1px solid ${activeCat === g.id ? g.color : "rgba(255,255,255,0.1)"}`, background: activeCat === g.id ? g.color + "22" : "transparent", color: activeCat === g.id ? g.color : "#475569", borderRadius: 100, transition: "all 0.15s" }}>
                  {g.icon} {g.label.toUpperCase()} ({standards.filter(s => s.category === g.id).length})
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* â”€â”€ BODY â”€â”€ */}
      <div style={{ flex: 1, maxWidth: 1400, margin: "0 auto", width: "100%", padding: "20px 28px", boxSizing: "border-box" }}>

        {/* â•â• ROADMAP VIEW â•â• */}
        {view === "roadmap" && (
          <div style={{ maxWidth: 800, margin: "0 auto" }}>
            <div style={{ textAlign: "center", marginBottom: 28 }}>
              <h2 style={{ fontWeight: 400, fontSize: 20, color: "#94a3b8", margin: 0, fontStyle: "italic" }}>Security Engineer Learning Roadmap</h2>
              <p style={{ color: "#334155", fontSize: 10, fontFamily: "monospace", marginTop: 4, letterSpacing: 2 }}>PROGRESSIVE SKILL DEVELOPMENT â€” STARTUP TO ENTERPRISE</p>
            </div>
            {roadmap.map((step, i) => (
              <div key={step.step} style={{ display: "flex", gap: 0, marginBottom: 0 }}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 44, flexShrink: 0 }}>
                  <div style={{ width: 32, height: 32, borderRadius: "50%", background: step.color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#000", fontFamily: "monospace", flexShrink: 0, zIndex: 1 }}>{step.step}</div>
                  {i < roadmap.length - 1 && <div style={{ width: 2, height: 40, background: `linear-gradient(${step.color}, ${roadmap[i + 1].color})`, marginTop: 2 }} />}
                </div>
                <div style={{ flex: 1, paddingLeft: 16, paddingBottom: 28, paddingTop: 4 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                    <span style={{ fontSize: 10, letterSpacing: 3, color: step.color, textTransform: "uppercase", fontFamily: "monospace" }}>Phase {step.step} â€” {step.title}</span>
                    <span style={{ fontSize: 9, color: "#334155", fontFamily: "monospace" }}>{step.duration}</span>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {step.items.map(item => (
                      <button key={item.label} onClick={() => selectStd(item.id)}
                        style={{ padding: "7px 14px", background: "rgba(255,255,255,0.03)", border: `1px solid ${step.color}33`, borderRadius: 8, fontSize: 11, color: "#94a3b8", cursor: "pointer", fontFamily: "Georgia, serif", transition: "all 0.2s" }}
                        onMouseEnter={e => { e.currentTarget.style.background = step.color + "22"; e.currentTarget.style.borderColor = step.color; e.currentTarget.style.color = "#e2e8f0"; }}
                        onMouseLeave={e => { e.currentTarget.style.background = "rgba(255,255,255,0.03)"; e.currentTarget.style.borderColor = step.color + "33"; e.currentTarget.style.color = "#94a3b8"; }}>
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* â•â• COMPARE VIEW â•â• */}
        {view === "compare" && (
          <div style={{ overflowX: "auto" }}>
            <div style={{ textAlign: "center", marginBottom: 20 }}>
              <h2 style={{ fontWeight: 400, fontSize: 20, color: "#94a3b8", margin: 0, fontStyle: "italic" }}>Standards Comparison Matrix</h2>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "monospace" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                  {["Standard", "Org", "Type", "Region", "Mandatory", "Focus", "Toolkit Tools", "Certifiable"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "8px 12px", color: "#475569", letterSpacing: 2, textTransform: "uppercase", fontSize: 8, fontWeight: 400 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {standards.map((s, i) => {
                  const cat = categoryGroups.find(c => c.id === s.category);
                  return (
                    <tr key={s.id} onClick={() => selectStd(s.id)}
                      style={{ borderBottom: "1px solid rgba(255,255,255,0.03)", cursor: "pointer", background: i % 2 === 0 ? "rgba(255,255,255,0.01)" : "transparent", transition: "background 0.15s" }}
                      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                      onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? "rgba(255,255,255,0.01)" : "transparent"}>
                      <td style={{ padding: "9px 12px" }}><span style={{ color: s.color, fontWeight: 700 }}>{s.short}</span></td>
                      <td style={{ padding: "9px 12px", color: "#64748b" }}>{s.org}</td>
                      <td style={{ padding: "9px 12px" }}><span style={{ padding: "2px 7px", borderRadius: 100, background: cat?.color + "22", color: cat?.color, fontSize: 9 }}>{s.type}</span></td>
                      <td style={{ padding: "9px 12px", color: "#64748b" }}>{s.region}</td>
                      <td style={{ padding: "9px 12px" }}>
                        <span style={{ color: s.mandatory.startsWith("Yes") ? "#ef4444" : s.mandatory === "Voluntary" ? "#22c55e" : "#f59e0b", fontSize: 9 }}>
                          {s.mandatory.startsWith("Yes") ? "âš  " : s.mandatory === "Voluntary" ? "âœ“ " : "â—Ž "}{s.mandatory}
                        </span>
                      </td>
                      <td style={{ padding: "9px 12px", color: "#475569" }}>{s.focus}</td>
                      <td style={{ padding: "9px 12px", color: "#475569" }}>{s.toolkit?.length || 0} tools</td>
                      <td style={{ padding: "9px 12px" }}>
                        <span style={{ color: s.type.includes("Certif") ? "#22c55e" : "#475569", fontSize: 9 }}>
                          {s.type.includes("Certif") ? "âœ“ Yes" : "â€” No"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* â•â• GRID VIEW â•â• */}
        {view === "grid" && (
          <div style={{ display: "flex", gap: 20 }}>
            {/* Cards */}
            <div style={{ flex: 1, minWidth: 0 }}>
              {filtered.length === 0 && (
                <div style={{ textAlign: "center", color: "#334155", padding: "60px 0", fontFamily: "monospace", fontSize: 12 }}>No standards match your search.</div>
              )}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
                {filtered.map(std => {
                  const isSel = selected === std.id;
                  return (
                    <div key={std.id} onClick={() => { setSelected(isSel ? null : std.id); setDetailTab("overview"); }}
                      style={{ background: isSel ? std.color + "11" : "rgba(255,255,255,0.02)", border: `1px solid ${isSel ? std.color : "rgba(255,255,255,0.06)"}`, borderRadius: 10, padding: "14px", cursor: "pointer", transition: "all 0.2s", position: "relative" }}
                      onMouseEnter={e => { if (!isSel) { e.currentTarget.style.borderColor = std.color + "66"; e.currentTarget.style.background = "rgba(255,255,255,0.04)"; } }}
                      onMouseLeave={e => { if (!isSel) { e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)"; e.currentTarget.style.background = "rgba(255,255,255,0.02)"; } }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                        <span style={{ fontSize: 20 }}>{std.icon}</span>
                        <span style={{ fontSize: 8, padding: "2px 6px", borderRadius: 100, background: std.color + "22", color: std.color, fontFamily: "monospace" }}>{std.org}</span>
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: std.color, marginBottom: 2, fontFamily: "monospace" }}>{std.short}</div>
                      <div style={{ fontSize: 10, color: "#94a3b8", lineHeight: 1.4, marginBottom: 8 }}>{std.name}</div>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontSize: 8, color: "#334155", fontFamily: "monospace" }}>{std.region}</span>
                        <span style={{ fontSize: 8, color: std.mandatory.startsWith("Yes") ? "#ef4444" : "#22c55e", fontFamily: "monospace" }}>
                          {std.mandatory.startsWith("Yes") ? "âš  REQ" : "âœ“ OPT"}
                        </span>
                      </div>
                      {std.toolkit && (
                        <div style={{ marginTop: 6, fontSize: 8, color: "#334155", fontFamily: "monospace" }}>
                          ðŸ§° {std.toolkit.length} tools Â· ðŸ—º {std.implementation?.length || 0} phases Â· ðŸ­ {std.industries?.length || 0} industries
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* â”€â”€ DETAIL PANEL â”€â”€ */}
            {selectedStd && (
              <div style={{ width: 420, flexShrink: 0, background: "rgba(255,255,255,0.02)", border: `1px solid ${selectedStd.color}44`, borderRadius: 12, overflow: "hidden", alignSelf: "flex-start", position: "sticky", top: 20, maxHeight: "calc(100vh - 140px)", display: "flex", flexDirection: "column" }}>

                {/* Panel Header */}
                <div style={{ padding: "16px 18px 0", background: `linear-gradient(135deg, ${selectedStd.color}11, transparent)`, flexShrink: 0 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 24 }}>{selectedStd.icon}</span>
                        <div>
                          <div style={{ fontSize: 16, fontWeight: 700, color: selectedStd.color, fontFamily: "monospace" }}>{selectedStd.short}</div>
                          <div style={{ fontSize: 10, color: "#64748b", lineHeight: 1.3, maxWidth: 300 }}>{selectedStd.name}</div>
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 6, marginTop: 8, marginBottom: 10, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 8, padding: "2px 7px", borderRadius: 100, background: "rgba(255,255,255,0.07)", color: "#64748b", fontFamily: "monospace" }}>{selectedStd.region}</span>
                        <span style={{ fontSize: 8, padding: "2px 7px", borderRadius: 100, background: "rgba(255,255,255,0.07)", color: "#64748b", fontFamily: "monospace" }}>{selectedStd.type}</span>
                        <span style={{ fontSize: 8, padding: "2px 7px", borderRadius: 100, background: selectedStd.mandatory.startsWith("Yes") ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)", color: selectedStd.mandatory.startsWith("Yes") ? "#ef4444" : "#22c55e", fontFamily: "monospace" }}>
                          {selectedStd.mandatory.startsWith("Yes") ? "âš  " : "âœ“ "}{selectedStd.mandatory}
                        </span>
                      </div>
                    </div>
                    <button onClick={() => setSelected(null)} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#475569", cursor: "pointer", borderRadius: 6, width: 26, height: 26, fontSize: 12, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>âœ•</button>
                  </div>

                  {/* Tab Bar */}
                  <div style={{ display: "flex", gap: 0, borderBottom: "1px solid rgba(255,255,255,0.06)", marginTop: 4, overflowX: "auto" }}>
                    {TABS.map(t => (
                      <button key={t.id} onClick={() => setDetailTab(t.id)}
                        style={{ padding: "7px 8px", border: "none", cursor: "pointer", background: "transparent", borderBottom: `2px solid ${detailTab === t.id ? selectedStd.color : "transparent"}`, color: detailTab === t.id ? selectedStd.color : "#475569", fontSize: 9, fontFamily: "monospace", letterSpacing: 0.5, whiteSpace: "nowrap", transition: "all 0.15s", flexShrink: 0 }}>
                        {t.icon} {t.label.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Panel Content */}
                <div style={{ padding: "14px 18px", overflowY: "auto", flex: 1 }}>

                  {/* â”€â”€ OVERVIEW TAB â”€â”€ */}
                  {detailTab === "overview" && (
                    <div>
                      <p style={{ margin: "0 0 14px", fontSize: 12, lineHeight: 1.85, color: "#94a3b8" }}>{selectedStd.overview}</p>
                      <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 12 }}>
                        <p style={{ margin: "0 0 8px", fontSize: 9, color: "#334155", fontFamily: "monospace", letterSpacing: 2 }}>USE CASES</p>
                        {selectedStd.usecases.map((u, i) => (
                          <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 6 }}>
                            <span style={{ color: selectedStd.color, fontSize: 10, marginTop: 1 }}>â†’</span>
                            <span style={{ fontSize: 11, color: "#94a3b8" }}>{u}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* â”€â”€ STRUCTURE TAB â”€â”€ */}
                  {detailTab === "structure" && (
                    <div>
                      {selectedStd.clauses.length > 0 ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {selectedStd.clauses.map(c => (
                            <div key={c.num} style={{ padding: "10px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 8, borderLeft: `3px solid ${selectedStd.color}` }}>
                              <div style={{ display: "flex", gap: 8, alignItems: "baseline", marginBottom: 3 }}>
                                <span style={{ fontSize: 9, color: selectedStd.color, fontFamily: "monospace", letterSpacing: 1, flexShrink: 0 }}>{c.num}</span>
                                <span style={{ fontSize: 11, color: "#e2e8f0", fontWeight: 600 }}>{c.title}</span>
                              </div>
                              <p style={{ margin: 0, fontSize: 10, color: "#64748b", lineHeight: 1.5 }}>{c.desc}</p>
                            </div>
                          ))}
                        </div>
                      ) : null}
                      <div style={{ marginTop: 12, padding: "10px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 8, fontSize: 11, color: "#64748b", lineHeight: 1.6, borderLeft: "3px solid rgba(255,255,255,0.1)" }}>
                        <strong style={{ color: "#94a3b8", fontSize: 9, fontFamily: "monospace", letterSpacing: 1, display: "block", marginBottom: 4 }}>CONTROLS & SCOPE</strong>
                        {selectedStd.controls}
                      </div>
                    </div>
                  )}

                  {/* â”€â”€ TOOLKIT TAB â”€â”€ */}
                  {detailTab === "toolkit" && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      <p style={{ margin: "0 0 10px", fontSize: 9, color: "#334155", fontFamily: "monospace", letterSpacing: 2 }}>TOOLS & RESOURCES</p>
                      {(selectedStd.toolkit || []).map((tool, i) => (
                        <div key={i} style={{ padding: "10px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.06)" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 4 }}>
                            <span style={{ fontSize: 12, color: selectedStd.color, fontWeight: 600 }}>{tool.name}</span>
                            <span style={{ fontSize: 8, padding: "2px 6px", borderRadius: 100, background: tool.type === "Free" ? "rgba(34,197,94,0.15)" : tool.type === "Paid" ? "rgba(239,68,68,0.15)" : "rgba(245,158,11,0.15)", color: tool.type === "Free" ? "#22c55e" : tool.type === "Paid" ? "#f87171" : "#f59e0b", fontFamily: "monospace", flexShrink: 0 }}>
                              {tool.type}
                            </span>
                          </div>
                          <p style={{ margin: 0, fontSize: 10, color: "#64748b", lineHeight: 1.5 }}>{tool.purpose}</p>
                          {tool.url && <a href={tool.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 9, color: selectedStd.color + "99", fontFamily: "monospace", textDecoration: "none", display: "block", marginTop: 4 }}>{tool.url.replace("https://", "").split("/")[0]}</a>}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* â”€â”€ IMPLEMENT TAB â”€â”€ */}
                  {detailTab === "implement" && (
                    <div>
                      <p style={{ margin: "0 0 12px", fontSize: 9, color: "#334155", fontFamily: "monospace", letterSpacing: 2 }}>STEP-BY-STEP IMPLEMENTATION</p>
                      {(selectedStd.implementation || []).map((phase, pi) => (
                        <div key={pi} style={{ marginBottom: 14 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                            <div style={{ width: 22, height: 22, borderRadius: "50%", background: selectedStd.color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: "#000", fontFamily: "monospace", flexShrink: 0 }}>{phase.phase}</div>
                            <div>
                              <div style={{ fontSize: 11, color: "#e2e8f0", fontWeight: 600 }}>{phase.title}</div>
                              <div style={{ fontSize: 9, color: "#475569", fontFamily: "monospace" }}>{phase.duration}</div>
                            </div>
                          </div>
                          <div style={{ paddingLeft: 30 }}>
                            {phase.tasks.map((task, ti) => (
                              <div key={ti} style={{ display: "flex", gap: 7, alignItems: "flex-start", marginBottom: 5 }}>
                                <span style={{ color: selectedStd.color + "88", fontSize: 10, flexShrink: 0, marginTop: 1 }}>â–¸</span>
                                <span style={{ fontSize: 10, color: "#64748b", lineHeight: 1.5 }}>{task}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* â”€â”€ INDUSTRIES TAB â”€â”€ */}
                  {detailTab === "industries" && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                      <p style={{ margin: "0 0 6px", fontSize: 9, color: "#334155", fontFamily: "monospace", letterSpacing: 2 }}>INDUSTRY IMPLEMENTATION PLANS</p>
                      {(selectedStd.industries || []).map((ind, ii) => (
                        <div key={ii} style={{ padding: "12px", background: "rgba(255,255,255,0.03)", borderRadius: 8, border: `1px solid ${ind.priority === "Critical" ? "rgba(239,68,68,0.2)" : ind.priority === "Mandatory" ? "rgba(239,68,68,0.3)" : "rgba(255,255,255,0.06)"}` }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                            <span style={{ fontSize: 13 }}>{ind.icon} <span style={{ fontSize: 11, color: "#e2e8f0", fontWeight: 600 }}>{ind.name}</span></span>
                            <span style={{ fontSize: 8, padding: "2px 7px", borderRadius: 100, fontFamily: "monospace", background: ind.priority === "Critical" || ind.priority === "Mandatory" ? "rgba(239,68,68,0.15)" : ind.priority === "High" ? "rgba(245,158,11,0.15)" : "rgba(34,197,94,0.15)", color: ind.priority === "Critical" || ind.priority === "Mandatory" ? "#f87171" : ind.priority === "High" ? "#fbbf24" : "#4ade80" }}>
                              {ind.priority}
                            </span>
                          </div>
                          <p style={{ margin: 0, fontSize: 10, color: "#64748b", lineHeight: 1.6 }}>{ind.plan}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* â”€â”€ RELATED TAB â”€â”€ */}
                  {detailTab === "related" && (
                    <div>
                      <p style={{ margin: "0 0 12px", fontSize: 9, color: "#334155", fontFamily: "monospace", letterSpacing: 2 }}>RELATED STANDARDS</p>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        {(selectedStd.related || []).map(rid => {
                          const rel = standards.find(s => s.id === rid);
                          return rel ? (
                            <div key={rid} onClick={() => { setSelected(rid); setDetailTab("overview"); }}
                              style={{ padding: "10px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 8, cursor: "pointer", border: "1px solid rgba(255,255,255,0.06)", transition: "all 0.2s" }}
                              onMouseEnter={e => { e.currentTarget.style.borderColor = rel.color; e.currentTarget.style.background = rel.color + "11"; }}
                              onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)"; e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span style={{ fontSize: 16 }}>{rel.icon}</span>
                                <div>
                                  <div style={{ fontSize: 12, color: rel.color, fontFamily: "monospace" }}>{rel.short}</div>
                                  <div style={{ fontSize: 9, color: "#475569" }}>{rel.name}</div>
                                </div>
                              </div>
                            </div>
                          ) : null;
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* â”€â”€ FOOTER â”€â”€ */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", padding: "8px 28px", display: "flex", justifyContent: "space-between", fontSize: 8, color: "#1e293b", fontFamily: "monospace", letterSpacing: 1 }}>
        <span>CYBERSECURITY STANDARDS ATLAS â€” FOR REFERENCE & STUDY ONLY</span>
        <span>ISO Â· OWASP Â· NIST Â· PCI Â· GDPR Â· CERT-IN Â· RBI Â· CIS Â· SOC2 Â· COBIT</span>
      </div>
    </div>
  );
}

