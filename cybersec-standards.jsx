const standards = [
  {
    id: "iso27001",
    short: "ISO 27001",
    name: "Information Security Management System",
    org: "ISO/IEC",
    region: " Global",
    type: "Certifiable",
    mandatory: "Voluntary",
    focus: "ISMS",
    color: "#3b82f6",
    
    category: "iso",
    overview: "ISO/IEC 27001 is the international standard for establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS). It provides a risk-based approach to managing sensitive company information.",
    clauses: [
      { num: "4", title: "Context of Organization", desc: "Understand internal/external issues, interested parties, and ISMS scope" },
      { num: "5", title: "Leadership", desc: "Top management commitment, security policy, and organizational roles" },
      { num: "6", title: "Planning", desc: "Risk assessment, risk treatment, and security objectives" },
      { num: "7", title: "Support", desc: "Resources, competence, awareness, communication, and documentation" },
      { num: "8", title: "Operation", desc: "Implementing risk treatment plans and controls" },
      { num: "9", title: "Performance Evaluation", desc: "Monitoring, measurement, internal audit, and management review" },
      { num: "10", title: "Improvement", desc: "Nonconformity correction and continual improvement" },
    ],
    controls: "93 Annex A controls (2022 version) grouped into: Organizational, People, Physical, Technological",
    usecases: ["Enterprise compliance certification", "VAPT & audit alignment", "Startup security baseline", "Vendor due diligence"],
    related: ["iso27002", "iso27017", "iso27701"],
    reference: "https://www.iso.org/isoiec-27001-information-security.html",
  },
  {
    id: "iso27002",
    short: "ISO 27002",
    name: "Security Controls Guidelines",
    org: "ISO/IEC",
    region: " Global",
    type: "Guideline",
    mandatory: "Voluntary",
    focus: "Control implementation",
    color: "#60a5fa",
    
    category: "iso",
    overview: "ISO/IEC 27002 provides guidance for implementing the information security controls listed in ISO/IEC 27001 Annex A. It is the companion standard that explains how to apply each of the 93 controls.",
    clauses: [],
    controls: "Detailed implementation guidance for all 93 ISO 27001 controls with attributes, purpose, and implementation notes",
    usecases: ["Controls implementation reference", "Policy writing guide", "Audit preparation", "Security architecture design"],
    related: ["iso27001"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "iso27017",
    short: "ISO 27017",
    name: "Cloud Security Controls",
    org: "ISO/IEC",
    region: " Global",
    type: "Guideline",
    mandatory: "Voluntary",
    focus: "Cloud security",
    color: "#93c5fd",
    
    category: "iso",
    overview: "ISO/IEC 27017 provides cloud-specific security controls extending ISO 27001/27002. It defines responsibilities for both cloud service providers (CSPs) and cloud service customers (CSCs).",
    clauses: [],
    controls: "7 additional cloud-specific controls beyond ISO 27002 covering virtual machine hardening, cloud admin operations, monitoring, and shared responsibilities",
    usecases: ["AWS/Azure/GCP security baseline", "Cloud vendor assessment", "Multi-cloud governance", "SaaS security"],
    related: ["iso27001", "iso27018"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "iso27018",
    short: "ISO 27018",
    name: "PII Protection in Cloud",
    org: "ISO/IEC",
    region: " Global",
    type: "Guideline",
    mandatory: "Voluntary",
    focus: "Privacy in cloud",
    color: "#bfdbfe",
    
    category: "iso",
    overview: "ISO/IEC 27018 establishes controls for protection of Personally Identifiable Information (PII) in public cloud computing environments, acting as a bridge between cloud security and privacy compliance.",
    clauses: [],
    controls: "Controls addressing: consent, data minimization, transparency, accountability, and PII breach notification in cloud services",
    usecases: ["GDPR cloud compliance", "Healthcare cloud data", "PII data processor obligations", "Cloud privacy audits"],
    related: ["iso27001", "iso27701"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "iso27701",
    short: "ISO 27701",
    name: "Privacy Information Management",
    org: "ISO/IEC",
    region: " Global",
    type: "Certifiable Extension",
    mandatory: "Voluntary",
    focus: "Privacy ISMS",
    color: "#dbeafe",
    
    category: "iso",
    overview: "ISO/IEC 27701 extends ISO 27001 to include privacy controls, creating a Privacy Information Management System (PIMS). It maps to GDPR and other privacy regulations, making it a key tool for demonstrating privacy compliance.",
    clauses: [],
    controls: "Privacy-specific controls for both PII controllers and processors. Maps directly to GDPR obligations including Articles 5, 6, 9, 17, 20, 25, 28, 32, 33, and 35.",
    usecases: ["GDPR accountability demonstration", "Privacy compliance certification", "Data processor contracts", "Privacy by design implementation"],
    related: ["iso27001", "gdpr"],
    reference: "https://www.iso.org/standard/71670.html",
  },
  {
    id: "owasp-top10",
    short: "OWASP Top 10",
    name: "Web Application Security Risks",
    org: "OWASP",
    region: " Global",
    type: "Best Practice",
    mandatory: "No",
    focus: "Web app security",
    color: "#f97316",
    
    category: "owasp",
    overview: "The OWASP Top 10 is the most recognized list of critical web application security risks. Updated periodically based on real-world data from vulnerability assessments, penetration tests, and bug bounty programs worldwide.",
    clauses: [
      { num: "A01", title: "Broken Access Control", desc: "Moving up from #5; 94% of apps tested had some form of broken access control" },
      { num: "A02", title: "Cryptographic Failures", desc: "Formerly Sensitive Data Exposure; focus on failures related to cryptography" },
      { num: "A03", title: "Injection", desc: "SQL, NoSQL, OS, LDAP injection — drops to third position" },
      { num: "A04", title: "Insecure Design", desc: "New 2021 category focusing on design flaws, not implementation bugs" },
      { num: "A05", title: "Security Misconfiguration", desc: "89% of apps tested; includes XML External Entities (XXE)" },
      { num: "A06", title: "Vulnerable & Outdated Components", desc: "Formerly Using Known Vulnerable Components" },
      { num: "A07", title: "ID & Authentication Failures", desc: "Formerly Broken Authentication" },
      { num: "A08", title: "Software & Data Integrity Failures", desc: "New 2021; includes insecure deserialization" },
      { num: "A09", title: "Security Logging & Monitoring Failures", desc: "Formerly Insufficient Logging & Monitoring" },
      { num: "A10", title: "Server-Side Request Forgery (SSRF)", desc: "New 2021; added based on community survey despite low incidence rate" },
    ],
    controls: "Each risk includes: description, example attack scenarios, prevention techniques, and references",
    usecases: ["VAPT report baseline", "Developer security training", "Code review checklist", "Bug bounty scope definition"],
    related: ["owasp-asvs", "owasp-mobile"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "owasp-asvs",
    short: "OWASP ASVS",
    name: "Application Security Verification Standard",
    org: "OWASP",
    region: " Global",
    type: "Best Practice",
    mandatory: "No",
    focus: "Secure SDLC verification",
    color: "#fb923c",
    
    category: "owasp",
    overview: "ASVS provides a framework of security requirements and controls that developers and security testers can use to define, build, and test secure web applications. It defines three security verification levels.",
    clauses: [
      { num: "L1", title: "Level 1 – Basic", desc: "Minimum security for all applications. Can be verified through penetration testing alone" },
      { num: "L2", title: "Level 2 – Standard", desc: "For apps handling sensitive data. Requires security testing and code review" },
      { num: "L3", title: "Level 3 – Advanced", desc: "For critical applications (banking, healthcare). Full architecture review + formal verification" },
    ],
    controls: "14 categories including: Architecture, Authentication, Session Management, Access Control, Validation, Cryptography, Error Handling, Data Protection, API Security, Config, IAM",
    usecases: ["Secure SDLC requirements", "Security acceptance criteria", "Penetration test scope definition", "Third-party app assessment"],
    related: ["owasp-top10"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "owasp-mobile",
    short: "OWASP Mobile Top 10",
    name: "Mobile Application Security Risks",
    org: "OWASP",
    region: " Global",
    type: "Best Practice",
    mandatory: "No",
    focus: "Mobile app security",
    color: "#fdba74",
    
    category: "owasp",
    overview: "The OWASP Mobile Top 10 lists the most critical security risks for mobile applications (iOS and Android). The 2024 version reflects the current mobile threat landscape including privacy concerns and supply chain issues.",
    clauses: [
      { num: "M1", title: "Improper Credential Usage", desc: "Hardcoded credentials, insecure credential transmission" },
      { num: "M2", title: "Inadequate Supply Chain Security", desc: "Third-party libraries and SDKs with vulnerabilities" },
      { num: "M3", title: "Insecure Authentication & Authorization", desc: "Broken auth, client-side authorization checks" },
      { num: "M4", title: "Insufficient Input/Output Validation", desc: "Injection attacks targeting mobile app interfaces" },
      { num: "M5", title: "Insecure Communication", desc: "Cleartext transmission, invalid certificate validation" },
      { num: "M6", title: "Inadequate Privacy Controls", desc: "Over-collection of PII, tracking without consent" },
      { num: "M7", title: "Insufficient Binary Protections", desc: "Lack of obfuscation, anti-tampering, root detection" },
      { num: "M8", title: "Security Misconfiguration", desc: "Backup enabled, debug logs, exported components" },
      { num: "M9", title: "Insecure Data Storage", desc: "Plaintext storage, SharedPreferences exposure" },
      { num: "M10", title: "Insufficient Cryptography", desc: "Weak algorithms, hardcoded keys, improper key management" },
    ],
    controls: "Prevention techniques specific to both Android and iOS platforms for each risk",
    usecases: ["Android/iOS VAPT baseline", "Mobile SDLC security", "App store compliance prep", "Mobile bug bounty"],
    related: ["owasp-top10", "owasp-asvs"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "nist-csf",
    short: "NIST CSF",
    name: "Cybersecurity Framework",
    org: "NIST",
    region: " US (Global Adoption)",
    type: "Framework",
    mandatory: "Voluntary",
    focus: "Risk management",
    color: "#22c55e",
    
    category: "nist",
    overview: "The NIST Cybersecurity Framework (CSF) 2.0 provides a flexible, risk-based approach to managing cybersecurity risk. Originally for US critical infrastructure, it is now widely adopted globally across industries and company sizes.",
    clauses: [
      { num: "GV", title: "Govern (NEW in CSF 2.0)", desc: "Organizational context, risk strategy, supply chain risk, oversight" },
      { num: "ID", title: "Identify", desc: "Asset management, risk assessment, business environment understanding" },
      { num: "PR", title: "Protect", desc: "Access control, data security, training, platform security, resilience" },
      { num: "DE", title: "Detect", desc: "Continuous monitoring, adverse event analysis, detection processes" },
      { num: "RS", title: "Respond", desc: "Incident management, analysis, mitigation, communication" },
      { num: "RC", title: "Recover", desc: "Recovery planning, improvements, communication during recovery" },
    ],
    controls: "Framework Core with Functions, Categories, and Subcategories. Maps to ISO 27001, NIST 800-53, CIS Controls, COBIT and other frameworks",
    usecases: ["Executive risk communication", "Security program assessment", "Vendor risk management", "Board-level reporting"],
    related: ["nist-800-53", "nist-800-61", "cis"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "nist-800-53",
    short: "NIST SP 800-53",
    name: "Security & Privacy Controls",
    org: "NIST",
    region: " US Federal",
    type: "Control Catalog",
    mandatory: "Mandatory (Federal)",
    focus: "Federal system controls",
    color: "#4ade80",
    
    category: "nist",
    overview: "NIST SP 800-53 Rev 5 provides the most comprehensive catalog of security and privacy controls for federal information systems and organizations. It is the foundational control standard for US government agencies and their contractors.",
    clauses: [
      { num: "AC", title: "Access Control", desc: "20 controls for managing system access" },
      { num: "AU", title: "Audit & Accountability", desc: "16 controls for logging and audit" },
      { num: "CM", title: "Configuration Management", desc: "14 controls for baseline configs" },
      { num: "IA", title: "Identification & Authentication", desc: "13 controls for identity management" },
      { num: "IR", title: "Incident Response", desc: "10 controls for incident handling" },
      { num: "SC", title: "System & Comms Protection", desc: "51 controls for network security" },
      { num: "SI", title: "System & Information Integrity", desc: "23 controls for malware/patching" },
    ],
    controls: "20 control families, 1000+ individual controls across low/moderate/high baselines. Rev 5 integrates privacy controls directly",
    usecases: ["FedRAMP authorization", "US federal agency compliance", "Defense contractor requirements (CMMC)", "FISMA compliance"],
    related: ["nist-csf", "nist-800-61"],
    reference: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
  },
  {
    id: "nist-800-61",
    short: "NIST SP 800-61",
    name: "Incident Response Guide",
    org: "NIST",
    region: " US (Global Reference)",
    type: "Guideline",
    mandatory: "Voluntary",
    focus: "Incident response",
    color: "#86efac",
    
    category: "nist",
    overview: "NIST SP 800-61 Rev 2 is the definitive guide for establishing an incident response program. It covers the entire incident lifecycle and is widely used as the industry reference for IR planning and execution.",
    clauses: [
      { num: "1", title: "Preparation", desc: "Establishing IR capability, tools, policies, and team readiness" },
      { num: "2", title: "Detection & Analysis", desc: "Identifying incidents, prioritizing, documenting evidence" },
      { num: "3", title: "Containment, Eradication & Recovery", desc: "Stopping spread, removing threat, restoring systems" },
      { num: "4", title: "Post-Incident Activity", desc: "Lessons learned, root cause analysis, improvement" },
    ],
    controls: "Incident categories, severity classifications, escalation procedures, evidence handling guidelines, and coordination with external parties",
    usecases: ["IR plan development", "SOC playbook creation", "Tabletop exercise design", "Post-breach analysis"],
    related: ["nist-csf", "nist-800-53"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "pci-dss",
    short: "PCI-DSS v4.0",
    name: "Payment Card Industry Data Security Standard",
    org: "PCI SSC",
    region: " Global",
    type: "Compliance Standard",
    mandatory: "Yes (card processing)",
    focus: "Cardholder data protection",
    color: "#eab308",
    
    category: "compliance",
    overview: "PCI-DSS v4.0 (released 2022, effective March 2024) is the mandatory standard for any organization that stores, processes, or transmits payment card data. Non-compliance results in fines, increased transaction fees, and loss of card processing privileges.",
    clauses: [
      { num: "1", title: "Install and Maintain Network Security Controls", desc: "Firewalls, network segmentation, DMZ configuration" },
      { num: "2", title: "Apply Secure Configurations", desc: "Vendor defaults changed, unnecessary services removed" },
      { num: "3", title: "Protect Stored Account Data", desc: "Encryption, masking, key management for stored card data" },
      { num: "4", title: "Protect Data in Transit", desc: "Strong cryptography for cardholder data over open networks" },
      { num: "5", title: "Protect All Systems Against Malware", desc: "Anti-malware, anti-phishing, periodic scanning" },
      { num: "6", title: "Develop & Maintain Secure Systems", desc: "Vulnerability management, secure development, patching" },
      { num: "7", title: "Restrict Access by Business Need", desc: "Least privilege, access control systems" },
      { num: "8", title: "Identify Users and Authenticate Access", desc: "MFA, password requirements, service account management" },
      { num: "9", title: "Restrict Physical Access", desc: "Physical security controls for cardholder data areas" },
      { num: "10", title: "Log and Monitor All Access", desc: "Audit logs, SIEM, log integrity" },
      { num: "11", title: "Test Security Regularly", desc: "Penetration testing, vulnerability scanning, intrusion detection" },
      { num: "12", title: "Support Information Security with Policies", desc: "Security policy, risk assessment, awareness program" },
    ],
    controls: "12 requirements with 300+ sub-requirements. v4.0 adds 13 new requirements including multi-factor authentication expansion",
    usecases: ["Payment gateway compliance", "E-commerce security", "FinTech audits", "Card brand mandates"],
    related: ["iso27001", "nist-csf"],
    reference: "https://www.pcisecuritystandards.org/document_library",
  },
  {
    id: "gdpr",
    short: "GDPR",
    name: "General Data Protection Regulation",
    org: "European Union",
    region: " EU (Extraterritorial)",
    type: "Regulation",
    mandatory: "Yes (EU data subjects)",
    focus: "Personal data protection",
    color: "#6366f1",
    
    category: "compliance",
    overview: "GDPR is the EU's comprehensive data protection law that applies to any organization processing EU residents' personal data, regardless of where the organization is located. Penalties reach €20M or 4% of global annual turnover.",
    clauses: [
      { num: "Art. 5", title: "Data Processing Principles", desc: "Lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity" },
      { num: "Art. 6", title: "Lawful Basis for Processing", desc: "Consent, contract, legal obligation, vital interests, public task, legitimate interests" },
      { num: "Art. 17", title: "Right to Erasure", desc: "Right to be forgotten — deletion upon request under certain conditions" },
      { num: "Art. 20", title: "Right to Data Portability", desc: "Receive personal data in structured, machine-readable format" },
      { num: "Art. 25", title: "Privacy by Design & Default", desc: "Security and privacy built into systems from the ground up" },
      { num: "Art. 32", title: "Security of Processing", desc: "Appropriate technical and organizational security measures" },
      { num: "Art. 33", title: "Breach Notification", desc: "Report to supervisory authority within 72 hours of discovering a breach" },
      { num: "Art. 35", title: "Data Protection Impact Assessment", desc: "DPIA required for high-risk processing activities" },
    ],
    controls: "Data subject rights (access, rectification, erasure, portability, objection), Data Protection Officer (DPO) appointment, Privacy by Design, Standard Contractual Clauses for transfers",
    usecases: ["EU market access", "Data breach response", "Privacy policy compliance", "Vendor DPA agreements"],
    related: ["iso27701", "iso27001"],
    reference: "https://gdpr.eu/",
  },
  {
    id: "cert-in",
    short: "CERT-In",
    name: "Indian Computer Emergency Response Team",
    org: "Ministry of Electronics & IT",
    region: " India",
    type: "Regulation",
    mandatory: "Yes (in India)",
    focus: "Incident reporting",
    color: "#f43f5e",
    
    category: "india",
    overview: "CERT-In (Indian CERT) under MeitY mandates cybersecurity incident reporting for organizations operating in India. The 2022 directions significantly tightened requirements with a 6-hour reporting window and 5-year log retention.",
    clauses: [
      { num: "1", title: "6-Hour Breach Reporting", desc: "Cybersecurity incidents must be reported to CERT-In within 6 hours of detection" },
      { num: "2", title: "Log Retention", desc: "ICT logs must be maintained for 180 days within India's jurisdiction" },
      { num: "3", title: "Mandatory Synchronization", desc: "ICT systems must synchronize clocks with NTP servers of NPTI/NIC" },
      { num: "4", title: "Virtual Asset Registration", desc: "Crypto exchanges/VASPs must maintain KYC records for 5 years" },
      { num: "5", title: "VPN Provider Requirements", desc: "VPN providers must maintain subscriber info for 5 years" },
    ],
    controls: "24 incident types that must be reported including data breaches, ransomware, unauthorized access, critical infrastructure attacks",
    usecases: ["India operations compliance", "SOC reporting procedures", "Cloud provider compliance in India", "BFSI regulatory compliance"],
    related: ["rbi", "iso27001"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "rbi",
    short: "RBI Cybersecurity Framework",
    name: "Reserve Bank of India Cybersecurity",
    org: "Reserve Bank of India",
    region: " India (BFSI)",
    type: "Regulation",
    mandatory: "Yes (Banks/NBFCs)",
    focus: "Banking cybersecurity",
    color: "#fb7185",
    
    category: "india",
    overview: "The RBI Cybersecurity Framework mandates banks, NBFCs, and payment system operators to implement robust cybersecurity controls, report incidents, conduct audits, and maintain cyber resilience. Non-compliance risks regulatory action.",
    clauses: [
      { num: "1", title: "Cybersecurity Policy", desc: "Board-approved cybersecurity policy reviewed annually" },
      { num: "2", title: "IT Architecture", desc: "Defence-in-depth, DMZ, network segmentation requirements" },
      { num: "3", title: "Secure Configuration", desc: "Hardening standards, patch management, baseline configs" },
      { num: "4", title: "Application Security", desc: "Secure SDLC, VAPT before go-live, WAF requirements" },
      { num: "5", title: "Data-at-Rest Encryption", desc: "Critical data encryption using approved algorithms" },
      { num: "6", title: "Risk-Based Transaction Monitoring", desc: "Real-time fraud detection and monitoring" },
      { num: "7", title: "Incident Response", desc: "Cyber crisis management plan, war room setup, 2-6 hour reporting" },
    ],
    controls: "Covers: SOC requirements, SWIFT customer security controls, payment system security, internet banking security, ATM/PoS security",
    usecases: ["Bank IT audits", "NBFC compliance", "Payment gateway approvals", "RBI audit preparation"],
    related: ["cert-in", "pci-dss", "iso27001"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "cis",
    short: "CIS Controls v8",
    name: "Center for Internet Security Controls",
    org: "CIS",
    region: " Global",
    type: "Best Practice",
    mandatory: "No",
    focus: "Practical security baseline",
    color: "#14b8a6",
    
    category: "practical",
    overview: "CIS Controls v8 is the most practical, implementation-focused security framework. 18 prioritized controls with Implementation Groups (IG1/IG2/IG3) allow organizations of any size to adopt controls proportional to their risk profile.",
    clauses: [
      { num: "CIS 1", title: "Inventory and Control of Enterprise Assets", desc: "Know every device on your network — managed and unmanaged" },
      { num: "CIS 2", title: "Inventory and Control of Software Assets", desc: "Software allowlisting and unauthorized software detection" },
      { num: "CIS 3", title: "Data Protection", desc: "Data classification, handling, and retention management" },
      { num: "CIS 4", title: "Secure Configuration of Enterprise Assets & Software", desc: "Hardening baselines for OSes, apps, and network devices" },
      { num: "CIS 5", title: "Account Management", desc: "Manage the lifecycle of all system and application accounts" },
      { num: "CIS 6", title: "Access Control Management", desc: "Least privilege, role-based access control" },
      { num: "CIS 7", title: "Continuous Vulnerability Management", desc: "Regular scanning, remediation prioritization, SLA tracking" },
      { num: "CIS 8", title: "Audit Log Management", desc: "Collect, alert, review, and retain audit logs" },
      { num: "CIS 9", title: "Email and Web Browser Protections", desc: "Anti-phishing, web filtering, email security gateways" },
      { num: "CIS 10", title: "Malware Defenses", desc: "Anti-malware, behavioral detection, script blocking" },
      { num: "CIS 11", title: "Data Recovery", desc: "Backup, restoration testing, offline backups" },
      { num: "CIS 12", title: "Network Infrastructure Management", desc: "Secure network devices, patch management, routing security" },
      { num: "CIS 13", title: "Network Monitoring and Defense", desc: "IDS/IPS, network flow monitoring, SIEM" },
      { num: "CIS 14", title: "Security Awareness & Skills Training", desc: "Role-based training, phishing simulations" },
      { num: "CIS 15", title: "Service Provider Management", desc: "Third-party risk management, vendor security assessments" },
      { num: "CIS 16", title: "Application Software Security", desc: "Secure SDLC, SAST/DAST, dependency management" },
      { num: "CIS 17", title: "Incident Response Management", desc: "IR plan, tabletop exercises, post-incident review" },
      { num: "CIS 18", title: "Penetration Testing", desc: "Regular red team exercises and external penetration tests" },
    ],
    controls: "Implementation Groups: IG1 (basic cyber hygiene), IG2 (adds 74 safeguards), IG3 (all 153 safeguards). Each maps to NIST CSF, ISO 27001, and PCI-DSS",
    usecases: ["SME security baseline", "Security program roadmap", "Audit readiness", "Board risk reporting"],
    related: ["nist-csf", "iso27001"],
    reference: "https://www.iso.org/home.html",
  },
  {
    id: "soc2",
    short: "SOC 2",
    name: "System and Organization Controls 2",
    org: "AICPA",
    region: " US (SaaS Global)",
    type: "Audit Report",
    mandatory: "Market-driven",
    focus: "SaaS trust & security",
    color: "#8b5cf6",
    
    category: "compliance",
    overview: "SOC 2 is an auditing standard for technology service providers. Type I reports on design of controls at a point in time. Type II reports on operating effectiveness over 6–12 months. Most B2B SaaS companies require SOC 2 Type II for enterprise sales.",
    clauses: [
      { num: "CC", title: "Common Criteria (Security)", desc: "Logical access, system operations, change management, risk management" },
      { num: "A", title: "Availability", desc: "System availability commitments and uptime SLAs" },
      { num: "PI", title: "Processing Integrity", desc: "Complete, valid, accurate, timely processing" },
      { num: "C", title: "Confidentiality", desc: "Protection of confidential information through its lifecycle" },
      { num: "P", title: "Privacy", desc: "Collection, use, retention, disclosure and disposal of personal information" },
    ],
    controls: "Trust Services Criteria mapped to COSO framework. Security (CC) criteria is mandatory; Availability, PI, Confidentiality, Privacy are add-ons based on customer commitments",
    usecases: ["Enterprise SaaS sales enablement", "Vendor security questionnaires", "Customer trust building", "US market access"],
    related: ["iso27001", "nist-csf"],
    reference: "https://www.aicpa-cima.com/resources/download/soc-2-system-and-organization-controls-for-service-organizations",
  },
  {
    id: "cobit",
    short: "COBIT 2019",
    name: "Control Objectives for IT",
    org: "ISACA",
    region: " Global",
    type: "IT Governance Framework",
    mandatory: "Voluntary",
    focus: "IT governance & risk",
    color: "#a78bfa",
    
    category: "practical",
    overview: "COBIT 2019 is ISACA's framework for IT governance and management. It bridges the gap between technical security controls and business governance objectives, making it essential for CISOs and IT directors communicating with boards.",
    clauses: [
      { num: "EDM", title: "Evaluate, Direct and Monitor", desc: "Governance objectives: benefits realization, risk optimization, resource optimization" },
      { num: "APO", title: "Align, Plan and Organize", desc: "Strategy, architecture, innovation, portfolio, budget, HR, relationships" },
      { num: "BAI", title: "Build, Acquire and Implement", desc: "Programs, change, solutions, knowledge, assets" },
      { num: "DSS", title: "Deliver, Service and Support", desc: "Operations, service requests, problems, continuity, security" },
      { num: "MEA", title: "Monitor, Evaluate and Assess", desc: "Performance, system of controls, compliance" },
    ],
    controls: "40 governance and management objectives. Includes Design Factors for tailoring to organizational context. Maps to ISO 27001, NIST, ITIL, and TOGAF",
    usecases: ["Board-level IT governance", "ISACA CISA/CISM exam", "IT audit frameworks", "Enterprise risk management"],
    related: ["nist-csf", "iso27001"],
    reference: "https://www.isaca.org/resources/cobit",
  },
];

const categoryGroups = [
  { id: "iso", label: "ISO Standards", color: "#3b82f6",  },
  { id: "owasp", label: "OWASP", color: "#f97316",  },
  { id: "nist", label: "NIST", color: "#22c55e",  },
  { id: "compliance", label: "Compliance", color: "#eab308",  },
  { id: "india", label: "India", color: "#f43f5e",  },
  { id: "practical", label: "Practical", color: "#14b8a6",  },
];

const roadmap = [
  { step: 1, title: "Foundation", items: ["OWASP Top 10", "OWASP Mobile Top 10", "Secure Coding Basics", "ASVS L1"], color: "#f97316" },
  { step: 2, title: "Governance", items: ["ISO 27001 ISMS", "Risk Assessment", "Security Policies", "ISO 27002 Controls"], color: "#3b82f6" },
  { step: 3, title: "Operations", items: ["NIST CSF Mapping", "Incident Response (800-61)", "Logging & Monitoring", "CIS Controls IG1/IG2"], color: "#22c55e" },
  { step: 4, title: "Cloud & Privacy", items: ["ISO 27017 Cloud", "ISO 27701 Privacy", "GDPR Compliance", "CIS Benchmarks"], color: "#8b5cf6" },
  { step: 5, title: "Industry", items: ["PCI-DSS (if FinTech)", "SOC 2 Type II", "RBI Framework (BFSI)", "CERT-In Requirements"], color: "#eab308" },
];

function CybersecStandards() {
  const [activeCategory, setActiveCategory] = React.useState("all");
  const [selected, setSelected] = React.useState(null);
  const [activeTab, setActiveTab] = React.useState("overview");
  const [view, setView] = React.useState("grid"); // grid | roadmap | compare

  const filtered = activeCategory === "all" ? standards : standards.filter(s => s.category === activeCategory);
  const selectedStd = standards.find(s => s.id === selected);

  return (
    <div style={{ minHeight: "100vh", background: "#080c14", color: "#e2e8f0", fontFamily: "Georgia, 'Times New Roman', serif", display: "flex", flexDirection: "column" }}>

      {/* Header */}
      <div style={{ background: "linear-gradient(135deg, #0d1526 0%, #111827 50%, #0a0f1a 100%)", borderBottom: "1px solid rgba(255,255,255,0.06)", padding: "28px 32px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: 5, color: "#6366f1", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 6 }}>CYBERSECURITY REFERENCE</div>
              <h1 style={{ margin: 0, fontSize: 30, fontWeight: 400, letterSpacing: -0.5, color: "#f8fafc", lineHeight: 1.1 }}>
                Global Security Standards<br />
                <span style={{ fontStyle: "italic", color: "#94a3b8", fontSize: 22 }}>& Frameworks Atlas</span>
              </h1>
              <p style={{ margin: "10px 0 0", fontSize: 12, color: "#64748b", fontFamily: "monospace" }}>
                {standards.length} STANDARDS · ISO · OWASP · NIST · PCI-DSS · GDPR · CERT-In · RBI · CIS · SOC2 · COBIT
              </p>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              {[["grid","⊞ Standards"],["roadmap","⟶ Roadmap"],["compare","⊙ Compare"]].map(([v,label]) => (
                <button key={v} onClick={() => { setView(v); setSelected(null); }}
                  style={{ padding: "8px 14px", fontSize: 11, fontFamily: "monospace", letterSpacing: 1, cursor: "pointer", border: `1px solid ${view === v ? "#6366f1" : "rgba(255,255,255,0.1)"}`, background: view === v ? "rgba(99,102,241,0.15)" : "transparent", color: view === v ? "#818cf8" : "rgba(255,255,255,0.4)", borderRadius: 6, transition: "all 0.2s" }}>
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Category filter */}
          {view === "grid" && (
            <div style={{ display: "flex", gap: 8, marginTop: 20, flexWrap: "wrap" }}>
              <button onClick={() => setActiveCategory("all")}
                style={{ padding: "5px 14px", fontSize: 10, fontFamily: "monospace", letterSpacing: 1, cursor: "pointer", border: `1px solid ${activeCategory === "all" ? "#fff" : "rgba(255,255,255,0.12)"}`, background: activeCategory === "all" ? "rgba(255,255,255,0.1)" : "transparent", color: activeCategory === "all" ? "#fff" : "rgba(255,255,255,0.4)", borderRadius: 100, transition: "all 0.15s" }}>
                ALL ({standards.length})
              </button>
              {categoryGroups.map(g => (
                <button key={g.id} onClick={() => setActiveCategory(g.id)}
                  style={{ padding: "5px 14px", fontSize: 10, fontFamily: "monospace", letterSpacing: 1, cursor: "pointer", border: `1px solid ${activeCategory === g.id ? g.color : "rgba(255,255,255,0.12)"}`, background: activeCategory === g.id ? g.color + "22" : "transparent", color: activeCategory === g.id ? g.color : "rgba(255,255,255,0.4)", borderRadius: 100, transition: "all 0.15s" }}>
                  {g.icon} {g.label.toUpperCase()} ({standards.filter(s => s.category === g.id).length})
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ flex: 1, maxWidth: 1200, margin: "0 auto", width: "100%", padding: "24px 32px", boxSizing: "border-box" }}>

        {/* ROADMAP VIEW */}
        {view === "roadmap" && (
          <div>
            <div style={{ textAlign: "center", marginBottom: 32 }}>
              <h2 style={{ fontWeight: 400, fontSize: 22, color: "#94a3b8", margin: 0 }}>Security Engineer Learning Roadmap</h2>
              <p style={{ color: "#475569", fontSize: 12, fontFamily: "monospace", marginTop: 6 }}>PROGRESSIVE SKILL DEVELOPMENT PATH — STARTUP TO ENTERPRISE</p>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
              {roadmap.map((step, i) => (
                <div key={step.step} style={{ display: "flex", gap: 0 }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 48, flexShrink: 0 }}>
                    <div style={{ width: 36, height: 36, borderRadius: "50%", background: step.color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700, color: "#000", fontFamily: "monospace", flexShrink: 0 }}>{step.step}</div>
                    {i < roadmap.length - 1 && <div style={{ width: 2, flex: 1, background: `linear-gradient(${step.color}, ${roadmap[i+1].color})`, minHeight: 32 }} />}
                  </div>
                  <div style={{ flex: 1, paddingLeft: 20, paddingBottom: 28, paddingTop: 4 }}>
                    <div style={{ fontSize: 11, letterSpacing: 3, color: step.color, textTransform: "uppercase", fontFamily: "monospace", marginBottom: 8 }}>Phase {step.step} — {step.title}</div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      {step.items.map(item => {
                        const std = standards.find(s => s.short === item || s.short.includes(item.split(' ')[0]));
                        return (
                          <div key={item} onClick={() => { if (std) { setSelected(std.id); setView("grid"); setActiveCategory("all"); } }}
                            style={{ padding: "8px 16px", background: "rgba(255,255,255,0.03)", border: `1px solid ${step.color}44`, borderRadius: 8, fontSize: 12, color: "#cbd5e1", cursor: std ? "pointer" : "default", transition: "all 0.2s" }}
                            onMouseEnter={e => std && (e.target.style.background = step.color + "22")}
                            onMouseLeave={e => std && (e.target.style.background = "rgba(255,255,255,0.03)")}>
                            {item}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* COMPARE VIEW */}
        {view === "compare" && (
          <div style={{ overflowX: "auto" }}>
            <div style={{ textAlign: "center", marginBottom: 24 }}>
              <h2 style={{ fontWeight: 400, fontSize: 22, color: "#94a3b8", margin: 0 }}>Standards Comparison Matrix</h2>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, fontFamily: "monospace" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
                  {["Standard", "Organization", "Type", "Region", "Mandatory", "Focus Area"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "10px 14px", color: "#64748b", letterSpacing: 2, textTransform: "uppercase", fontSize: 9, fontWeight: 400 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {standards.map((s, i) => {
                  const cat = categoryGroups.find(c => c.id === s.category);
                  return (
                    <tr key={s.id} onClick={() => { setSelected(s.id); setView("grid"); setActiveCategory("all"); }}
                      style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer", background: i % 2 === 0 ? "rgba(255,255,255,0.01)" : "transparent", transition: "background 0.15s" }}
                      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                      onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? "rgba(255,255,255,0.01)" : "transparent"}>
                      <td style={{ padding: "10px 14px" }}>
                        <span style={{ color: s.color, fontWeight: 700 }}>{s.short}</span>
                      </td>
                      <td style={{ padding: "10px 14px", color: "#94a3b8" }}>{s.org}</td>
                      <td style={{ padding: "10px 14px" }}>
                        <span style={{ padding: "2px 8px", borderRadius: 100, background: cat?.color + "22", color: cat?.color, fontSize: 9 }}>{s.type}</span>
                      </td>
                      <td style={{ padding: "10px 14px", color: "#94a3b8" }}>{s.region}</td>
                      <td style={{ padding: "10px 14px" }}>
                        <span style={{ color: s.mandatory.startsWith("Yes") ? "#ef4444" : s.mandatory === "Voluntary" ? "#22c55e" : "#f59e0b", fontSize: 10 }}>
                          {s.mandatory.startsWith("Yes") ? " " : s.mandatory === "Voluntary" ? " " : "◎ "}{s.mandatory}
                        </span>
                      </td>
                      <td style={{ padding: "10px 14px", color: "#64748b" }}>{s.focus}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* GRID VIEW */}
        {view === "grid" && (
          <div style={{ display: "flex", gap: 24 }}>
            {/* Cards Grid */}
            <div style={{ flex: 1 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
                {filtered.map(std => {
                  const isSelected = selected === std.id;
                  return (
                    <div key={std.id} onClick={() => { setSelected(isSelected ? null : std.id); setActiveTab("overview"); }}
                      style={{ background: isSelected ? `${std.color}11` : "rgba(255,255,255,0.02)", border: `1px solid ${isSelected ? std.color : "rgba(255,255,255,0.07)"}`, borderRadius: 10, padding: "16px", cursor: "pointer", transition: "all 0.2s" }}
                      onMouseEnter={e => !isSelected && (e.currentTarget.style.borderColor = std.color + "66")}
                      onMouseLeave={e => !isSelected && (e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)")}>
                      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 10 }}>
                        <span style={{ fontSize: 22 }}>{std.icon}</span>
                        <span style={{ fontSize: 9, padding: "2px 7px", borderRadius: 100, background: std.color + "22", color: std.color, fontFamily: "monospace", letterSpacing: 0.5 }}>{std.org}</span>
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: std.color, marginBottom: 3, fontFamily: "monospace" }}>{std.short}</div>
                      <div style={{ fontSize: 11, color: "#94a3b8", lineHeight: 1.4, marginBottom: 10 }}>{std.name}</div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: 9, color: "#475569", fontFamily: "monospace" }}>{std.region}</span>
                        <span style={{ fontSize: 9, color: std.mandatory.startsWith("Yes") ? "#ef4444" : "#22c55e", fontFamily: "monospace" }}>
                          {std.mandatory.startsWith("Yes") ? " REQUIRED" : " VOLUNTARY"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Detail Panel */}
            {selectedStd && (
              <div style={{ width: 380, flexShrink: 0, background: "rgba(255,255,255,0.02)", border: `1px solid ${selectedStd.color}44`, borderRadius: 12, overflow: "hidden", alignSelf: "flex-start", position: "sticky", top: 24 }}>
                {/* Panel Header */}
                <div style={{ padding: "20px 20px 0", borderBottom: `1px solid ${selectedStd.color}33`, background: `linear-gradient(135deg, ${selectedStd.color}11, transparent)` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div>
                      <span style={{ fontSize: 28 }}>{selectedStd.icon}</span>
                      <div style={{ fontSize: 18, fontWeight: 700, color: selectedStd.color, fontFamily: "monospace", marginTop: 6 }}>{selectedStd.short}</div>
                      <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 12, maxWidth: 300, lineHeight: 1.4 }}>{selectedStd.name}</div>
                    </div>
                    <button onClick={() => setSelected(null)} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#64748b", cursor: "pointer", borderRadius: 6, width: 28, height: 28, fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center" }}></button>
                  </div>
                  <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                    <span style={{ fontSize: 9, padding: "3px 8px", borderRadius: 100, background: "rgba(255,255,255,0.07)", color: "#94a3b8", fontFamily: "monospace" }}>{selectedStd.region}</span>
                    <span style={{ fontSize: 9, padding: "3px 8px", borderRadius: 100, background: selectedStd.mandatory.startsWith("Yes") ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)", color: selectedStd.mandatory.startsWith("Yes") ? "#ef4444" : "#22c55e", fontFamily: "monospace" }}>
                      {selectedStd.mandatory.startsWith("Yes") ? " " : " "}{selectedStd.mandatory}
                    </span>
                  </div>

                  {/* Tabs */}
                  <div style={{ display: "flex", gap: 0 }}>
                    {[["overview","Overview"],["clauses", selectedStd.clauses.length > 0 ? "Structure" : "Controls"],["usecases","Use Cases"],["related","Related"]].map(([t, l]) => (
                      <button key={t} onClick={() => setActiveTab(t)}
                        style={{ flex: 1, padding: "7px 4px", border: "none", cursor: "pointer", background: "transparent", borderBottom: `2px solid ${activeTab === t ? selectedStd.color : "transparent"}`, color: activeTab === t ? selectedStd.color : "#64748b", fontSize: 10, fontFamily: "monospace", letterSpacing: 0.5, transition: "all 0.15s" }}>
                        {l}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Panel Content */}
                <div style={{ padding: "16px 20px", maxHeight: 420, overflowY: "auto" }}>
                  {activeTab === "overview" && (
                    <p style={{ margin: 0, fontSize: 12, lineHeight: 1.8, color: "#94a3b8" }}>{selectedStd.overview}</p>
                  )}

                  {activeTab === "clauses" && (
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
                      ) : (
                        <p style={{ margin: 0, fontSize: 12, lineHeight: 1.8, color: "#94a3b8" }}>{selectedStd.controls}</p>
                      )}
                      {selectedStd.clauses.length > 0 && (
                        <div style={{ marginTop: 12, padding: "10px 12px", background: "rgba(255,255,255,0.02)", borderRadius: 8, fontSize: 11, color: "#64748b", lineHeight: 1.6 }}>
                          <strong style={{ color: "#94a3b8", fontSize: 10, fontFamily: "monospace", letterSpacing: 1 }}>CONTROLS: </strong>{selectedStd.controls}
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab === "usecases" && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                      {selectedStd.usecases.map((uc, i) => (
                        <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                          <span style={{ color: selectedStd.color, fontSize: 12, marginTop: 1 }}>→</span>
                          <span style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.5 }}>{uc}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {activeTab === "related" && (
                    <div>
                      <p style={{ margin: "0 0 12px", fontSize: 11, color: "#64748b", fontFamily: "monospace" }}>RELATED STANDARDS</p>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        {selectedStd.related.map(rid => {
                          const rel = standards.find(s => s.id === rid);
                          return rel ? (
                            <div key={rid} onClick={() => { setSelected(rid); setActiveTab("overview"); }}
                              style={{ padding: "10px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 8, cursor: "pointer", border: "1px solid rgba(255,255,255,0.07)", transition: "all 0.2s" }}
                              onMouseEnter={e => e.currentTarget.style.borderColor = rel.color}
                              onMouseLeave={e => e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)"}>
                              <div style={{ fontSize: 12, color: rel.color, fontFamily: "monospace", marginBottom: 2 }}>{rel.short}</div>
                              <div style={{ fontSize: 10, color: "#64748b" }}>{rel.name}</div>
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

      {/* Footer */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", padding: "10px 32px", display: "flex", justifyContent: "space-between", fontSize: 9, color: "#334155", fontFamily: "monospace", letterSpacing: 1 }}>
        <span>CYBERSECURITY STANDARDS ATLAS — FOR REFERENCE & STUDY</span>
        <span>ISO · OWASP · NIST · PCI · GDPR · CERT-IN · RBI · CIS · SOC2 · COBIT</span>
      </div>
    </div>
  );
}
