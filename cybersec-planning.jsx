// 
// STRATEGIC PLANNING THEMES
// 
const planningPhases = [
    {
        id: "assess", label: "Discovery & Assess",  color: "#3b82f6",
        themes: [
            {
                title: "Asset Discovery & Classification",
                desc: "Identify all hardware, software, and data assets across the organization. Classify data based on sensitivity and business criticality.",
                tasks: ["Deploy automated discovery tools", "Create a data classification policy", "Build CMDB (Configuration Management Database)", "Assign data owners"]
            },
            {
                title: "Risk Assessment",
                desc: "Evaluate the likelihood and impact of potential threats to business operations. Translate technical risks into business impact.",
                tasks: ["Conduct Business Impact Analysis (BIA)", "Perform Threat Modeling", "Calculate Risk Scores (Likelihood x Impact)", "Establish Risk Tolerance Matrix"]
            },
            {
                title: "Current State Analysis (Maturity Assessment)",
                desc: "Assess the current cybersecurity posture against industry frameworks like NIST CSF or ISO 27001.",
                tasks: ["Perform GAP analysis against chosen framework", "Conduct internal audits", "Review existing policies and procedures", "Benchmark against industry peers"]
            }
        ]
    },
    {
        id: "strategize", label: "Strategize & Budget",  color: "#a855f7",
        themes: [
            {
                title: "Security Architecture & Roadmap",
                desc: "Design the target-state security architecture and create a multi-year roadmap aligned with business objectives.",
                tasks: ["Define Target Operating Model (TOM)", "Design Zero Trust Architecture principles", "Create phased roadmap (30-60-90 days, 1-3 years)", "Align with digital transformation goals"]
            },
            {
                title: "Budgeting & Resource Allocation",
                desc: "Secure funding for security initiatives, balancing CapEx (tools/infrastructure) and OpEx (services/personnel).",
                tasks: ["Quantify risk reduction to justify ROI", "Allocate budget across People, Process, Technology", "Plan for continuous training and certifications", "Evaluate managed services vs. in-house SOC"]
            },
            {
                title: "Policy & Governance Framework",
                desc: "Establish the rules and oversight mechanisms to ensure the security strategy is executed effectively.",
                tasks: ["Draft Information Security Policy", "Establish Security Steering Committee", "Define KPIs and KRIs for Board reporting", "Implement Third-Party Risk Management (TPRM) policy"]
            }
        ]
    },
    {
        id: "implement", label: "Implement & Operate",  color: "#10b981",
        themes: [
            {
                title: "Identity & Access Management (IAM)",
                desc: "Ensure only authorized individuals have access to the right resources at the right times for the right reasons.",
                tasks: ["Implement enforced MFA across all systems", "Deploy Single Sign-On (SSO)", "Enforce Principle of Least Privilege", "Automate Joiner/Mover/Leaver (JML) processes"]
            },
            {
                title: "Security Engineering & Operations",
                desc: "Deploy technical controls and establish continuous monitoring for threat detection.",
                tasks: ["Deploy EDR/MDR solutions", "Implement SIEM and log aggregation", "Automate vulnerability scanning and patch management", "Establish Secure SDLC (DevSecOps) pipeline"]
            },
            {
                title: "Data Protection & Privacy",
                desc: "Implement controls to protect data at rest, in transit, and in use, ensuring regulatory compliance.",
                tasks: ["Implement Data Loss Prevention (DLP)", "Enforce encryption standards (TLS 1.2+, AES-256)", "Implement data masking for non-prod environments", "Align with GDPR/CCPA privacy requirements"]
            }
        ]
    },
    {
        id: "respond", label: "Respond & Improve",  color: "#ef4444",
        themes: [
            {
                title: "Incident Response Planning",
                desc: "Prepare the organization to effectively detect, respond to, and recover from cybersecurity incidents.",
                tasks: ["Develop step-by-step IR Playbooks", "Establish communication plans (internal & legal)", "Create Cyber Crisis Management Plan", "Retain external Digital Forensics (DFIR) firm"]
            },
            {
                title: "Cyber Resilience & BCDR",
                desc: "Ensure the organization can maintain operations and recover data in the event of a catastrophic attack (e.g., Ransomware).",
                tasks: ["Implement Immutable Backups (3-2-1 rule)", "Define RTO and RPO metrics for critical services", "Draft Business Continuity Plan (BCP)", "Conduct Disaster Recovery (DR) testing"]
            },
            {
                title: "Testing & Continuous Improvement",
                desc: "Continuously validate the effectiveness of the security program and adapt to the evolving threat landscape.",
                tasks: ["Conduct annual Penetration Testing", "Run Red/Blue Team (Purple Team) exercises", "Perform Tabletop exercises with Executives", "Gather metrics and adjust strategy annually"]
            }
        ]
    }
];

function CybersecPlanning() {
    const [activePhase, setActivePhase] = React.useState("assess");

    const currentPhaseData = planningPhases.find(p => p.id === activePhase);

    return (
        <div style={{ minHeight: "100vh", background: "#05070b", color: "#e2e8f0", fontFamily: "Georgia, serif", padding: "24px 28px" }}>
            <div style={{ maxWidth: 1200, margin: "0 auto" }}>

                {/* Header Section */}
                <div style={{ marginBottom: 40 }}>
                    <div style={{ fontSize: 10, letterSpacing: 4, color: "#6366f1", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 8 }}>EXECUTIVE DASHBOARD</div>
                    <h1 style={{ margin: 0, fontSize: 32, fontWeight: 400, color: "#f8fafc", lineHeight: 1.2 }}>
                        Strategic <span style={{ fontStyle: "italic", color: "#94a3b8" }}>Cybersecurity Planning</span>
                    </h1>
                    <p style={{ margin: "12px 0 0", fontSize: 13, color: "#64748b", maxWidth: 600, lineHeight: 1.6 }}>
                        A structured framework for building a resilient, mature, and business-aligned security program from initial discovery to continuous improvement.
                    </p>
                </div>

                {/* Navigation Tabs */}
                <div style={{ display: "flex", gap: 12, marginBottom: 32, flexWrap: "wrap", borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: 16 }}>
                    {planningPhases.map((phase, idx) => {
                        const isActive = activePhase === phase.id;
                        return (
                            <button
                                key={phase.id}
                                onClick={() => setActivePhase(phase.id)}
                                style={{
                                    display: "flex", alignItems: "center", gap: 8,
                                    padding: "10px 18px",
                                    background: isActive ? `${phase.color}18` : "transparent",
                                    border: `1px solid ${isActive ? phase.color : "rgba(255,255,255,0.1)"}`,
                                    color: isActive ? phase.color : "#94a3b8",
                                    borderRadius: 8,
                                    fontSize: 12,
                                    fontFamily: "monospace",
                                    letterSpacing: 1,
                                    cursor: "pointer",
                                    transition: "all 0.2s"
                                }}
                            >
                                <div style={{
                                    width: 20, height: 20, borderRadius: "50%",
                                    background: isActive ? phase.color : "rgba(255,255,255,0.1)",
                                    color: isActive ? "#000" : "#94a3b8",
                                    display: "flex", alignItems: "center", justifyContent: "center",
                                    fontSize: 10, fontWeight: "bold"
                                }}>
                                    {idx + 1}
                                </div>
                                <span>{phase.icon} {phase.label.toUpperCase()}</span>
                            </button>
                        )
                    })}
                </div>

                {/* Content Area */}
                <div style={{
                    background: "linear-gradient(145deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01))",
                    border: `1px solid ${currentPhaseData.color}44`,
                    borderRadius: 16,
                    padding: 32,
                    position: "relative",
                    overflow: "hidden"
                }}>
                    {/* Subtle background glow */}
                    <div style={{
                        position: "absolute", top: -100, right: -100, width: 300, height: 300,
                        background: `radial-gradient(circle, ${currentPhaseData.color}15 0%, transparent 70%)`,
                        pointerEvents: "none"
                    }} />

                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
                        <span style={{ fontSize: 32 }}>{currentPhaseData.icon}</span>
                        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 400, color: currentPhaseData.color }}>
                            Phase {planningPhases.findIndex(p => p.id === activePhase) + 1}: {currentPhaseData.label}
                        </h2>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 24 }}>
                        {currentPhaseData.themes.map((theme, i) => (
                            <div key={i} style={{
                                background: "rgba(0,0,0,0.3)",
                                border: "1px solid rgba(255,255,255,0.06)",
                                borderRadius: 12,
                                padding: 20,
                                display: "flex", flexDirection: "column"
                            }}>
                                <h3 style={{ margin: "0 0 10px", fontSize: 16, color: "#f8fafc", fontWeight: 600 }}>{theme.title}</h3>
                                <p style={{ margin: "0 0 16px", fontSize: 12, lineHeight: 1.6, color: "#94a3b8", flex: 1 }}>
                                    {theme.desc}
                                </p>
                                <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: 12 }}>
                                    <div style={{ fontSize: 9, fontFamily: "monospace", color: currentPhaseData.color, marginBottom: 8, letterSpacing: 1 }}>KEY INITIATIVES</div>
                                    <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                                        {theme.tasks.map((task, ti) => (
                                            <li key={ti} style={{ fontSize: 11, color: "#cbd5e1", marginBottom: 6, display: "flex", gap: 8, alignItems: "flex-start" }}>
                                                <span style={{ color: currentPhaseData.color, marginTop: 2 }}></span>
                                                <span style={{ lineHeight: 1.4 }}>{task}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

            </div>
        </div>
    );
}
