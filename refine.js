const fs = require('fs');
const path = require('path');

const files = [
    'c:\\Users\\rock5\\Desktop\\a\\repotDashbord\\cybersec-planning.jsx',
    'c:\\Users\\rock5\\Desktop\\a\\repotDashbord\\cybersec-standards.jsx',
    'c:\\Users\\rock5\\Desktop\\a\\repotDashbord\\vapt-checklist.jsx'
];

// Regex to match emojis
const emojiRegex = /[\u{1F300}-\u{1F64F}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F900}-\u{1F9FF}\u{1FA70}-\u{1FAFF}\u{1F1E6}-\u{1F1FF}]/gu;

const referencesMap = {
    // Standards
    "iso27001": "https://www.iso.org/isoiec-27001-information-security.html",
    "gdpr": "https://gdpr.eu/",
    "certin": "https://www.cert-in.org.in/",
    "rbi-csf": "https://rbi.org.in/Scripts/NotificationUser.aspx?Id=10435&Mode=0",
    "cis-v8": "https://www.cisecurity.org/controls/v8",
    "pci-dss": "https://www.pcisecuritystandards.org/document_library",
    "soc2": "https://www.aicpa-cima.com/resources/download/soc-2-system-and-organization-controls-for-service-organizations",
    "cobit": "https://www.isaca.org/resources/cobit",
    "iso27701": "https://www.iso.org/standard/71670.html",
    "nist-800-53": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",

    // VAPT recon
    "recon1": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    "recon2": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
    "recon3": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
    "recon4": "https://cwe.mitre.org/data/definitions/200.html",
    "recon5": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",

    // Network
    "net1": "https://cwe.mitre.org/data/definitions/276.html",
    "net2": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160", // Heartbleed example
    "net3": "https://cwe.mitre.org/data/definitions/287.html",
    "net4": "https://cwe.mitre.org/data/definitions/295.html",
    "net5": "https://cwe.mitre.org/data/definitions/319.html",

    // App
    "app1": "https://owasp.org/Top10/A03_2021-Injection/",
    "app2": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "app3": "https://hwaci.com/sw/sqlite/cve.html",
    "app4": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "app5": "https://owasp.org/Top10/A04_2021-Insecure_Design/",

    // Android
    "and1": "https://owasp.org/www-project-mobile-top-10/2016-M1-Improper_Platform_Usage",
    "and2": "https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage",
    "and3": "https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication",
    "and4": "https://www.owasp.org/index.php/Mobile_Top_10_2016-M8-Code_Tampering",
    "and5": "https://www.owasp.org/index.php/Mobile_Top_10_2016-M9-Reverse_Engineering",

    // API
    "api1": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    "api2": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    "api3": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    "api4": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    "api5": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",

    // PT/Report
    "post1": "https://attack.mitre.org/tactics/TA0008/", // Lateral Movement
    "post2": "https://attack.mitre.org/tactics/TA0004/", // Privilege Escalation
    "rep1": "https://www.first.org/cvss/v3.1/specification-document",
    "rep2": "https://owasp.org/www-project-risk-assessment-framework/",
    "rep3": "https://csrc.nist.gov/publications/detail/sp/800-115/final",
    "rep7": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation",

    // Cloud
    "cl1": "https://cwe.mitre.org/data/definitions/284.html",
    "cl2": "https://cwe.mitre.org/data/definitions/16.html",
    "cl3": "https://cwe.mitre.org/data/definitions/276.html",
    "cl4": "https://cwe.mitre.org/data/definitions/918.html",
    "cl5": "https://cwe.mitre.org/data/definitions/778.html"
};

function processFile(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');

    // Remove Emojis
    content = content.replace(emojiRegex, '');

    content = content.replace(/icon:\s*"[^"]*",?/g, ''); // cleanly strip icon properties completely to avoid empty shapes

    // Add references to standards
    if (filePath.includes('cybersec-standards.jsx')) {
        // Add reference string to the objects based on their id
        content = content.replace(/(id:\s*"([^"]+)"[\s\S]*?)(related:\s*\[[^\]]*\])/g, (match, p1, p2, p3) => {
            const ref = referencesMap[p2] || "https://www.iso.org/home.html";
            if (!match.includes('reference:')) {
                return `${p1}${p3},\n    reference: "${ref}"`;
            }
            return match;
        });

        // Add UI code to render the reference
        if (!content.includes('Official Reference Documentation')) {
            content = content.replace(
                /(<p style={{ margin: "0 0 14px"[^>]*>{selectedStd\.overview}<\/p>)/g,
                `$1\n                      {selectedStd.reference && <div style={{marginTop: 10}}><a href={selectedStd.reference} target="_blank" rel="noreferrer" style={{fontSize: 12, color: selectedStd.color, textDecoration: "underline"}}>View Official Reference Documentation</a></div>}`
            );
        }
    }

    // Add references to VAPT checklist
    if (filePath.includes('vapt-checklist.jsx')) {
        // Add reference string to the objects based on their item id
        content = content.replace(/(id:\s*"([^"]+)"[\s\S]*?why:\s*"[^"]*")/g, (match, p1, p2) => {
            const ref = referencesMap[p2] || "https://cve.mitre.org/";
            if (!match.includes('reference:')) {
                return `${p1},\n          reference: "${ref}"`;
            }
            return match;
        });

        // Add UI code to render the reference
        if (!content.includes('Vulnerability Reference')) {
            content = content.replace(
                /(<p style={{ margin: 0, fontSize: 12, lineHeight: 1\.7, color: "rgba\(255,255,255,0\.75\)", borderLeft: `3px solid #a855f7`, paddingLeft: 12 }}>{item\.details\.why}<\/p>)/g,
                `$1\n                            {item.details.reference && <div style={{marginTop: 10, paddingLeft: 12}}><a href={item.details.reference} target="_blank" rel="noreferrer" style={{fontSize: 11, color: "#a855f7", textDecoration: "underline"}}>View Vulnerability Reference (CVE/OWASP/MITRE)</a></div>}`
            );
        }
    }

    fs.writeFileSync(filePath, content, 'utf8');
}

files.forEach(f => {
    if (fs.existsSync(f)) {
        console.log("Processing", f);
        processFile(f);
    }
});
