import os
import re

files = [
    r'c:\Users\rock5\Desktop\a\repotDashbord\cybersec-planning.jsx',
    r'c:\Users\rock5\Desktop\a\repotDashbord\cybersec-standards.jsx',
    r'c:\Users\rock5\Desktop\a\repotDashbord\vapt-checklist.jsx'
]

# A regex that matches most common emojis and symbols used in the file
emoji_pattern = re.compile(
    "["
    u"\U0001f600-\U0001f64f"  # emoticons
    u"\U0001f300-\U0001f5ff"  # symbols & pictographs
    u"\U0001f680-\U0001f6ff"  # transport & map symbols
    u"\U0001f1e0-\U0001f1ff"  # flags (iOS)
    u"\U00002702-\U000027b0"
    u"\U000024C2-\U0001F251"
    u"\U0001f900-\U0001f9ff"  # supplemental symbols
    u"\u2600-\u26ff"          # misc symbols
    u"\u2700-\u27bf"          # dingbats
    u"\u2B50\u2B55\u2934\u2935"
    "]+", flags=re.UNICODE)

for filepath in files:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Remove emojis
    content = emoji_pattern.sub('', content)
    # Remove unicode variation selectors and zero width joiners if any
    content = content.replace('\ufe0f', '').replace('\u200d', '')
    
    # Clean up empty strings or double spaces caused by emoji removal
    content = content.replace('icon: " ",', 'icon: "",').replace('icon: "  ",', 'icon: "",')
    
    # 2. Add References
    if 'cybersec-standards.jsx' in filepath:
        # Add reference URL to standards array
        if 'reference: "https://www.nist.gov' not in content:
            content = re.sub(r'(related:\s*\[.*?\])', r'\1,\n    reference: "https://www.nist.gov/cyberframework"', content)
        
            # Add UI code to render reference
            overview_ui = r'(<p style={{ margin: "0 0 14px",.*?>{selectedStd\.overview}</p>)'
            replacement = r'\1\n                      {selectedStd.reference && <div style={{marginTop: 10}}><a href={selectedStd.reference} target="_blank" rel="noreferrer" style={{fontSize: 12, color: selectedStd.color, textDecoration: "underline"}}>Official Reference Documentation</a></div>}'
            content = re.sub(overview_ui, replacement, content)

    if 'vapt-checklist.jsx' in filepath:
        # Add reference URL to details
        if 'reference: "https://cve' not in content:
            content = re.sub(r'(why:\s*".*?")', r'\1,\n          reference: "https://cve.mitre.org/"', content)
        
            # Add UI code to render reference in Why tab
            why_ui = r'(<p style={{ margin: 0, fontSize: 12, lineHeight: 1\.7, color: "rgba\(255,255,255,0\.75\)", borderLeft: `3px solid #a855f7`, paddingLeft: 12 }}>{item\.details\.why}</p>)'
            replacement = r'\1\n                            {item.details.reference && <div style={{marginTop: 10, paddingLeft: 12}}><a href={item.details.reference} target="_blank" rel="noreferrer" style={{fontSize: 11, color: "#a855f7", textDecoration: "underline"}}>Vulnerability Reference (CVE/OWASP)</a></div>}'
            content = re.sub(why_ui, replacement, content)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

print("Refinement completed.")
