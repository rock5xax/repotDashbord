# VAPT Checklist (Browser JSX Demo)

This project runs a React JSX checklist directly in the browser using:
- `index.html`
- `vapt-checklist.jsx`
- `cybersec-standards01.jsx`
- React UMD + Babel standalone (CDN)

## Files

- `index.html`: Loads React, ReactDOM, Babel, and mounts the app.
- `vapt-checklist.jsx`: Contains the `VAPTChecklist` React component.
- `cybersec-standards01.jsx`: Contains the `CybersecStandards` React component (detailed version).

## Pages

- `VAPT Checklist`
- `Cybersec Standards`

Use the top toggle buttons in the app to switch between pages.

## Run Locally

1. Open terminal in this folder:
```powershell
cd c:\Users\rock5\Desktop\a\ab01
```

2. Start a local HTTP server:
```powershell
python -m http.server 8000
```

3. Open in browser:
```text
http://localhost:8000
```

## Important Notes

- Do not open `index.html` via double-click (`file://...`), use `http://localhost:8000`.
- `vapt-checklist.jsx` is written for browser Babel mode:
  - no `import` statements
  - no `export default`
  - uses `React.useState(...)`

## Troubleshooting

- If page is blank, open browser DevTools Console and check errors.
- If port `8000` is busy, run:
```powershell
python -m http.server 8080
```
Then open `http://localhost:8080`.
