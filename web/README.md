# Web Vulnerability Dashboard

The `web/` directory contains a static vulnerability dashboard that can be deployed to GitLab Pages or any static hosting.

## Features

- **Static Site**: Pure HTML, CSS, and JavaScript - no backend required
- **GitLab Pages Compatible**: Deploy directly from repository
- **Vulnerability Sorting**: Sort by severity, scanner, file, or search
- **Filter & Search**: Multiple filtering options
- **Statistics Dashboard**: Overview of vulnerability counts by severity
- **Responsive Design**: Works on desktop and mobile
- **No Dependencies**: Vanilla JavaScript, no frameworks needed

## Directory Structure

```
web/
├── index.html              # Main dashboard page
├── style.css               # Styling
├── app.js                  # JavaScript application logic
├── data/                   # JSON vulnerability data
│   └── vulnerabilities.json # Merged vulnerability report
└── README.md               # This file
```

## Usage

### Local Development

Simply open `index.html` in a web browser or use a local HTTP server:

```bash
# Python 3
cd web
python -m http.server 8000

# Node.js http-server
npx http-server web -p 8000
```

Visit `http://localhost:8000` to see the dashboard.

### GitLab Pages Deployment

The `.gitlab-ci.yml` file is configured to automatically deploy the web directory to GitLab Pages.

**Prerequisites:**
1. Your project is on GitLab.com or self-hosted GitLab
2. You have enabled GitLab Pages in project settings

**Deployment:**

The pipeline will automatically deploy on push to main branch:

```bash
git add .
git commit -m "Update vulnerability dashboard"
git push origin main
```

Your dashboard will be available at: `https://<username>.gitlab.io/<project>/`

### Generating Vulnerability Reports

To generate a merged vulnerability report:

```bash
# Scan and save results in web format
ez-appsec gitlab-scan /path/to/project --output web/data/vulnerabilities.json

# Or merge multiple scan results
python scripts/merge_reports.py scan1.json scan2.json > web/data/vulnerabilities.json
```

## Vulnerability Data Format

The dashboard expects vulnerabilities in GitLab Vulnerability Format or similar JSON structure:

```json
{
  "version": "15.0.0",
  "vulnerabilities": [
    {
      "id": "unique-id",
      "category": "sast|secret_detection|dependency_scanning|...",
      "name": "Vulnerability Title",
      "message": "Short description",
      "description": "Detailed description",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "solution": "How to fix this vulnerability",
      "scanner": {
        "id": "gitleaks|semgrep|kics|grype",
        "name": "Scanner Name"
      },
      "location": {
        "file": "path/to/file",
        "start_line": 25,
        "end_line": 25
      },
      "cve": "CVE-2021-44228",
      "identifiers": [...],
      "links": [...]
    }
  ]
}
```

## Features Explained

### Sorting & Filtering

- **Severity Filter**: Show only critical, high, medium, low, or all issues
- **Scanner Filter**: Filter by specific scanner (gitleaks, semgrep, kics, grype)
- **Text Search**: Search across vulnerability names, descriptions, files
- **Reset Filters**: Clear all filters to view all vulnerabilities

### Statistics Dashboard

Shows counts by severity level:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🟢 Low
- 🔵 Info

### Vulnerability Cards

Each vulnerability shows:
- Title and severity badge
- Scanner identification
- File location and line number
- Description and details
- Remediation guidance
- Links to CVE details (if applicable)

## Customization

### Styling

Edit `style.css` to customize colors and layout:

```css
:root {
    --primary-color: #0066cc;
    --danger-color: #d32f2f;
    /* ... other colors ... */
}
```

### Adding Custom Scanners

The dashboard auto-detects scanners from the `scanner.id` field in vulnerability JSON. Update the scanner filter dropdown in `index.html` to add new options:

```html
<option value="custom-scanner">Custom Scanner</option>
```

### Merging Multiple Reports

To combine reports from different scans:

```javascript
// In app.js, modify the loadVulnerabilities function
const response = await fetch('data/all-vulns.json');
const data = await response.json();

// Merge multiple vulnerability sources
const all = [
  ...data.vulnerabilities,
  ...otherData.vulnerabilities
];
```

## Deployment Examples

### GitLab Pages

Already configured in `.gitlab-ci.yml` - just push!

### GitHub Pages

Use GitHub Actions to deploy:

```yaml
- name: Deploy to Pages
  uses: actions/upload-pages-artifact@v2
  with:
    path: 'web/'
```

### Netlify

Connect repository and point to `web/` as build output directory.

### AWS S3 + CloudFront

```bash
aws s3 sync web/ s3://my-bucket/
aws cloudfront create-invalidation --distribution-id <ID> --paths "/*"
```

## Performance

- **File Size**: ~50KB (HTML + CSS + JS)
- **Load Time**: Sub-second (JSON file dependent)
- **Browser Compatibility**: All modern browsers (Chrome, Firefox, Safari, Edge)

## Troubleshooting

### "Could not load vulnerabilities"

Ensure `web/data/vulnerabilities.json` exists and contains valid JSON:

```bash
# Validate JSON
python -m json.tool web/data/vulnerabilities.json > /dev/null && echo "Valid JSON"
```

### Blank vulnerability list

Check browser console (F12) for errors. Ensure JSON format matches expected schema.

### Slow loading

If you have many vulnerabilities (>1000), consider:
1. Splitting into multiple smaller JSON files
2. Adding pagination to the dashboard
3. Using virtual scrolling for large lists

## Future Enhancements

- [ ] Multiple vulnerability source files
- [ ] Export to CSV/PDF
- [ ] Trend analysis over time
- [ ] Team collaboration notes
- [ ] Integration with issue trackers
- [ ] Real-time updates via WebSocket