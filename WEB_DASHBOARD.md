# Web Vulnerability Dashboard

A modern, responsive web application for viewing and analyzing security vulnerabilities in a GitLab Pages-compatible static site.

## 🎯 Overview

The web dashboard provides a user-friendly interface to view, filter, and sort security vulnerabilities from ez-appsec scans. It's completely static (HTML/CSS/JavaScript), requires no backend server, and deploys directly to GitLab Pages.

### Key Features

✅ **Static Site** - Pure HTML, CSS, JS (no Node.js, no Python server required)  
✅ **GitLab Pages Ready** - Automatic deployment via CI/CD  
✅ **Vulnerability Filtering** - By severity, scanner, and full-text search  
✅ **Responsive Design** - Works on desktop, tablet, and mobile  
✅ **Severity Metrics** - Quick overview of issue counts  
✅ **Remediation Guidance** - Solutions for each vulnerability  
✅ **Multi-Scanner Support** - Gitleaks, Semgrep, KICS, Grype  
✅ **GitLab Format Compatible** - Uses standard vulnerability schema  

## 📁 Files & Structure

```
web/
├── index.html                     # Main dashboard page
├── style.css                      # Responsive styling (50KB)
├── app.js                         # Vanilla JavaScript app (20KB)
├── data/
│   └── vulnerabilities.json       # Vulnerability data (generated)
├── README.md                      # Web dashboard documentation
└── .gitignore                     # Exclude generated files
```

## 🚀 Quick Start

### Local Development

1. **Generate vulnerability data:**
```bash
cd /path/to/ez-appsec
ez-appsec web-report . --output web/data
```

2. **Start local server:**
```bash
cd web
python3 -m http.server 8000
```

3. **Open browser:**
```
http://localhost:8000
```

### GitLab Pages Deployment

The `.gitlab-ci.yml` is pre-configured. Just push your changes:

```bash
git add .
git commit -m "Update vulnerability dashboard"
git push origin main
```

Your dashboard will be live at:
```
https://<username>.gitlab.io/<project>/
```

## 🔌 API Usage

The dashboard project's CI/CD pipeline provides API-triggerable jobs for managing scans and updates.

### Rescan a Single Project

Trigger `rescan:project` to clone and scan a specific project:

```bash
curl --request POST \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects/<dashboard-project-id>/pipeline" \
  --form "ref=main" \
  --form "variables[RESCAN_PROJECT_PATH]=<namespace/project>"
```

**Example:** Scan `myorg/frontend-app`
```bash
curl --request POST \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects/12345/pipeline" \
  --form "ref=main" \
  --form "variables[RESCAN_PROJECT_PATH]=myorg/frontend-app"
```

### Rescan All Projects

Trigger `rescan:all` to scan every registered project:

```bash
curl --request POST \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects/<dashboard-project-id>/pipeline" \
  --form "ref=main"
```

The job iterates through `public/data/projects/*/meta.json` and scans each.

### Update Web Assets

Trigger `update:web` to pull latest dashboard assets from ez-appsec:

```bash
curl --request POST \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.com/api/v4/projects/<dashboard-project-id>/pipeline" \
  --form "ref=main"
```

Downloads `index.html`, `style.css`, `app.js`, and `.gitlab-ci.yml` from the ez-appsec source repo.

### Finding the Dashboard Project ID

```bash
# Find by path (replace with your group path)
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('your-group/ez_appsec/ez-appsec-dashboard', safe=''))")
glab api "projects/${ENCODED}" --field id

# Or search
glab api search --scope projects --search ez-appsec-dashboard
```

### Using glab CLI

```bash
# Trigger with glab (requires authenticated glab)
glab api --method POST "projects/<dashboard-id>/pipeline" \
  --field ref=main \
  --field "variables[RESCAN_PROJECT_PATH]=myorg/myapp"
```

### Web UI Trigger

You can also trigger jobs from the GitLab web UI:
1. Go to CI/CD → Pipelines
2. Click "New pipeline" → "Run pipeline"
3. Add variables as needed (e.g., `RESCAN_PROJECT_PATH`)
4. Click "Run pipeline"

## 📊 Dashboard Features

### Filtering & Sorting

**Severity Filter:**
- 🔴 Critical - Requires immediate action
- 🟠 High - Fix ASAP
- 🟡 Medium - Plan remediation
- 🟢 Low - Consider addressing
- 🔵 Info - Informational only

**Scanner Filter:**
- Gitleaks - Secrets detection
- Semgrep - SAST analysis
- KICS - Infrastructure as Code
- Grype - Dependency vulnerabilities

**Text Search:**
- Search across names, descriptions, files
- Case-insensitive
- Real-time filtering

**Statistics Dashboard:**
- Total vulnerability count
- Breakdown by severity
- Visual indicators

### Vulnerability Card Details

Each vulnerability displays:
- **Title** - Clear vulnerability name
- **Severity Badge** - Color-coded priority
- **Scanner** - Which tool found it
- **Location** - File path and line number
- **Description** - What the issue is
- **Category** - Type of vulnerability
- **CVE ID** - Known CVE reference (if applicable)
- **Remediation** - How to fix it

## 💾 Data Format

Vulnerabilities are stored as JSON in `data/vulnerabilities.json`:

```json
{
  "version": "15.0.0",
  "vulnerabilities": [
    {
      "id": "unique-identifier",
      "category": "sast|secret_detection|dependency_scanning|...",
      "name": "Vulnerability Title",
      "message": "Short description for display",
      "description": "Detailed explanation of the issue",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "solution": "Step-by-step remediation guidance",
      "scanner": {
        "id": "gitleaks|semgrep|kics|grype",
        "name": "Human-readable scanner name"
      },
      "location": {
        "file": "path/to/vulnerable/file",
        "start_line": 42,
        "end_line": 42
      },
      "cve": "CVE-YYYY-XXXXX",
      "identifiers": [
        {
          "type": "cve",
          "name": "CVE-YYYY-XXXXX",
          "value": "CVE-YYYY-XXXXX"
        }
      ],
      "links": [
        {
          "url": "https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX"
        }
      ]
    }
  ],
  "remediations": []
}
```

## 🔧 Generating Reports

### From Command Line

Generate a web report from scan results:

```bash
# Scan and generate web report
ez-appsec web-report /path/to/project --output web/data

# Merge multiple reports
ez-appsec gitlab-scan . --output web/data/vulnerabilities.json
```

### CI/CD Integration

Add to your GitLab CI pipeline:

```yaml
security_scan:
  stage: test
  script:
    - ez-appsec web-report . --output web/data
  artifacts:
    paths:
      - web/data/

pages:
  stage: deploy
  dependencies:
    - security_scan
  script:
    - mkdir -p public
    - cp -r web/* public/
  artifacts:
    paths:
      - public
  only:
    - main
```

## 🎨 Customization

### Styling

Colors are defined as CSS variables in `style.css`:

```css
:root {
    --primary-color: #0066cc;
    --danger-color: #d32f2f;     /* Critical */
    --warning-color: #f57c00;    /* High */
    --info-color: #1976d2;       /* Low/Info */
    --success-color: #388e3c;    /* Medium-Low */
    --text-color: #333;
    --border-color: #ddd;
    --shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}
```

Change any color to customize the dashboard appearance.

### Adding New Scanners

Update the scanner filter dropdown in `index.html`:

```html
<select id="scanner-filter">
    <option value="">All Scanners</option>
    <option value="gitleaks">Gitleaks</option>
    <option value="semgrep">Semgrep</option>
    <option value="kics">KICS</option>
    <option value="grype">Grype</option>
    <option value="custom-tool">Your Tool</option>  <!-- Add here -->
</select>
```

The JavaScript will auto-detect scanners from the JSON data.

### Branding

Edit the header in `index.html`:

```html
<header class="header">
    <div class="container">
        <h1>Your Organization - Security Dashboard</h1>
        <p class="subtitle">Vulnerability assessment and tracking</p>
    </div>
</header>
```

## 📈 Performance

- **Size**: ~70KB total (HTML + CSS + JS)
- **Load Time**: <100ms on modern browsers
- **Data Size**: Scales well up to 10,000 vulnerabilities
- **Browser Support**: All modern browsers (2020+)

For larger datasets (>10,000 issues), consider:
1. Splitting into multiple JSON files
2. Implementing pagination
3. Using virtual scrolling (lazy load)

## 🔒 Security Considerations

- **No sensitive data in JSON** - Never store actual secrets in reports
- **Static hosting only** - No backend to secure
- **Public by default** - GitLab Pages are public (authenticate via GitLab if needed)
- **Local ONLY** - Running `python3 -m http.server` is for development only

For private dashboards, use:
- GitLab Pages with authentication
- AWS S3 + CloudFront with IAM
- Nginx with basic auth
- Netlify with site protection

## 🌍 Deployment

### GitLab Pages (Recommended)

Push to main branch - CI/CD handles the rest!

```bash
git push origin main
# Dashboard live at: https://<username>.gitlab.io/<project>/
```

### GitHub Pages

Configure in repository settings:
- Source: `/ (root)`
- Branch: `main`

Or add GitHub Actions:

```yaml
- uses: actions/upload-pages-artifact@v2
  with:
    path: 'web/'
```

### Self-Hosted (Nginx)

```nginx
server {
    listen 80;
    server_name security.example.com;
    
    root /var/www/ez-appsec/web;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### Docker

```bash
# Build container with web dashboard
docker build -t ez-appsec-web .

# Serve on port 8080
docker run -p 8080:80 -v $(pwd)/web:/usr/share/nginx/html:ro nginx:alpine
```

## 🐛 Troubleshooting

### "No vulnerabilities found" when there should be data

1. Check if `web/data/vulnerabilities.json` exists
2. Validate JSON format:
   ```bash
   python3 -m json.tool web/data/vulnerabilities.json
   ```
3. Ensure file path is correct in `app.js`

### Blank page in browser

1. Open browser console (F12)
2. Check for error messages
3. Ensure JSON file is accessible
4. Check CORS if loading from different domain

### Slow loading with many vulnerabilities

1. Split large reports into multiple files
2. Implement pagination in `app.js`
3. Use virtual scrolling for large lists
4. Compress JSON with gzip

### Doesn't work on GitHub Pages

Ensure:
1. Repository is public (or use private Pages)
2. `web/index.html` is in root or `docs/` folder
3. No `./` relative paths in links
4. Server has MIME type for `.js` files

## 📚 Examples

### Example: Filter Critical Issues

```javascript
// In app.js, modify applyFilters():
const criticalOnly = this.vulnerabilities.filter(v => v.severity === 'critical');
```

### Example: Export to CSV

```javascript
// Add to app.js
exportToCSV() {
    let csv = 'Name,Severity,File,Scanner\n';
    this.vulnerabilities.forEach(v => {
        csv += `"${v.name}","${v.severity}","${v.file}","${v.scanner}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    // Download...
}
```

### Example: Add Statistics

```javascript
// In app.js
getStats() {
    return {
        byScanner: this.groupBy(this.vulnerabilities, 'scanner'),
        bySeverity: this.groupBy(this.vulnerabilities, 'severity'),
        byCategory: this.groupBy(this.vulnerabilities, 'category')
    };
}
```

## 🚀 Future Enhancements

- [ ] Multiple data source files (merge multiple scans)
- [ ] Export functionality (CSV, PDF, SARIF)
- [ ] Trend visualization (vulnerabilities over time)
- [ ] Team collaboration (comments, status tracking)
- [ ] Integration with issue trackers (auto-create GitHub issues)
- [ ] Real-time updates via WebSocket
- [ ] Mobile-optimized vulnerability list
- [ ] Dark mode toggle
- [ ] Keyboard shortcuts for navigation
- [ ] Accessibility improvements (WCAG 2.1 AA)

## 📝 License

Same as ez-appsec (see main LICENSE file)

## 🤝 Contributing

Improvements welcome! Common areas:
- UI/UX enhancements
- Performance optimizations
- Additional filter options
- Export formats
- Documentation

See main repository CONTRIBUTING guide.