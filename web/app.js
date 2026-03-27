/**
 * Vulnerability Dashboard Application
 * Loads and displays security vulnerabilities from JSON files
 */

class VulnerabilityDashboard {
    constructor() {
        this.vulnerabilities = [];
        this.filteredVulnerabilities = [];
        this.config = null;
        
        // DOM elements
        this.severityFilter = document.getElementById('severity-filter');
        this.scannerFilter = document.getElementById('scanner-filter');
        this.searchFilter = document.getElementById('search-filter');
        this.resetButton = document.getElementById('reset-filters');
        this.container = document.getElementById('vulnerabilities-container');
        
        // Stats elements
        this.totalCount = document.getElementById('total-count');
        this.criticalCount = document.getElementById('critical-count');
        this.highCount = document.getElementById('high-count');
        this.mediumCount = document.getElementById('medium-count');
        this.lowCount = document.getElementById('low-count');
        
        this.init();
    }

    async init() {
        this.attachEventListeners();
        this.initModal();
        this.initConfigModal();
        await this.loadConfig();
        await this.loadVulnerabilities();
    }

    initModal() {
        const modal = document.getElementById('vuln-modal');
        const closeBtn = document.getElementById('modal-close');
        closeBtn.addEventListener('click', () => this.closeModal());
        modal.addEventListener('click', (e) => { if (e.target === modal) this.closeModal(); });
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') this.closeModal(); });
    }

    showDetail(vuln) {
        const modal = document.getElementById('vuln-modal');
        document.getElementById('modal-content').innerHTML = this.createVulnerabilityCard(vuln);
        modal.setAttribute('aria-hidden', 'false');
        modal.classList.add('modal-overlay--open');
        document.body.style.overflow = 'hidden';
    }

    closeModal() {
        const modal = document.getElementById('vuln-modal');
        modal.setAttribute('aria-hidden', 'true');
        modal.classList.remove('modal-overlay--open');
        document.body.style.overflow = '';
    }

    attachEventListeners() {
        this.severityFilter.addEventListener('change', () => this.applyFilters());
        this.scannerFilter.addEventListener('change', () => this.applyFilters());
        this.searchFilter.addEventListener('input', () => this.applyFilters());
        this.resetButton.addEventListener('click', () => this.resetFilters());
        document.getElementById('rescan-btn').addEventListener('click', () => this.triggerRescan());
        document.getElementById('config-btn').addEventListener('click', () => this.openConfigModal());
    }

    async loadConfig() {
        try {
            const r = await fetch('data/config.json');
            if (r.ok) this.config = await r.json();
        } catch (e) { /* config is optional */ }
    }

    initConfigModal() {
        const modal = document.getElementById('config-modal');
        document.getElementById('config-modal-close').addEventListener('click', () => this.closeConfigModal());
        modal.addEventListener('click', (e) => { if (e.target === modal) this.closeConfigModal(); });
        document.getElementById('save-token-btn').addEventListener('click', () => {
            const val = document.getElementById('trigger-token-input').value.trim();
            if (val) localStorage.setItem('ez_appsec_trigger_token', val);
            this.closeConfigModal();
        });
        document.getElementById('clear-token-btn').addEventListener('click', () => {
            localStorage.removeItem('ez_appsec_trigger_token');
            document.getElementById('trigger-token-input').value = '';
        });
    }

    openConfigModal() {
        const saved = localStorage.getItem('ez_appsec_trigger_token') || this.config?.trigger_token || '';
        document.getElementById('trigger-token-input').value = saved;
        const modal = document.getElementById('config-modal');
        modal.setAttribute('aria-hidden', 'false');
        modal.classList.add('modal-overlay--open');
        document.body.style.overflow = 'hidden';
        document.getElementById('trigger-token-input').focus();
    }

    closeConfigModal() {
        const modal = document.getElementById('config-modal');
        modal.setAttribute('aria-hidden', 'true');
        modal.classList.remove('modal-overlay--open');
        document.body.style.overflow = '';
    }

    async triggerRescan() {
        const token = localStorage.getItem('ez_appsec_trigger_token') || this.config?.trigger_token;
        if (!token) { this.openConfigModal(); return; }

        if (!this.config?.project_id) {
            alert('No project config found. Run a CI scan first to generate config.json.');
            return;
        }

        const btn = document.getElementById('rescan-btn');
        btn.disabled = true;
        btn.textContent = 'Scanning\u2026';
        btn.classList.add('btn--scanning');

        try {
            const url = `${this.config.gitlab_url}/api/v4/projects/${encodeURIComponent(this.config.project_id)}/trigger/pipeline`;
            const body = new FormData();
            body.append('token', token);
            body.append('ref', this.config.default_branch || 'main');

            const r = await fetch(url, { method: 'POST', body });
            if (!r.ok) throw new Error(`GitLab returned ${r.status}`);

            btn.classList.replace('btn--scanning', 'btn--success');
            btn.textContent = 'Triggered \u2713';
            setTimeout(() => {
                btn.disabled = false;
                btn.classList.remove('btn--success');
                btn.textContent = 'Rescan';
            }, 4000);
        } catch (e) {
            console.error('Rescan trigger failed:', e);
            btn.classList.replace('btn--scanning', 'btn--error');
            btn.textContent = 'Failed \u2717';
            setTimeout(() => {
                btn.disabled = false;
                btn.classList.remove('btn--error');
                btn.textContent = 'Rescan';
            }, 4000);
        }
    }

    async loadVulnerabilities() {
        try {
            const response = await fetch('data/vulnerabilities.json');

            if (!response.ok) {
                throw new Error('Could not load vulnerabilities');
            }

            const data = await response.json();

            // Handle both direct vulnerability array and GitLab report format
            if (Array.isArray(data)) {
                this.vulnerabilities = data;
            } else if (data.vulnerabilities) {
                this.vulnerabilities = data.vulnerabilities;
            } else if (data.issues) {
                this.vulnerabilities = data.issues;
            } else {
                throw new Error('Invalid vulnerability data format');
            }

            // Normalize vulnerability data
            this.vulnerabilities = this.vulnerabilities.map(v => this.normalizeVulnerability(v));

            // Sort by severity by default
            this.vulnerabilities.sort((a, b) => this.severityValue(b.severity) - this.severityValue(a.severity));

            this.updateScanMeta(data);
            this.populateScannerFilter();
            this.applyFilters();
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
            this.showError(`Failed to load vulnerabilities: ${error.message}`);
        }
    }

    updateScanMeta(data) {
        const meta = document.getElementById('scan-meta');
        if (!meta) return;
        const scanDate = data.scan_date || data.generated_at || null;
        const project  = data.project || data.project_name || null;
        const parts = [];
        if (project) parts.push(`Project: ${project}`);
        if (scanDate) parts.push(`Scanned: ${new Date(scanDate).toLocaleString()}`);
        parts.push(`${this.vulnerabilities.length} findings`);
        meta.textContent = parts.join('  ·  ');
    }

    populateScannerFilter() {
        const select = this.scannerFilter;
        if (!select || select.tagName !== 'SELECT') return;
        const scanners = [...new Set(this.vulnerabilities.map(v => v.scanner).filter(Boolean))].sort();
        // Remove existing dynamic options (keep the first "All scanners" option)
        while (select.options.length > 1) select.remove(1);
        scanners.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.toLowerCase();
            opt.textContent = s;
            select.appendChild(opt);
        });
    }

    normalizeVulnerability(vuln) {
        // Normalize different vulnerability formats
        const normalized = {
            // Core fields (GitLab format)
            id: vuln.id || vuln.cve || '',
            name: vuln.name || vuln.title || '',
            message: vuln.message || vuln.description || '',
            description: vuln.description || vuln.message || '',
            severity: (vuln.severity || 'medium').toLowerCase(),
            confidence: vuln.confidence || 'medium',
            category: vuln.category || vuln.type || 'unknown',
            
            // Location
            file: this.getFilePath(vuln),
            line: this.getLineNumber(vuln),
            
            // Scanner info
            scanner: this.getScannerName(vuln),
            
            // Solutions
            solution: vuln.solution || '',
            
            // Additional details
            cve: vuln.cve || '',
            identifiers: vuln.identifiers || [],
            links: vuln.links || [],
            external_id: vuln.cve || (vuln.identifiers?.[0]?.value) || (vuln.identifiers?.[0]?.name) || '',
            
            // Raw data for flexibility
            raw: vuln
        };
        
        return normalized;
    }

    getFilePath(vuln) {
        if (vuln.location?.file) return vuln.location.file;
        if (vuln.file) return vuln.file;
        if (vuln.location?.dependency?.package?.name) {
            return `dependency: ${vuln.location.dependency.package.name}`;
        }
        return 'unknown';
    }

    getLineNumber(vuln) {
        if (vuln.location?.start_line) return vuln.location.start_line;
        if (vuln.line) return vuln.line;
        return null;
    }

    getScannerName(vuln) {
        if (vuln.scanner?.name) return vuln.scanner.name;
        if (vuln.scanner?.id) return vuln.scanner.id;
        if (vuln.scanner) return vuln.scanner;
        return 'unknown';
    }

    applyFilters() {
        const severity = this.severityFilter.value;
        const scanner = this.scannerFilter.value;
        const search = this.searchFilter.value.toLowerCase();

        this.filteredVulnerabilities = this.vulnerabilities.filter(vuln => {
            // Severity filter
            if (severity && vuln.severity !== severity) {
                return false;
            }

            // Scanner filter
            if (scanner && !vuln.scanner.toLowerCase().includes(scanner)) {
                return false;
            }

            // Search filter
            if (search) {
                const searchableText = `
                    ${vuln.name} 
                    ${vuln.description} 
                    ${vuln.file} 
                    ${vuln.scanner}
                `.toLowerCase();
                
                if (!searchableText.includes(search)) {
                    return false;
                }
            }

            return true;
        });

        this.renderVulnerabilities();
        this.updateStats();
    }

    renderVulnerabilities() {
        if (this.filteredVulnerabilities.length === 0) {
            this.container.innerHTML = `
                <div class="empty-state">
                    <h3>No vulnerabilities found</h3>
                    <p>Try adjusting your filters or search criteria</p>
                </div>
            `;
            return;
        }

        const rows = this.filteredVulnerabilities
            .map(vuln => this.createTableRow(vuln))
            .join('');

        this.container.innerHTML = `
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Name</th>
                        <th>Scanner</th>
                        <th>Location</th>
                        <th>External ID</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;

        this.container.querySelectorAll('.vuln-row').forEach((row, idx) => {
            row.addEventListener('click', () => this.showDetail(this.filteredVulnerabilities[idx]));
        });
    }

    createTableRow(vuln) {
        const sev = this.getSeverityClass(vuln.severity);
        const lineInfo = vuln.line ? `:${vuln.line}` : '';
        const extId = vuln.external_id || '—';
        return `
            <tr class="vuln-row vuln-row--${sev}">
                <td><span class="badge badge-severity badge-${sev}">${vuln.severity.toUpperCase()}</span></td>
                <td class="vuln-row__name">${this.escapeHtml(vuln.name)}</td>
                <td>${this.escapeHtml(vuln.scanner)}</td>
                <td class="vuln-row__location">${this.escapeHtml(vuln.file)}${lineInfo}</td>
                <td class="vuln-row__extid">${this.escapeHtml(extId)}</td>
            </tr>
        `;
    }

    createVulnerabilityCard(vuln) {
        const severityClass = this.getSeverityClass(vuln.severity);
        const lineInfo = vuln.line ? `:${vuln.line}` : '';
        
        return `
            <div class="vulnerability-card ${severityClass}">
                <div class="vuln-header">
                    <div class="vuln-title">${this.escapeHtml(vuln.name)}</div>
                    <div class="vuln-badges">
                        <span class="badge badge-severity badge-${severityClass}">
                            ${vuln.severity.toUpperCase()}
                        </span>
                        <span class="badge badge-scanner">${this.escapeHtml(vuln.scanner)}</span>
                        ${vuln.confidence ? `<span class="badge badge-scanner">Confidence: ${vuln.confidence}</span>` : ''}
                    </div>
                </div>

                <div class="vuln-location">
                    <span class="location-file">${this.escapeHtml(vuln.file)}${lineInfo}</span>
                </div>

                <div class="vuln-description">
                    ${this.escapeHtml(vuln.message)}
                </div>

                <div class="vuln-details">
                    <div class="detail-item">
                        <div class="detail-label">Category</div>
                        <div class="detail-value">${this.escapeHtml(vuln.category)}</div>
                    </div>
                    ${vuln.cve ? `
                        <div class="detail-item">
                            <div class="detail-label">CVE</div>
                            <div class="detail-value">${this.escapeHtml(vuln.cve)}</div>
                        </div>
                    ` : ''}
                </div>

                ${vuln.description && vuln.description !== vuln.message ? `
                    <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--border-color); font-size: 0.95em;">
                        <strong>Details:</strong><br/>
                        ${this.escapeHtml(vuln.description)}
                    </div>
                ` : ''}

                ${vuln.solution ? `
                    <div class="vuln-solution">
                        <div class="solution-label">✓ Remediation</div>
                        ${this.escapeHtml(vuln.solution)}
                    </div>
                ` : ''}
            </div>
        `;
    }

    getSeverityClass(severity) {
        const severityMap = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info'
        };
        return severityMap[severity.toLowerCase()] || 'medium';
    }

    severityValue(severity) {
        const values = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        };
        return values[severity.toLowerCase()] || 0;
    }

    updateStats() {
        const stats = {
            total: this.vulnerabilities.length,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        this.vulnerabilities.forEach(vuln => {
            switch (vuln.severity.toLowerCase()) {
                case 'critical':
                    stats.critical++;
                    break;
                case 'high':
                    stats.high++;
                    break;
                case 'medium':
                    stats.medium++;
                    break;
                case 'low':
                    stats.low++;
                    break;
            }
        });

        this.totalCount.textContent = stats.total;
        this.criticalCount.textContent = stats.critical;
        this.highCount.textContent = stats.high;
        this.mediumCount.textContent = stats.medium;
        this.lowCount.textContent = stats.low;
    }

    resetFilters() {
        this.severityFilter.value = '';
        this.scannerFilter.value = '';
        this.searchFilter.value = '';
        this.applyFilters();
    }

    showError(message) {
        this.container.innerHTML = `
            <div class="empty-state">
                <h3>⚠️ Error</h3>
                <p>${this.escapeHtml(message)}</p>
                <p style="margin-top: 15px; font-size: 0.9em;">
                    Place a <code>vulnerabilities.json</code> file in the <code>data/</code> directory
                </p>
            </div>
        `;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new VulnerabilityDashboard();
});