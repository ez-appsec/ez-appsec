/**
 * Vulnerability Dashboard Application
 * Loads and displays security vulnerabilities from JSON files
 */

class VulnerabilityDashboard {
    constructor() {
        this.vulnerabilities = [];
        this.filteredVulnerabilities = [];
        
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
        await this.loadVulnerabilities();
    }

    attachEventListeners() {
        this.severityFilter.addEventListener('change', () => this.applyFilters());
        this.scannerFilter.addEventListener('change', () => this.applyFilters());
        this.searchFilter.addEventListener('input', () => this.applyFilters());
        this.resetButton.addEventListener('click', () => this.resetFilters());
    }

    async loadVulnerabilities() {
        try {
            // Try to load all JSON files from data/ directory
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
            
            this.applyFilters();
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
            this.showError(`Failed to load vulnerabilities: ${error.message}`);
        }
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

        this.container.innerHTML = this.filteredVulnerabilities
            .map(vuln => this.createVulnerabilityCard(vuln))
            .join('');
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