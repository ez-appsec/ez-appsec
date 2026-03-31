/**
 * Vulnerability Dashboard Application
 * Supports single-project and multi-project (group) modes.
 * Multi-project mode activates when data/index.json is present.
 */

class VulnerabilityDashboard {
    constructor() {
        this.allVulnerabilities = [];       // full set for current view (pre-filter)
        this.filteredVulnerabilities = [];
        this.projects = [];                 // from index.json
        this.currentSlug = 'all';           // 'all' | project slug
        this.multiProject = false;
        this.config = null;

        // DOM elements
        this.severityFilter = document.getElementById('severity-filter');
        this.scannerFilter  = document.getElementById('scanner-filter');
        this.searchFilter   = document.getElementById('search-filter');
        this.resetButton    = document.getElementById('reset-filters');
        this.container      = document.getElementById('vulnerabilities-container');
        this.projectTree    = document.getElementById('project-tree');
        this.sidebar        = document.getElementById('sidebar');
        this.dashTitle      = document.getElementById('dash-title');
        this.scanMeta       = document.getElementById('scan-meta');

        // Stats
        this.totalCount    = document.getElementById('total-count');
        this.criticalCount = document.getElementById('critical-count');
        this.highCount     = document.getElementById('high-count');
        this.mediumCount   = document.getElementById('medium-count');
        this.lowCount      = document.getElementById('low-count');

        this.init();
    }

    async init() {
        this.attachEventListeners();
        this.initModal();
        await this.loadConfig();
        await this.loadIndex();
    }

    // ── Modal ──────────────────────────────────────────────────────────────

    initModal() {
        const modal    = document.getElementById('vuln-modal');
        const closeBtn = document.getElementById('modal-close');
        closeBtn.addEventListener('click', () => this.closeModal());
        modal.addEventListener('click', e => { if (e.target === modal) this.closeModal(); });
        document.addEventListener('keydown', e => { if (e.key === 'Escape') this.closeModal(); });
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

    // ── Filters ────────────────────────────────────────────────────────────

    attachEventListeners() {
        this.severityFilter.addEventListener('change', () => this.applyFilters());
        this.scannerFilter.addEventListener('change',  () => this.applyFilters());
        this.searchFilter.addEventListener('input',    () => this.applyFilters());
        this.resetButton.addEventListener('click',     () => this.resetFilters());
    }

    resetFilters() {
        this.severityFilter.value = '';
        this.scannerFilter.value  = '';
        this.searchFilter.value   = '';
        this.applyFilters();
    }

    // ── Config ─────────────────────────────────────────────────────────────

    async loadConfig() {
        try {
            const r = await fetch('data/config.json');
            if (!r.ok) return;
            this.config = await r.json();

            const rescan = document.getElementById('rescan-btn');
            if (rescan && this.config.project_path && this.config.gitlab_url) {
                rescan.href = `${this.config.gitlab_url}/${this.config.project_path}/-/pipelines/new`;
            }

            if (this.config.ez_appsec_version) {
                const versionLabel = document.getElementById('version-label');
                if (versionLabel) {
                    versionLabel.textContent = `v${this.config.ez_appsec_version}`;
                    versionLabel.hidden = false;
                }
                this.checkForUpgrade(this.config.gitlab_url);
            }
        } catch (e) { /* config is optional */ }
    }

    async checkForUpgrade(gitlabUrl) {
        try {
            const api = `${gitlabUrl}/api/v4/projects/jfelten.work-group%2Fez_appsec%2Fez_appsec/releases/permalink/latest`;
            const r = await fetch(api);
            if (!r.ok) return;
            const release = await r.json();
            const latest  = (release.tag_name || '').replace(/^v/, '');

            if (this.isOutdated(this.config.ez_appsec_version, latest)) {
                const btn   = document.getElementById('upgrade-btn');
                btn.href    = `${gitlabUrl}/jfelten.work-group/ez_appsec/ez_appsec/-/releases`;
                btn.title   = `Upgrade from ${this.config.ez_appsec_version} to ${latest}`;
                btn.textContent = `Upgrade to ${latest}`;
                btn.hidden  = false;
            }
        } catch (e) { /* project not yet public or network unavailable */ }
    }

    isOutdated(installed, latest) {
        if (!installed || !latest) return false;
        const a = installed.split('.').map(Number);
        const b = latest.split('.').map(Number);
        for (let i = 0; i < 3; i++) {
            if ((b[i] || 0) > (a[i] || 0)) return true;
            if ((b[i] || 0) < (a[i] || 0)) return false;
        }
        return false;
    }

    // ── Index / multi-project ──────────────────────────────────────────────

    async loadIndex() {
        try {
            const r = await fetch('data/index.json');
            if (!r.ok) throw new Error('no index');
            const index = await r.json();
            this.projects = index.projects || [];

            if (this.projects.length > 0) {
                this.multiProject = true;
                this.sidebar.removeAttribute('hidden');
                this.renderSidebar();
                await this.selectProject('all');
                return;
            }
        } catch (e) { /* no index.json — single-project fallback */ }

        // Single-project mode
        await this.loadVulnerabilities('data/vulnerabilities.json');
    }

    renderSidebar() {
        this.projectTree.innerHTML = '';

        // "All Projects" root node
        this.projectTree.appendChild(
            this.makeTreeNode('all', 'All Projects', null, true)
        );

        // Per-project nodes
        this.projects.forEach(p => {
            this.projectTree.appendChild(
                this.makeTreeNode(p.slug, p.name, p.summary, false)
            );
        });
    }

    makeTreeNode(slug, name, summary, isAll) {
        const el = document.createElement('div');
        el.className = `tree-node${isAll ? ' tree-node--all' : ''}`;
        el.dataset.slug = slug;

        const badges = summary && (summary.critical > 0 || summary.high > 0)
            ? `<span class="tree-node__badges">
                ${summary.critical > 0 ? `<span class="tree-badge tree-badge--critical">${summary.critical}C</span>` : ''}
                ${summary.high > 0     ? `<span class="tree-badge tree-badge--high">${summary.high}H</span>`         : ''}
               </span>`
            : '';

        el.innerHTML = `
            <span class="tree-node__icon">${isAll ? '◈' : '◦'}</span>
            <span class="tree-node__name">${this.escapeHtml(name)}</span>
            ${badges}
        `;

        el.addEventListener('click', () => this.selectProject(slug));
        return el;
    }

    async selectProject(slug) {
        this.currentSlug = slug;

        // Update active state
        this.projectTree.querySelectorAll('.tree-node').forEach(el => {
            el.classList.toggle('tree-node--active', el.dataset.slug === slug);
        });

        // Update page title
        if (this.dashTitle) {
            if (slug === 'all') {
                this.dashTitle.textContent = 'All Projects';
            } else {
                const proj = this.projects.find(p => p.slug === slug);
                this.dashTitle.textContent = proj ? proj.name : slug;
            }
        }

        if (slug === 'all') {
            await this.loadAllProjects();
        } else {
            await this.loadVulnerabilities(`data/projects/${slug}/vulnerabilities.json`);
        }
    }

    async loadAllProjects() {
        if (this.scanMeta) this.scanMeta.textContent = 'Loading all projects…';

        const results = await Promise.allSettled(
            this.projects.map(async p => {
                const r = await fetch(`data/projects/${p.slug}/vulnerabilities.json`);
                if (!r.ok) return [];
                const data = await r.json();
                const vulns = Array.isArray(data)
                    ? data
                    : (data.vulnerabilities || data.issues || []);
                return vulns.map(v => ({ ...v, _project: p.name, _project_slug: p.slug }));
            })
        );

        const allVulns = results
            .filter(r => r.status === 'fulfilled')
            .flatMap(r => r.value);

        this.allVulnerabilities = allVulns
            .map(v => this.normalizeVulnerability(v))
            .sort((a, b) => this.severityValue(b.severity) - this.severityValue(a.severity));

        if (this.scanMeta) {
            this.scanMeta.textContent =
                `${this.projects.length} projects  ·  ${this.allVulnerabilities.length} total findings`;
        }

        this.populateScannerFilter();
        this.applyFilters();
    }

    // ── Data loading ───────────────────────────────────────────────────────

    async loadVulnerabilities(path = 'data/vulnerabilities.json') {
        try {
            const response = await fetch(path);
            if (!response.ok) throw new Error(`Could not load ${path}`);

            const data = await response.json();

            if (Array.isArray(data)) {
                this.allVulnerabilities = data;
            } else if (data.vulnerabilities) {
                this.allVulnerabilities = data.vulnerabilities;
            } else if (data.issues) {
                this.allVulnerabilities = data.issues;
            } else {
                throw new Error('Invalid vulnerability data format');
            }

            this.allVulnerabilities = this.allVulnerabilities
                .map(v => this.normalizeVulnerability(v))
                .sort((a, b) => this.severityValue(b.severity) - this.severityValue(a.severity));

            this.updateScanMeta(data);
            this.populateScannerFilter();
            this.applyFilters();
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
            this.showError(`Failed to load vulnerabilities: ${error.message}`);
        }
    }

    updateScanMeta(data) {
        if (!this.scanMeta) return;
        const scanDate = data.scan_date || data.generated_at || null;
        const project  = data.project || data.project_name || null;
        const parts    = [];
        if (project)  parts.push(`Project: ${project}`);
        if (scanDate) parts.push(`Scanned: ${new Date(scanDate).toLocaleString()}`);
        parts.push(`${this.allVulnerabilities.length} findings`);
        this.scanMeta.textContent = parts.join('  ·  ');
    }

    populateScannerFilter() {
        const select = this.scannerFilter;
        if (!select || select.tagName !== 'SELECT') return;
        const scanners = [...new Set(
            this.allVulnerabilities.map(v => v.scanner).filter(Boolean)
        )].sort();
        while (select.options.length > 1) select.remove(1);
        scanners.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.toLowerCase();
            opt.textContent = s;
            select.appendChild(opt);
        });
    }

    // ── Normalization ──────────────────────────────────────────────────────

    normalizeVulnerability(vuln) {
        return {
            id:          vuln.id || vuln.cve || '',
            name:        vuln.name || vuln.title || '',
            message:     vuln.message || vuln.description || '',
            description: vuln.description || vuln.message || '',
            severity:    (vuln.severity || 'medium').toLowerCase(),
            confidence:  vuln.confidence || 'medium',
            category:    vuln.category || vuln.type || 'unknown',
            file:        this.getFilePath(vuln),
            line:        this.getLineNumber(vuln),
            scanner:     this.getScannerName(vuln),
            solution:    vuln.solution || '',
            cve:         vuln.cve || '',
            identifiers: vuln.identifiers || [],
            links:       vuln.links || [],
            external_id: vuln.cve || (vuln.identifiers?.[0]?.value) || (vuln.identifiers?.[0]?.name) || '',
            project:     vuln._project || null,
            raw:         vuln,
        };
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
        if (vuln.scanner?.id)   return vuln.scanner.id;
        if (vuln.scanner)       return vuln.scanner;
        return 'unknown';
    }

    // ── Filtering & rendering ──────────────────────────────────────────────

    applyFilters() {
        const severity = this.severityFilter.value;
        const scanner  = this.scannerFilter.value;
        const search   = this.searchFilter.value.toLowerCase();

        this.filteredVulnerabilities = this.allVulnerabilities.filter(vuln => {
            if (severity && vuln.severity !== severity) return false;
            if (scanner  && !vuln.scanner.toLowerCase().includes(scanner)) return false;
            if (search) {
                const text = `${vuln.name} ${vuln.description} ${vuln.file} ${vuln.scanner} ${vuln.project || ''}`.toLowerCase();
                if (!text.includes(search)) return false;
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
                </div>`;
            return;
        }

        const showProject = this.multiProject && this.currentSlug === 'all';
        const projectHeader = showProject ? '<th>Project</th>' : '';

        const rows = this.filteredVulnerabilities
            .map(v => this.createTableRow(v, showProject))
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
                        ${projectHeader}
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>`;

        this.container.querySelectorAll('.vuln-row').forEach((row, idx) => {
            row.addEventListener('click', () => this.showDetail(this.filteredVulnerabilities[idx]));
        });
    }

    createTableRow(vuln, showProject = false) {
        const sev      = this.getSeverityClass(vuln.severity);
        const lineInfo = vuln.line ? `:${vuln.line}` : '';
        const extId    = vuln.external_id || '—';
        const projectCell = showProject
            ? `<td class="vuln-row__project">${this.escapeHtml(vuln.project || '—')}</td>`
            : '';
        return `
            <tr class="vuln-row vuln-row--${sev}">
                <td><span class="badge badge-severity badge-${sev}">${vuln.severity.toUpperCase()}</span></td>
                <td class="vuln-row__name">${this.escapeHtml(vuln.name)}</td>
                <td>${this.escapeHtml(vuln.scanner)}</td>
                <td class="vuln-row__location">${this.escapeHtml(vuln.file)}${lineInfo}</td>
                <td class="vuln-row__extid">${this.escapeHtml(extId)}</td>
                ${projectCell}
            </tr>`;
    }

    createVulnerabilityCard(vuln) {
        const severityClass = this.getSeverityClass(vuln.severity);
        const lineInfo = vuln.line ? `:${vuln.line}` : '';
        const projectBadge = vuln.project
            ? `<span class="badge badge-scanner">${this.escapeHtml(vuln.project)}</span>`
            : '';

        return `
            <div class="vulnerability-card ${severityClass}">
                <div class="vuln-header">
                    <div class="vuln-title">${this.escapeHtml(vuln.name)}</div>
                    <div class="vuln-badges">
                        <span class="badge badge-severity badge-${severityClass}">${vuln.severity.toUpperCase()}</span>
                        <span class="badge badge-scanner">${this.escapeHtml(vuln.scanner)}</span>
                        ${projectBadge}
                        ${vuln.confidence ? `<span class="badge badge-scanner">Confidence: ${vuln.confidence}</span>` : ''}
                    </div>
                </div>
                <div class="vuln-location">
                    <span class="location-file">${this.escapeHtml(vuln.file)}${lineInfo}</span>
                </div>
                <div class="vuln-description">${this.escapeHtml(vuln.message)}</div>
                <div class="vuln-details">
                    <div class="detail-item">
                        <div class="detail-label">Category</div>
                        <div class="detail-value">${this.escapeHtml(vuln.category)}</div>
                    </div>
                    ${vuln.cve ? `
                        <div class="detail-item">
                            <div class="detail-label">CVE</div>
                            <div class="detail-value">${this.escapeHtml(vuln.cve)}</div>
                        </div>` : ''}
                </div>
                ${vuln.description && vuln.description !== vuln.message ? `
                    <div style="margin-top:15px;padding-top:15px;border-top:1px solid var(--border);font-size:.95em;">
                        <strong>Details:</strong><br/>${this.escapeHtml(vuln.description)}
                    </div>` : ''}
                ${vuln.solution ? `
                    <div class="vuln-solution">
                        <div class="solution-label">✓ Remediation</div>
                        ${this.escapeHtml(vuln.solution)}
                    </div>` : ''}
            </div>`;
    }

    // ── Stats ──────────────────────────────────────────────────────────────

    updateStats() {
        const stats = { total: this.allVulnerabilities.length, critical: 0, high: 0, medium: 0, low: 0 };
        this.allVulnerabilities.forEach(v => {
            if (v.severity in stats) stats[v.severity]++;
        });
        this.totalCount.textContent    = stats.total;
        this.criticalCount.textContent = stats.critical;
        this.highCount.textContent     = stats.high;
        this.mediumCount.textContent   = stats.medium;
        this.lowCount.textContent      = stats.low;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    getSeverityClass(severity) {
        return { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' }[severity.toLowerCase()] || 'medium';
    }

    severityValue(severity) {
        return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity.toLowerCase()] || 0;
    }

    showError(message) {
        this.container.innerHTML = `
            <div class="empty-state">
                <h3>⚠️ Error</h3>
                <p>${this.escapeHtml(message)}</p>
                <p style="margin-top:15px;font-size:.9em;">
                    Place a <code>vulnerabilities.json</code> file in the <code>data/</code> directory
                </p>
            </div>`;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = String(text || '');
        return div.innerHTML;
    }
}

document.addEventListener('DOMContentLoaded', () => { new VulnerabilityDashboard(); });
