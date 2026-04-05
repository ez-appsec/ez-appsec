/**
 * Vulnerability Dashboard Application
 * GitHub Pages version for ez-appsec GitHub integration.
 * Supports single-project and multi-project (organization) modes.
 * Multi-project mode activates when data/index.json is present.
 */

class GitHubDashboard {
    constructor() {
        this.allVulnerabilities = [];       // full set for current view (pre-filter)
        this.filteredVulnerabilities = [];
        this.projects = [];                 // from index.json
        this.currentSlug = 'all';           // 'all' | project slug
        this.multiProject = false;
        this.config = null;
        this.falsePositives = new Set();
        this.remediationModal = null;
        this.scanDates = [];          // ISO date strings used to compute avg age
        this.currentPage = 0;
        this.PAGE_SIZE = 100;

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
        this.criticalCount = document.getElementById('critical-count');
        this.highCount     = document.getElementById('high-count');
        this.mediumCount   = document.getElementById('medium-count');
        this.lowCount      = document.getElementById('low-count');

        this.init();
    }

    async init() {
        this.attachEventListeners();
        this.initModal();
        this.initRemediationModal();
        await this.loadConfig();
        await this.loadIndex();
    }

    // ── Modal ──────────────────────────────────────────────────────────────

    initModal() {
        const modal    = document.getElementById('vuln-modal');
        const closeBtn = document.getElementById('modal-close');
        closeBtn.addEventListener('click', () => this.closeModal());
        modal.addEventListener('click', e => { if (e.target === modal) this.closeModal(); });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && modal.classList.contains('modal-overlay--open')) this.closeModal();
        });
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

    // ── Remediation Modal ──────────────────────────────────────────

    initRemediationModal() {
        const modal = document.createElement('div');
        modal.id = 'remediation-modal';
        modal.className = 'modal-overlay';
        modal.setAttribute('aria-hidden', 'true');
        modal.innerHTML = `
            <div class="modal-panel remediation-panel" role="dialog" aria-modal="true">
                <button class="modal-close" id="remediation-modal-close" aria-label="Close">&times;</button>
                <div id="remediation-content"></div>
            </div>`;
        document.body.appendChild(modal);
        this.remediationModal = modal;

        modal.querySelector('#remediation-modal-close').addEventListener('click', () => this.closeRemediationModal());
        modal.addEventListener('click', e => { if (e.target === modal) this.closeRemediationModal(); });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && modal.classList.contains('modal-overlay--open')) this.closeRemediationModal();
        });
    }

    showRemediationModal(vuln) {
        const key  = vuln.id || vuln.name;
        const isFp = this.falsePositives.has(key);
        const sev  = this.getSeverityClass(vuln.severity);
        const loc  = `${vuln.file}${vuln.line ? ':' + vuln.line : ''}`;

        const verifyPrompt = [
            'Please analyze whether this vulnerability is a false positive:',
            '',
            `Name: ${vuln.name}`,
            `Severity: ${vuln.severity}`,
            `File: ${loc}`,
            `Scanner: ${vuln.scanner}`,
            `Description: ${vuln.description || vuln.message}`,
        ].join('\n');

        const fixPrompt = [
            '/ez-appsec fix',
            '',
            `Name: ${vuln.name}`,
            `Severity: ${vuln.severity}`,
            `File: ${loc}`,
            `Scanner: ${vuln.scanner}`,
            `Description: ${vuln.description || vuln.message}`,
            ...(vuln.solution ? [`Suggested fix: ${vuln.solution}`] : []),
        ].join('\n');

        document.getElementById('remediation-content').innerHTML = `
            <div class="remediation-header">
                <span class="badge badge-severity badge-${sev}">${vuln.severity.toUpperCase()}</span>
                <h2 class="remediation-title">${this.escapeHtml(vuln.name)}</h2>
                <p class="remediation-location">${this.escapeHtml(loc)}</p>
            </div>
            <div class="remediation-actions">
                <button class="remediation-option${isFp ? ' remediation-option--active' : ''}" id="rem-fp">
                    <span class="rem-icon">🚫</span>
                    <span class="rem-text"><span class="rem-label">${isFp ? 'Unmark False Positive' : 'Mark False Positive'}</span><span class="rem-desc">${isFp ? 'Currently flagged as FP' : 'Flag finding as a false positive'}</span></span>
                </button>
                <button class="remediation-option" id="rem-verify">
                    <span class="rem-icon">🔍</span>
                    <span class="rem-text"><span class="rem-label">Verify with AI</span><span class="rem-desc">Copy prompt to check if this is a false positive</span></span>
                </button>
                <button class="remediation-option" id="rem-fix">
                    <span class="rem-icon">🔧</span>
                    <span class="rem-text"><span class="rem-label">Fix with AI</span><span class="rem-desc">Copy /ez-appsec fix prompt for AI chat</span></span>
                </button>
            </div>
            <div class="remediation-copy-area" id="rem-copy-area" hidden>
                <div class="rem-copy-label">Copy this prompt into your AI chat:</div>
                <pre class="rem-copy-text" id="rem-copy-text"></pre>
                <button class="btn btn--primary btn--sm" id="rem-copy-btn">Copy to Clipboard</button>
            </div>`;

        document.getElementById('rem-fp').addEventListener('click', () => {
            if (this.falsePositives.has(key)) { this.falsePositives.delete(key); }
            else { this.falsePositives.add(key); }
            this.closeRemediationModal();
            this.applyFilters();
        });

        const showCopy = (text) => {
            document.getElementById('rem-copy-text').textContent = text;
            document.getElementById('rem-copy-area').removeAttribute('hidden');
            document.getElementById('rem-copy-btn').onclick = () => {
                navigator.clipboard.writeText(text).then(() => {
                    const btn = document.getElementById('rem-copy-btn');
                    btn.textContent = 'Copied!';
                    setTimeout(() => { btn.textContent = 'Copy to Clipboard'; }, 2000);
                });
            };
        };

        document.getElementById('rem-verify').addEventListener('click', () => showCopy(verifyPrompt));
        document.getElementById('rem-fix').addEventListener('click', () => showCopy(fixPrompt));

        this.remediationModal.setAttribute('aria-hidden', 'false');
        this.remediationModal.classList.add('modal-overlay--open');
        document.body.style.overflow = 'hidden';
    }

    closeRemediationModal() {
        this.remediationModal.setAttribute('aria-hidden', 'true');
        this.remediationModal.classList.remove('modal-overlay--open');
        document.body.style.overflow = '';
    }

    // ── Filters ────────────────────────────────────────────────────

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

    // ── Config ─────────────────────────────────────────────────────

    async loadConfig() {
        try {
            const r = await fetch('data/config.json');
            if (!r.ok) return;
            this.config = await r.json();

            if (this.config.ez_appsec_version) {
                const versionLabel = document.getElementById('version-label');
                if (versionLabel) {
                    versionLabel.textContent = `v${this.config.ez_appsec_version}`;
                    versionLabel.hidden = false;
                }
                this.checkForUpgrade();
            }
        } catch (e) { /* config is optional */ }
    }

    async checkForUpgrade() {
        try {
            const api = 'https://api.github.com/repos/jfelten/ez-appsec/releases/latest';
            const r = await fetch(api);
            if (!r.ok) return;
            const release = await r.json();
            const latest  = release.tag_name || release.name || '';

            if (this.isOutdated(this.config?.ez_appsec_version, latest)) {
                const btn   = document.getElementById('upgrade-btn');
                btn.href    = release.html_url || 'https://github.com/jfelten/ez-appsec/releases';
                btn.title   = `Upgrade from ${this.config.ez_appsec_version} to ${latest}`;
                btn.textContent = `Upgrade to ${latest}`;
                btn.hidden  = false;
            }
        } catch (e) { /* network unavailable */ }
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

    // ── Index / multi-project ──────────────────────────────────────

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

                // Honour ?project= query param for linkable URLs
                const params = new URLSearchParams(window.location.search);
                const requested = params.get('project');
                const valid = requested && this.projects.some(p => p.slug === requested);
                await this.selectProject(valid ? requested : 'all');
                return;
            }
        } catch (e) { /* no index.json — single-project fallback */ }

        // Single-project mode
        await this.loadVulnerabilities('data/vulnerabilities.json');

        // Try to set rescan button from meta.json (single-project deploy)
        try {
            const mr = await fetch('data/meta.json');
            if (mr.ok) {
                const meta = await mr.json();
                const projectUrl = meta.github_url || null;
                const rescanBtn = document.getElementById('rescan-btn');
                if (rescanBtn && projectUrl) {
                    rescanBtn.href = projectUrl;
                    rescanBtn.classList.add('rescan-btn--visible');
                }
            }
        } catch (e) { /* meta.json is optional */ }
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
            ${!isAll ? `<button class="tree-node__link" title="Copy link" data-slug="${this.escapeHtml(slug)}">🔗</button>` : ''}
        `;

        el.addEventListener('click', e => {
            if (e.target.closest('.tree-node__link')) return;
            this.selectProject(slug);
        });

        if (!isAll) {
            el.querySelector('.tree-node__link').addEventListener('click', e => {
                e.stopPropagation();
                const url = new URL(window.location.href);
                url.searchParams.set('project', slug);
                navigator.clipboard.writeText(url.toString()).then(() => {
                    const btn = e.currentTarget;
                    btn.textContent = '✓';
                    setTimeout(() => { btn.textContent = '🔗'; }, 1500);
                });
            });
        }

        return el;
    }

    async selectProject(slug) {
        this.currentSlug = slug;

        // Update active state in sidebar
        this.projectTree.querySelectorAll('.tree-node').forEach(el => {
            el.classList.toggle('tree-node--active', el.dataset.slug === slug);
        });

        // Update page title + rescan button per selected project
        const rescanBtn = document.getElementById('rescan-btn');
        if (slug === 'all') {
            if (this.dashTitle) this.dashTitle.textContent = 'All Projects';
            if (rescanBtn) rescanBtn.classList.remove('rescan-btn--visible');
        } else {
            const proj = this.projects.find(p => p.slug === slug);
            const label      = proj ? proj.name : slug;
            const projectUrl = proj ? `https://github.com/${proj.project_path || proj.slug}` : null;

            if (this.dashTitle) {
                if (projectUrl) {
                    this.dashTitle.innerHTML = `<a class="dash-title__link" href="${this.escapeHtml(projectUrl)}" target="_blank" rel="noopener">${this.escapeHtml(label)}</a>`;
                } else {
                    this.dashTitle.textContent = label;
                }
            }

            if (rescanBtn) {
                if (projectUrl) {
                    rescanBtn.href = projectUrl;
                    rescanBtn.classList.add('rescan-btn--visible');
                } else {
                    rescanBtn.classList.remove('rescan-btn--visible');
                }
            }
        }

        // Update URL so this view is linkable
        const url = new URL(window.location.href);
        if (slug === 'all') {
            url.searchParams.delete('project');
        } else {
            url.searchParams.set('project', slug);
        }
        history.replaceState(null, '', url.toString());

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
                const projectUrl = `https://github.com/${p.project_path || p.slug}`;
                const r = await fetch(`data/projects/${p.slug}/vulnerabilities.json`);
                if (!r.ok) return { status: 'rejected', value: null };
                const data = await r.json();
                const vulns = Array.isArray(data)
                    ? data
                    : (data.vulnerabilities || data.issues || []);
                const scanDate = data.scan_date || data.generated_at || null;
                return { status: 'fulfilled', value: { vulns: vulns.map(v => ({ ...v, _project: p.name, _project_slug: p.slug })), project: p, projectUrl, scanDate } };
            })
        );

        const projectStats = [];
        const allVulns = [];
        const scanDates = [];
        results.forEach(r => {
            if (r.status !== 'fulfilled') return;
            const { vulns, project, projectUrl, scanDate } = r.value;
            if (scanDate) scanDates.push(scanDate);
            const normalized = vulns.map(v => this.normalizeVulnerability(v));
            allVulns.push(...normalized);
            const stats = { total: normalized.length, critical: 0, high: 0, medium: 0, low: 0 };
            normalized.forEach(v => { if (v.severity in stats) stats[v.severity]++; });
            projectStats.push({ project, stats, projectUrl });
        });

        this.allVulnerabilities = allVulns
            .sort((a, b) => this.severityValue(b.severity) - this.severityValue(a.severity));

        this.scanDates = scanDates.length
            ? scanDates
            : this.projects.map(p => p.last_updated).filter(Boolean);

        if (this.scanMeta) {
            this.scanMeta.textContent =
                `${this.projects.length} projects  ·  ${this.allVulnerabilities.length} total findings`;
        }

        this.populateScannerFilter();
        this.applyFilters();
    }

    // ── Data loading ───────────────────────────────────────────────

    async loadVulnerabilities(path = 'data/vulnerabilities.json') {
        try {
            const response = await fetch(path);
            if (!response.ok) throw new Error(`Could not load ${path}`);

            const data = await response.json();

            if (Array.isArray(data)) {
                this.allVulnerabilities = data;
            } else if (data.vulnerabilities) {
                this.allVulnerabilities = data.vulnerabilities;
            } else if (data.runs && data.runs[0] && data.runs[0].results) {
                // Handle SARIF format
                const sarifResults = data.runs[0].results;
                const rules = data.runs[0].tool?.driver?.rules || [];

                this.allVulnerabilities = sarifResults.map(result => {
                    const rule = rules.find(r => r.id === result.ruleId);
                    return this.normalizeVulnerability({
                        name: result.ruleId,
                        message: result.message?.text || '',
                        severity: this.sarifLevelToSeverity(result.level),
                        locations: result.locations || [],
                        scanner: 'sarif'
                    });
                });
            } else {
                throw new Error('Invalid vulnerability data format');
            }

            this.allVulnerabilities = this.allVulnerabilities
                .map(v => this.normalizeVulnerability(v))
                .sort((a, b) => this.severityValue(b.severity) - this.severityValue(a.severity));

            // Store scan date for avg-age calculation
            const scanDate = data.scan_date || data.generated_at || response.headers.get('Last-Modified') || null;
            this.scanDates = scanDate ? [scanDate] : [];

            this.updateScanMeta(data);
            this.populateScannerFilter();
            this.applyFilters();
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
            this.showError(`Failed to load vulnerabilities: ${error.message}`);
        }
    }

    sarifLevelToSeverity(level) {
        const mapping = { 'error': 'critical', 'warning': 'medium', 'note': 'low' };
        return mapping[level] || 'medium';
    }

    updateScanMeta(data) {
        if (!this.scanMeta) return;
        const scanDate = data.scan_date || data.generated_at || null;
        const project  = data.project_name || data.project_path || null;
        const parts    = [];
        if (project) parts.push(`Project: ${project}`);
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

    // ── Normalization ──────────────────────────────────────────────

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

    // ── Filtering & rendering ──────────────────────────────────────

    applyFilters() {
        const severity = this.severityFilter.value;
        const scanner  = this.scannerFilter.value;
        const search   = this.searchFilter.value.toLowerCase();

        this.currentPage = 0;
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

        const total     = this.filteredVulnerabilities.length;
        const pageCount = Math.ceil(total / this.PAGE_SIZE);
        this.currentPage = Math.min(this.currentPage, pageCount - 1);
        const start  = this.currentPage * this.PAGE_SIZE;
        const end    = Math.min(start + this.PAGE_SIZE, total);
        const page   = this.filteredVulnerabilities.slice(start, end);

        const showProject   = this.multiProject && this.currentSlug === 'all';
        const projectHeader = showProject ? '<th>Project</th>' : '';

        const rows = page.map((v, i) => this.createTableRow(v, showProject, start + i)).join('');

        const pagination = pageCount > 1 ? `
            <div class="pagination">
                <button class="pagination__btn" id="pg-prev" ${this.currentPage === 0 ? 'disabled' : ''}>← Prev</button>
                <span class="pagination__info">Rows ${start + 1}–${end} of ${total}</span>
                <button class="pagination__btn" id="pg-next" ${this.currentPage >= pageCount - 1 ? 'disabled' : ''}>Next →</button>
            </div>` : '';

        this.container.innerHTML = `
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th class="th-rem"></th>
                        <th>Severity</th>
                        <th>Name</th>
                        <th>Scanner</th>
                        <th>Location</th>
                        <th>External ID</th>
                        ${projectHeader}
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
            ${pagination}`;

        this.container.querySelectorAll('.vuln-row').forEach((row, i) => {
            row.addEventListener('click', () => this.showDetail(this.filteredVulnerabilities[start + i]));
        });

        this.container.querySelectorAll('.btn-remediate').forEach(btn => {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.idx, 10);
                this.showRemediationModal(this.filteredVulnerabilities[idx]);
            });
        });

        const prevBtn = document.getElementById('pg-prev');
        const nextBtn = document.getElementById('pg-next');
        if (prevBtn) prevBtn.addEventListener('click', () => { this.currentPage--; this.renderVulnerabilities(); this.container.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
        if (nextBtn) nextBtn.addEventListener('click', () => { this.currentPage++; this.renderVulnerabilities(); this.container.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    }

    createTableRow(vuln, showProject = false, idx = 0) {
        const sev      = this.getSeverityClass(vuln.severity);
        const lineInfo = vuln.line ? `:${vuln.line}` : '';
        const extId    = vuln.external_id || '—';
        const isFp     = this.falsePositives.has(vuln.id || vuln.name);
        const projectCell = showProject
            ? `<td class="vuln-row__project">${this.escapeHtml(vuln.project || '—')}</td>`
            : '';

        return `
            <tr class="vuln-row vuln-row--${sev}${isFp ? ' vuln-row--fp' : ''}">
                <td class="td-rem"><button class="btn-remediate" data-idx="${idx}" title="Remediate">⚕</button></td>
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

    // ── Stats ──────────────────────────────────────────────────────

    updateStats() {
        const stats = { critical: 0, high: 0, medium: 0, low: 0 };
        this.allVulnerabilities.forEach(v => {
            if (v.severity in stats) stats[v.severity]++;
        });
        stats.total = stats.critical + stats.high + stats.medium + stats.low;
        this.criticalCount.textContent = stats.critical;
        this.highCount.textContent     = stats.high;
        this.mediumCount.textContent   = stats.medium;
        this.lowCount.textContent      = stats.low;
        this.renderPieChart(stats);

        const ageEl = document.getElementById('age-count');
        if (ageEl) ageEl.textContent = this.computeAvgAge();
    }

    computeAvgAge() {
        if (!this.scanDates.length) return '—';
        const now = Date.now();
        const ages = this.scanDates
            .map(d => (now - new Date(d).getTime()) / 86400000)
            .filter(d => !isNaN(d) && d >= 0);
        if (!ages.length) return '—';
        const avg = Math.round(ages.reduce((s, d) => s + d, 0) / ages.length);
        return `${avg}d`;
    }

    renderPieChart(stats) {
        const el = document.getElementById('stats-chart');
        if (!el) return;

        const segments = [
            { value: stats.critical, color: '#f87171' },
            { value: stats.high,     color: '#fb923c' },
            { value: stats.medium,   color: '#fbbf24' },
            { value: stats.low,      color: '#34d399' },
        ];
        const total = stats.total;

        const r = 34, cx = 44, cy = 44, sw = 12;
        const circ = 2 * Math.PI * r;

        let accum = 0;
        const arcs = segments.map(seg => {
            if (seg.value === 0) return '';
            const len    = (seg.value / total) * circ;
            const rotate = (accum / circ) * 360 - 90;
            accum += len;
            return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
                stroke="${seg.color}" stroke-width="${sw}"
                stroke-dasharray="${len.toFixed(2)} ${(circ - len).toFixed(2)}"
                transform="rotate(${rotate.toFixed(2)} ${cx} ${cy})"/>`;
        }).join('');

        const label = total === 0
            ? `<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="middle" fill="#7a8099" font-size="11">—</text>`
            : `<text x="${cx}" y="${cy - 6}" text-anchor="middle" dominant-baseline="middle" fill="#e2e6f0" font-size="14" font-weight="800">${total}</text>
               <text x="${cx}" y="${cy + 9}" text-anchor="middle" dominant-baseline="middle" fill="#7a8099" font-size="9" letter-spacing="0.5">TOTAL</text>`;

        el.innerHTML = `<svg width="88" height="88" viewBox="0 0 88 88">
            <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#252a38" stroke-width="${sw}"/>
            ${total > 0 ? arcs : ''}
            ${label}
        </svg>`;
    }

    // ── Helpers ────────────────────────────────────────────────────

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

document.addEventListener('DOMContentLoaded', () => { new GitHubDashboard(); });
