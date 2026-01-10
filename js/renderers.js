// ============================================
// SECURITY SITUATION MONITOR - RENDERERS
// DOM rendering functions for each panel
// Safe DOM manipulation without innerHTML
// ============================================

import { COUNTRY_CODES } from './constants.js';

/**
 * Create element with text content (safe)
 */
function createElement(tag, className, textContent) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (textContent) el.textContent = textContent;
    return el;
}

/**
 * Create link element
 */
function createLink(href, text, className) {
    const a = document.createElement('a');
    a.href = href;
    a.textContent = text;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    if (className) a.className = className;
    return a;
}

/**
 * Clear container and show empty state
 */
function showEmptyState(container, icon, text) {
    container.textContent = '';
    const emptyDiv = createElement('div', 'empty-state');
    emptyDiv.appendChild(createElement('div', 'empty-state-icon', icon));
    emptyDiv.appendChild(createElement('div', 'empty-state-text', text));
    container.appendChild(emptyDiv);
}

/**
 * Truncate text
 */
function truncate(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

/**
 * Format date
 */
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });
    } catch {
        return dateString;
    }
}

/**
 * Format date and time
 */
function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return dateString;
    }
}

/**
 * Get country name from code
 */
function getCountryName(code) {
    if (!code) return 'Unknown';
    return COUNTRY_CODES[code.toUpperCase()] || code;
}

/**
 * Render CVE items to the panel
 */
export function renderCVEs(cves, containerId = 'cve-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    if (!cves || cves.length === 0) {
        showEmptyState(container, '🛡️', 'No CVEs found');
        return;
    }

    cves.forEach(cve => {
        const item = createElement('div', `cve-item ${cve.severity}`);
        item.dataset.severity = cve.severity;

        // Header
        const header = createElement('div', 'cve-header');
        const idDiv = createElement('div', 'cve-id');
        idDiv.appendChild(createLink(`https://nvd.nist.gov/vuln/detail/${cve.id}`, cve.id));
        header.appendChild(idDiv);

        const scoreDiv = createElement('div', `cve-score ${cve.severity}`, cve.score.toFixed(1));
        header.appendChild(scoreDiv);
        item.appendChild(header);

        // Description
        const desc = createElement('div', 'cve-description', truncate(cve.description, 150));
        item.appendChild(desc);

        // Meta
        const meta = createElement('div', 'cve-meta');
        meta.appendChild(createElement('span', null, `Published: ${formatDate(cve.published)}`));
        meta.appendChild(createElement('span', null, cve.vector));
        item.appendChild(meta);

        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('cve-count');
    if (countBadge) {
        countBadge.textContent = cves.length;
    }
}

/**
 * Render CISA KEV items
 */
export function renderKEVs(kevs, containerId = 'kev-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    if (!kevs || kevs.length === 0) {
        showEmptyState(container, '✓', 'No recent KEVs');
        return;
    }

    kevs.forEach(kev => {
        const item = createElement('div', `kev-item ${kev.knownRansomware ? 'ransomware' : ''}`);

        // Header
        const header = createElement('div', 'kev-header');
        const idDiv = createElement('div', 'kev-id');
        idDiv.appendChild(createLink(`https://nvd.nist.gov/vuln/detail/${kev.id}`, kev.id));
        header.appendChild(idDiv);
        header.appendChild(createElement('div', 'kev-due', `Due: ${formatDate(kev.dueDate)}`));
        item.appendChild(header);

        // Vendor and product
        item.appendChild(createElement('div', 'kev-vendor', kev.vendor));
        item.appendChild(createElement('div', 'kev-product', kev.product));

        if (kev.knownRansomware) {
            item.appendChild(createElement('div', 'kev-ransomware-tag', '⚠ Ransomware'));
        }

        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('kev-count');
    if (countBadge) {
        countBadge.textContent = kevs.length;
    }
}

/**
 * Render Threat Intelligence IOCs
 */
export function renderThreatIntel(data, containerId = 'threat-intel-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    const iocs = data.iocs || [];

    if (iocs.length === 0) {
        showEmptyState(container, '🔍', 'No IOCs found');
        return;
    }

    iocs.slice(0, 30).forEach(ioc => {
        const item = createElement('div', 'threat-item');
        item.dataset.type = ioc.type;

        // Header
        const header = createElement('div', 'threat-header');
        header.appendChild(createElement('span', 'threat-type', ioc.type));
        header.appendChild(createElement('span', 'threat-confidence', `${ioc.confidence}% confidence`));
        item.appendChild(header);

        // IOC value
        item.appendChild(createElement('div', 'threat-ioc', truncate(ioc.value, 60)));

        // Malware
        item.appendChild(createElement('div', 'threat-malware', ioc.malware || 'Unknown'));

        // Tags
        if (ioc.tags && ioc.tags.length > 0) {
            const tagsDiv = createElement('div', 'threat-tags');
            ioc.tags.slice(0, 5).forEach(tag => {
                tagsDiv.appendChild(createElement('span', 'threat-tag', tag));
            });
            item.appendChild(tagsDiv);
        }

        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('threat-count');
    if (countBadge) {
        countBadge.textContent = iocs.length;
    }
}

/**
 * Render Malware Families
 */
export function renderMalwareFamilies(data, containerId = 'malware-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    const families = data.malwareFamilies || [];

    if (families.length === 0) {
        showEmptyState(container, '🦠', 'No malware detected');
        return;
    }

    families.forEach(family => {
        const item = createElement('div', 'malware-item');
        item.appendChild(createElement('span', 'malware-name', family.name));
        item.appendChild(createElement('span', 'malware-count', `${family.count} IOCs`));
        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('malware-count');
    if (countBadge) {
        countBadge.textContent = families.length;
    }
}

/**
 * Render Ransomware Victims
 */
export function renderRansomwareVictims(victims, containerId = 'ransomware-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    if (!victims || victims.length === 0) {
        showEmptyState(container, '🔒', 'No recent victims');
        return;
    }

    victims.slice(0, 20).forEach(victim => {
        const item = createElement('div', 'ransomware-item');

        // Header
        const header = createElement('div', 'ransomware-header');
        header.appendChild(createElement('span', 'ransomware-victim', victim.name));
        header.appendChild(createElement('span', 'ransomware-group', victim.group));
        item.appendChild(header);

        // Meta
        const meta = createElement('div', 'ransomware-meta');
        meta.appendChild(createElement('span', 'ransomware-country', getCountryName(victim.country)));
        meta.appendChild(createElement('span', 'ransomware-sector', victim.sector));
        meta.appendChild(createElement('span', 'ransomware-date', formatDate(victim.discovered)));
        item.appendChild(meta);

        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('ransomware-count');
    if (countBadge) {
        countBadge.textContent = victims.length;
    }
}

/**
 * Render Ransomware Groups
 */
export function renderRansomwareGroups(groups, containerId = 'groups-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    if (!groups || groups.length === 0) {
        showEmptyState(container, '👥', 'No groups found');
        return;
    }

    groups.forEach(group => {
        const item = createElement('div', 'group-item');
        item.appendChild(createElement('span', 'group-name', group.name));
        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('groups-count');
    if (countBadge) {
        countBadge.textContent = groups.length;
    }
}

/**
 * Render Correlation Analysis
 */
export function renderCorrelations(correlations, containerId = 'correlation-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    if (!correlations || correlations.length === 0) {
        showEmptyState(container, '🔗', 'Building correlations...');
        return;
    }

    correlations.forEach(corr => {
        const item = createElement('div', 'correlation-item');
        item.appendChild(createElement('div', 'correlation-header', corr.type));
        item.appendChild(createElement('div', 'correlation-detail', corr.description));
        if (corr.cveId) {
            item.appendChild(createElement('div', 'correlation-link', `CVE: ${corr.cveId}`));
        }
        if (corr.malware) {
            item.appendChild(createElement('div', 'correlation-link', `Malware: ${corr.malware}`));
        }
        container.appendChild(item);
    });

    // Update count badge
    const countBadge = document.getElementById('correlation-count');
    if (countBadge) {
        countBadge.textContent = correlations.length;
    }
}

/**
 * Render Stats
 */
export function renderStats(stats) {
    const elements = {
        'stat-critical': stats.criticalCVEs || 0,
        'stat-kev': stats.kevCount || 0,
        'stat-iocs': stats.iocCount || 0,
        'stat-victims': stats.victimCount || 0
    };

    Object.entries(elements).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = value.toLocaleString();
        }
    });
}

/**
 * Render Timeline
 */
export function renderTimeline(events, containerId = 'timeline-content') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.textContent = '';

    if (!events || events.length === 0) {
        showEmptyState(container, '📅', 'No recent events');
        return;
    }

    events.slice(0, 15).forEach(event => {
        const item = createElement('div', `timeline-item ${event.type}`);
        item.appendChild(createElement('div', 'timeline-time', formatDateTime(event.timestamp)));
        item.appendChild(createElement('div', 'timeline-title', event.title));
        item.appendChild(createElement('div', 'timeline-desc', event.description));
        container.appendChild(item);
    });
}

/**
 * Update last refresh time
 */
export function updateLastRefresh() {
    const el = document.getElementById('last-update');
    if (el) {
        el.textContent = new Date().toLocaleTimeString();
    }
}

/**
 * Set status indicator
 */
export function setStatus(status, text) {
    const dot = document.querySelector('.status-dot');
    const textEl = document.getElementById('status-text');

    if (dot) {
        dot.classList.remove('active', 'error');
        if (status === 'active') dot.classList.add('active');
        if (status === 'error') dot.classList.add('error');
    }

    if (textEl) {
        textEl.textContent = text;
    }
}
