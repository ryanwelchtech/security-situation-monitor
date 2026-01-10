// ============================================
// SECURITY SITUATION MONITOR - MAIN
// Application entry point and orchestration
// ============================================

import { REFRESH_INTERVALS } from './constants.js';
import {
    fetchRecentCVEs,
    fetchCISAKEV,
    fetchThreatFoxIOCs,
    fetchRansomwareVictims,
    fetchRansomwareGroups,
    fetchConflictData,
    clearCache
} from './data.js';
import {
    renderCVEs,
    renderKEVs,
    renderThreatIntel,
    renderMalwareFamilies,
    renderRansomwareVictims,
    renderRansomwareGroups,
    renderCorrelations,
    renderStats,
    renderTimeline,
    updateLastRefresh,
    setStatus
} from './renderers.js';
import { analyzeCorrelations, buildTimeline, calculateStats } from './correlation.js';
import { initMap, updateThreatMarkers, resetMapZoom } from './map.js';
import { initPanels, isPanelEnabled, initMobileMenu } from './panels.js';

// State
let autoRefreshInterval = null;
let autoRefreshEnabled = true;
let allCVEs = [];
let allThreatData = { iocs: [], malwareFamilies: [] };
let allConflictData = { conflicts: [], locationCounts: {} };

/**
 * Initialize the application
 */
async function init() {
    console.log('Security Situation Monitor initializing...');

    // Initialize UI components
    initPanels();
    initMobileMenu();

    // Initialize map
    await initMap();

    // Initial data fetch
    await refreshAll();

    // Start auto-refresh
    startAutoRefresh();

    console.log('Security Situation Monitor ready');
}

/**
 * Refresh all data
 */
async function refreshAll() {
    setStatus('loading', 'FETCHING DATA...');

    try {
        // Fetch all data in parallel
        const [conflicts, cves, kevs, threatData, ransomwareVictims, ransomwareGroups] = await Promise.allSettled([
            fetchConflictData(),
            fetchRecentCVEs(),
            fetchCISAKEV(),
            fetchThreatFoxIOCs(),
            fetchRansomwareVictims(),
            fetchRansomwareGroups()
        ]);

        // Extract values, handling failures gracefully
        const conflictData = conflicts.status === 'fulfilled' ? conflicts.value : { conflicts: [], locationCounts: {} };
        const cveData = cves.status === 'fulfilled' ? cves.value : [];
        const kevData = kevs.status === 'fulfilled' ? kevs.value : [];
        const threatIntelData = threatData.status === 'fulfilled' ? threatData.value : { iocs: [], malwareFamilies: [] };
        const victimsData = ransomwareVictims.status === 'fulfilled' ? ransomwareVictims.value : [];
        const groupsData = ransomwareGroups.status === 'fulfilled' ? ransomwareGroups.value : [];

        // Store for filtering
        allCVEs = cveData;
        allThreatData = threatIntelData;
        allConflictData = conflictData;

        // Render panels
        if (isPanelEnabled('cve')) {
            renderCVEs(cveData);
        }

        if (isPanelEnabled('kev')) {
            renderKEVs(kevData);
        }

        if (isPanelEnabled('threat-intel')) {
            renderThreatIntel(threatIntelData);
        }

        if (isPanelEnabled('malware')) {
            renderMalwareFamilies(threatIntelData);
        }

        if (isPanelEnabled('ransomware')) {
            renderRansomwareVictims(victimsData);
        }

        if (isPanelEnabled('groups')) {
            renderRansomwareGroups(groupsData);
        }

        // Run correlation analysis
        if (isPanelEnabled('correlation')) {
            const correlations = analyzeCorrelations(cveData, kevData, threatIntelData, victimsData);
            renderCorrelations(correlations);
        }

        // Update map with conflict data as primary focus
        if (isPanelEnabled('map')) {
            updateThreatMarkers(conflictData, victimsData);

            // Update conflict count badge
            const conflictCount = conflictData.conflicts ? conflictData.conflicts.length : 0;
            const countBadge = document.getElementById('conflict-count');
            if (countBadge) {
                countBadge.textContent = conflictCount;
            }
        }

        // Update stats
        if (isPanelEnabled('stats')) {
            const stats = calculateStats(cveData, kevData, threatIntelData, victimsData);
            renderStats(stats);
        }

        // Build and render timeline
        if (isPanelEnabled('timeline')) {
            const timeline = buildTimeline(cveData, kevData, threatIntelData, victimsData);
            renderTimeline(timeline);
        }

        // Update UI
        updateLastRefresh();
        setStatus('active', 'MONITORING');

    } catch (error) {
        console.error('Error refreshing data:', error);
        setStatus('error', 'ERROR');
    }
}

/**
 * Filter CVEs by severity
 */
function filterCVEs() {
    const filter = document.getElementById('cve-severity-filter');
    if (!filter) return;

    const severity = filter.value;

    if (severity === 'all') {
        renderCVEs(allCVEs);
    } else {
        const filtered = allCVEs.filter(cve => cve.severity === severity);
        renderCVEs(filtered);
    }
}

/**
 * Filter threats by type
 */
function filterThreats() {
    const filter = document.getElementById('threat-type-filter');
    if (!filter) return;

    const type = filter.value;

    if (type === 'all') {
        renderThreatIntel(allThreatData);
    } else {
        const filtered = {
            ...allThreatData,
            iocs: allThreatData.iocs.filter(ioc => ioc.type === type)
        };
        renderThreatIntel(filtered);
    }
}

/**
 * Start auto-refresh interval
 */
function startAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }

    if (autoRefreshEnabled) {
        autoRefreshInterval = setInterval(refreshAll, REFRESH_INTERVALS.AUTO_REFRESH);
    }
}

/**
 * Toggle auto-refresh
 */
function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;

    const btn = document.getElementById('auto-refresh-btn');
    const btnMobile = document.getElementById('auto-refresh-btn-mobile');

    const text = autoRefreshEnabled ? 'Auto: ON' : 'Auto: OFF';
    const textMobile = autoRefreshEnabled ? 'Auto-Refresh: ON' : 'Auto-Refresh: OFF';

    if (btn) {
        const icon = btn.querySelector('.btn-icon');
        btn.textContent = '';
        if (icon) btn.appendChild(icon);
        btn.appendChild(document.createTextNode(` ${text}`));
    }

    if (btnMobile) {
        btnMobile.textContent = `⏱ ${textMobile}`;
    }

    if (autoRefreshEnabled) {
        startAutoRefresh();
    } else if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// Expose functions globally for onclick handlers
window.refreshAll = refreshAll;
window.filterCVEs = filterCVEs;
window.filterThreats = filterThreats;
window.toggleAutoRefresh = toggleAutoRefresh;
window.resetMapZoom = resetMapZoom;

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
