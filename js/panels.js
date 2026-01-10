// ============================================
// SECURITY SITUATION MONITOR - PANEL MANAGEMENT
// Panel visibility, settings, and UI controls
// ============================================

import { PANELS } from './constants.js';

const STORAGE_KEY = 'security-monitor-panels';

/**
 * Initialize panel settings from storage
 */
export function initPanels() {
    const stored = localStorage.getItem(STORAGE_KEY);
    let panelSettings = {};

    if (stored) {
        try {
            panelSettings = JSON.parse(stored);
        } catch {
            panelSettings = {};
        }
    }

    // Apply stored settings or defaults
    PANELS.forEach(panel => {
        const isEnabled = panelSettings[panel.id] !== undefined
            ? panelSettings[panel.id]
            : panel.enabled;

        const panelEl = document.getElementById(`panel-${panel.id}`);
        if (panelEl) {
            panelEl.classList.toggle('hidden', !isEnabled);
        }
    });

    // Build settings modal content
    buildPanelToggles();
}

/**
 * Build panel toggle checkboxes in settings modal
 */
function buildPanelToggles() {
    const container = document.getElementById('panel-toggles');
    if (!container) return;

    container.textContent = '';

    const stored = localStorage.getItem(STORAGE_KEY);
    let panelSettings = {};

    if (stored) {
        try {
            panelSettings = JSON.parse(stored);
        } catch {
            panelSettings = {};
        }
    }

    PANELS.forEach(panel => {
        const isEnabled = panelSettings[panel.id] !== undefined
            ? panelSettings[panel.id]
            : panel.enabled;

        const toggle = document.createElement('div');
        toggle.className = 'panel-toggle';

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `toggle-${panel.id}`;
        checkbox.checked = isEnabled;
        checkbox.addEventListener('change', () => togglePanel(panel.id, checkbox.checked));

        const label = document.createElement('label');
        label.htmlFor = `toggle-${panel.id}`;
        label.textContent = panel.name;

        toggle.appendChild(checkbox);
        toggle.appendChild(label);
        container.appendChild(toggle);
    });
}

/**
 * Toggle panel visibility
 */
export function togglePanel(panelId, enabled) {
    const panelEl = document.getElementById(`panel-${panelId}`);
    if (panelEl) {
        panelEl.classList.toggle('hidden', !enabled);
    }

    // Save to storage
    const stored = localStorage.getItem(STORAGE_KEY);
    let panelSettings = {};

    if (stored) {
        try {
            panelSettings = JSON.parse(stored);
        } catch {
            panelSettings = {};
        }
    }

    panelSettings[panelId] = enabled;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(panelSettings));
}

/**
 * Check if panel is enabled
 */
export function isPanelEnabled(panelId) {
    const panelEl = document.getElementById(`panel-${panelId}`);
    return panelEl && !panelEl.classList.contains('hidden');
}

/**
 * Open settings modal
 */
export function openSettings() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        modal.classList.add('open');
    }
}

/**
 * Close settings modal
 */
export function closeSettings() {
    const modal = document.getElementById('settings-modal');
    if (modal) {
        modal.classList.remove('open');
    }
}

/**
 * Initialize mobile menu
 */
export function initMobileMenu() {
    const hamburger = document.getElementById('hamburger-btn');
    const mobileNav = document.getElementById('mobile-nav');

    if (hamburger && mobileNav) {
        hamburger.addEventListener('click', () => {
            mobileNav.classList.toggle('open');
        });

        // Close on outside click
        document.addEventListener('click', (e) => {
            if (!hamburger.contains(e.target) && !mobileNav.contains(e.target)) {
                mobileNav.classList.remove('open');
            }
        });
    }
}

/**
 * Close mobile menu
 */
export function closeMobileMenu() {
    const mobileNav = document.getElementById('mobile-nav');
    if (mobileNav) {
        mobileNav.classList.remove('open');
    }
}

// Expose functions globally for onclick handlers
window.openSettings = openSettings;
window.closeSettings = closeSettings;
window.closeMobileMenu = closeMobileMenu;
