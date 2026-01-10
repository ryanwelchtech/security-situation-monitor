// ============================================
// SECURITY SITUATION MONITOR - DATA FETCHING
// Real API integrations for security data
// ============================================

import { API_ENDPOINTS, CVSS_SEVERITY } from './constants.js';

// Cache to avoid redundant API calls
const dataCache = {
    cve: { data: null, timestamp: 0 },
    kev: { data: null, timestamp: 0 },
    threatfox: { data: null, timestamp: 0 },
    ransomware: { data: null, timestamp: 0 },
    groups: { data: null, timestamp: 0 }
};

const CACHE_TTL = 4 * 60 * 1000; // 4 minutes

/**
 * Check if cache is valid
 */
function isCacheValid(key) {
    const cache = dataCache[key];
    return cache.data && (Date.now() - cache.timestamp) < CACHE_TTL;
}

/**
 * Fetch with timeout and error handling
 */
async function fetchWithTimeout(url, options = {}, timeout = 30000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(id);
        return response;
    } catch (error) {
        clearTimeout(id);
        throw error;
    }
}

/**
 * Fetch recent CVEs from NVD API 2.0
 * Returns CVEs published in the last 7 days
 */
export async function fetchRecentCVEs() {
    if (isCacheValid('cve')) {
        return dataCache.cve.data;
    }

    try {
        // Get CVEs from the last 7 days
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - 7);

        const params = new URLSearchParams({
            pubStartDate: startDate.toISOString(),
            pubEndDate: endDate.toISOString(),
            resultsPerPage: '50'
        });

        const response = await fetchWithTimeout(
            `${API_ENDPOINTS.NVD_CVE}?${params}`,
            {
                headers: {
                    'Accept': 'application/json'
                }
            },
            30000
        );

        if (!response.ok) {
            throw new Error(`NVD API error: ${response.status}`);
        }

        const data = await response.json();

        // Process and normalize CVE data
        const cves = (data.vulnerabilities || []).map(item => {
            const cve = item.cve;
            const metrics = cve.metrics?.cvssMetricV31?.[0] ||
                cve.metrics?.cvssMetricV30?.[0] ||
                cve.metrics?.cvssMetricV2?.[0];

            const baseScore = metrics?.cvssData?.baseScore || 0;
            const severity = getSeverityLevel(baseScore);

            return {
                id: cve.id,
                description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available',
                score: baseScore,
                severity: severity,
                published: cve.published,
                modified: cve.lastModified,
                vector: metrics?.cvssData?.vectorString || 'N/A',
                references: cve.references?.slice(0, 3) || []
            };
        });

        // Sort by score descending
        cves.sort((a, b) => b.score - a.score);

        dataCache.cve = { data: cves, timestamp: Date.now() };
        return cves;

    } catch (error) {
        console.error('Error fetching CVEs:', error);
        return dataCache.cve.data || [];
    }
}

/**
 * Fetch CISA Known Exploited Vulnerabilities
 */
export async function fetchCISAKEV() {
    if (isCacheValid('kev')) {
        return dataCache.kev.data;
    }

    try {
        // Use CORS proxy since CISA doesn't support CORS
        const response = await fetchWithTimeout(
            `${API_ENDPOINTS.CORS_PROXY}${encodeURIComponent(API_ENDPOINTS.CISA_KEV)}`,
            {},
            30000
        );

        if (!response.ok) {
            throw new Error(`CISA KEV error: ${response.status}`);
        }

        const data = await response.json();

        // Get the most recent KEVs (last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        const recentKEVs = (data.vulnerabilities || [])
            .filter(kev => new Date(kev.dateAdded) >= thirtyDaysAgo)
            .map(kev => ({
                id: kev.cveID,
                vendor: kev.vendorProject,
                product: kev.product,
                name: kev.vulnerabilityName,
                description: kev.shortDescription,
                dateAdded: kev.dateAdded,
                dueDate: kev.dueDate,
                knownRansomware: kev.knownRansomwareCampaignUse === 'Known'
            }))
            .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
            .slice(0, 20);

        dataCache.kev = { data: recentKEVs, timestamp: Date.now() };
        return recentKEVs;

    } catch (error) {
        console.error('Error fetching CISA KEV:', error);
        return dataCache.kev.data || [];
    }
}

/**
 * Fetch IOCs from ThreatFox API
 */
export async function fetchThreatFoxIOCs() {
    if (isCacheValid('threatfox')) {
        return dataCache.threatfox.data;
    }

    try {
        // ThreatFox API requires POST
        const response = await fetchWithTimeout(
            API_ENDPOINTS.THREATFOX_API,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    query: 'get_iocs',
                    days: 1  // Last 24 hours
                })
            },
            30000
        );

        if (!response.ok) {
            throw new Error(`ThreatFox API error: ${response.status}`);
        }

        const data = await response.json();

        if (data.query_status !== 'ok') {
            throw new Error(`ThreatFox query failed: ${data.query_status}`);
        }

        // Process IOCs
        const iocs = (data.data || []).slice(0, 100).map(ioc => ({
            id: ioc.id,
            type: ioc.ioc_type,
            value: ioc.ioc,
            threatType: ioc.threat_type,
            malware: ioc.malware_printable,
            malwareAlias: ioc.malware_alias,
            confidence: ioc.confidence_level,
            firstSeen: ioc.first_seen_utc,
            lastSeen: ioc.last_seen_utc,
            reporter: ioc.reporter,
            tags: ioc.tags || []
        }));

        // Extract malware family stats
        const malwareFamilies = {};
        iocs.forEach(ioc => {
            if (ioc.malware) {
                malwareFamilies[ioc.malware] = (malwareFamilies[ioc.malware] || 0) + 1;
            }
        });

        const result = {
            iocs,
            malwareFamilies: Object.entries(malwareFamilies)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 15)
        };

        dataCache.threatfox = { data: result, timestamp: Date.now() };
        return result;

    } catch (error) {
        console.error('Error fetching ThreatFox IOCs:', error);
        return dataCache.threatfox.data || { iocs: [], malwareFamilies: [] };
    }
}

/**
 * Fetch recent ransomware victims from Ransomware.live
 */
export async function fetchRansomwareVictims() {
    if (isCacheValid('ransomware')) {
        return dataCache.ransomware.data;
    }

    try {
        const response = await fetchWithTimeout(
            API_ENDPOINTS.RANSOMWARE_VICTIMS,
            {
                headers: {
                    'Accept': 'application/json'
                }
            },
            30000
        );

        if (!response.ok) {
            throw new Error(`Ransomware API error: ${response.status}`);
        }

        const data = await response.json();

        // Process victim data
        const victims = (data || []).slice(0, 50).map(victim => ({
            name: victim.victim || victim.post_title || 'Unknown',
            group: victim.group_name || victim.group || 'Unknown',
            discovered: victim.discovered || victim.post_date,
            country: victim.country || 'Unknown',
            sector: victim.activity || victim.sector || 'Unknown',
            website: victim.website || null,
            description: victim.description || null
        }));

        dataCache.ransomware = { data: victims, timestamp: Date.now() };
        return victims;

    } catch (error) {
        console.error('Error fetching ransomware victims:', error);
        return dataCache.ransomware.data || [];
    }
}

/**
 * Fetch ransomware groups from Ransomware.live
 */
export async function fetchRansomwareGroups() {
    if (isCacheValid('groups')) {
        return dataCache.groups.data;
    }

    try {
        const response = await fetchWithTimeout(
            API_ENDPOINTS.RANSOMWARE_GROUPS,
            {
                headers: {
                    'Accept': 'application/json'
                }
            },
            30000
        );

        if (!response.ok) {
            throw new Error(`Ransomware Groups API error: ${response.status}`);
        }

        const data = await response.json();

        // Process group data - sort by recent activity
        const groups = (data || [])
            .filter(group => group.name)
            .map(group => ({
                name: group.name,
                url: group.url || null,
                locations: group.locations || [],
                profile: group.profile || null
            }))
            .slice(0, 20);

        dataCache.groups = { data: groups, timestamp: Date.now() };
        return groups;

    } catch (error) {
        console.error('Error fetching ransomware groups:', error);
        return dataCache.groups.data || [];
    }
}

/**
 * Get severity level from CVSS score
 */
function getSeverityLevel(score) {
    if (score >= CVSS_SEVERITY.CRITICAL.min) return 'critical';
    if (score >= CVSS_SEVERITY.HIGH.min) return 'high';
    if (score >= CVSS_SEVERITY.MEDIUM.min) return 'medium';
    if (score >= CVSS_SEVERITY.LOW.min) return 'low';
    return 'none';
}

/**
 * Clear all caches
 */
export function clearCache() {
    Object.keys(dataCache).forEach(key => {
        dataCache[key] = { data: null, timestamp: 0 };
    });
}
