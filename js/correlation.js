// ============================================
// SECURITY SITUATION MONITOR - CORRELATION ENGINE
// Cross-reference CVEs, IOCs, and ransomware data
// ============================================

/**
 * Analyze correlations between different threat data sources
 */
export function analyzeCorrelations(cves, kevs, threatData, ransomwareVictims) {
    const correlations = [];

    // 1. Find CVEs that are being actively exploited (in KEV)
    if (cves && kevs) {
        const kevIds = new Set(kevs.map(k => k.id));
        const exploitedCVEs = cves.filter(cve => kevIds.has(cve.id));

        exploitedCVEs.forEach(cve => {
            correlations.push({
                type: 'Active Exploitation',
                description: `${cve.id} is in CISA KEV - actively exploited in the wild`,
                cveId: cve.id,
                severity: 'critical',
                timestamp: new Date().toISOString()
            });
        });
    }

    // 2. Find malware families associated with ransomware groups
    if (threatData && threatData.malwareFamilies && ransomwareVictims) {
        const ransomwareGroups = new Set(ransomwareVictims.map(v => v.group.toLowerCase()));

        threatData.malwareFamilies.forEach(family => {
            const familyLower = family.name.toLowerCase();

            // Check for known ransomware-associated malware
            const ransomwareRelated = [
                'cobalt strike', 'systembc', 'qakbot', 'emotet', 'icedid',
                'bumblebee', 'pikabot', 'darkgate', 'asyncrat', 'remcos'
            ];

            if (ransomwareRelated.some(r => familyLower.includes(r))) {
                correlations.push({
                    type: 'Ransomware Precursor',
                    description: `${family.name} detected - commonly used in ransomware attacks`,
                    malware: family.name,
                    iocCount: family.count,
                    severity: 'high',
                    timestamp: new Date().toISOString()
                });
            }
        });
    }

    // 3. Identify critical CVEs with high IOC activity
    if (cves && threatData && threatData.iocs) {
        const criticalCVEs = cves.filter(cve => cve.severity === 'critical');
        const iocMalwareSet = new Set(threatData.iocs.map(i => i.malware?.toLowerCase()).filter(Boolean));

        criticalCVEs.slice(0, 5).forEach(cve => {
            // Look for exploitation patterns in description
            const desc = cve.description.toLowerCase();
            const exploitIndicators = ['remote code execution', 'rce', 'arbitrary code', 'command injection'];

            if (exploitIndicators.some(indicator => desc.includes(indicator))) {
                correlations.push({
                    type: 'RCE Vulnerability',
                    description: `${cve.id} (CVSS ${cve.score}) enables remote code execution`,
                    cveId: cve.id,
                    severity: 'critical',
                    timestamp: cve.published
                });
            }
        });
    }

    // 4. Sector-based threat correlation
    if (ransomwareVictims && ransomwareVictims.length > 0) {
        const sectorCounts = {};
        ransomwareVictims.forEach(victim => {
            const sector = victim.sector || 'Unknown';
            sectorCounts[sector] = (sectorCounts[sector] || 0) + 1;
        });

        // Find most targeted sectors
        const topSectors = Object.entries(sectorCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        topSectors.forEach(([sector, count]) => {
            if (count >= 2) {
                correlations.push({
                    type: 'Sector Targeting',
                    description: `${sector} sector seeing elevated attacks (${count} victims)`,
                    sector: sector,
                    victimCount: count,
                    severity: 'medium',
                    timestamp: new Date().toISOString()
                });
            }
        });
    }

    // 5. Geographic threat concentration
    if (ransomwareVictims && ransomwareVictims.length > 0) {
        const countryCounts = {};
        ransomwareVictims.forEach(victim => {
            const country = victim.country || 'Unknown';
            countryCounts[country] = (countryCounts[country] || 0) + 1;
        });

        const topCountries = Object.entries(countryCounts)
            .filter(([country]) => country !== 'Unknown')
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        topCountries.forEach(([country, count]) => {
            if (count >= 3) {
                correlations.push({
                    type: 'Geographic Concentration',
                    description: `${country} experiencing elevated ransomware activity (${count} victims)`,
                    country: country,
                    victimCount: count,
                    severity: 'medium',
                    timestamp: new Date().toISOString()
                });
            }
        });
    }

    // 6. Active threat group analysis
    if (ransomwareVictims && ransomwareVictims.length > 0) {
        const groupCounts = {};
        ransomwareVictims.forEach(victim => {
            groupCounts[victim.group] = (groupCounts[victim.group] || 0) + 1;
        });

        const activeGroups = Object.entries(groupCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        activeGroups.forEach(([group, count]) => {
            if (count >= 2) {
                correlations.push({
                    type: 'Active Threat Actor',
                    description: `${group} showing high activity (${count} recent victims)`,
                    group: group,
                    victimCount: count,
                    severity: 'high',
                    timestamp: new Date().toISOString()
                });
            }
        });
    }

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    correlations.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return correlations;
}

/**
 * Build unified timeline from all data sources
 */
export function buildTimeline(cves, kevs, threatData, ransomwareVictims) {
    const events = [];

    // Add CVEs
    if (cves) {
        cves.slice(0, 10).forEach(cve => {
            events.push({
                type: 'cve',
                timestamp: cve.published,
                title: cve.id,
                description: `CVSS ${cve.score} - ${cve.severity.toUpperCase()}`
            });
        });
    }

    // Add KEVs
    if (kevs) {
        kevs.slice(0, 5).forEach(kev => {
            events.push({
                type: 'kev',
                timestamp: kev.dateAdded,
                title: `KEV: ${kev.id}`,
                description: `${kev.vendor} ${kev.product} - Active exploitation`
            });
        });
    }

    // Add IOCs
    if (threatData && threatData.iocs) {
        threatData.iocs.slice(0, 10).forEach(ioc => {
            events.push({
                type: 'ioc',
                timestamp: ioc.firstSeen,
                title: `IOC: ${ioc.malware || 'Unknown'}`,
                description: `${ioc.type} - ${ioc.value.substring(0, 30)}...`
            });
        });
    }

    // Add ransomware victims
    if (ransomwareVictims) {
        ransomwareVictims.slice(0, 10).forEach(victim => {
            events.push({
                type: 'ransomware',
                timestamp: victim.discovered,
                title: `Victim: ${victim.name}`,
                description: `${victim.group} - ${victim.country}`
            });
        });
    }

    // Sort by timestamp (most recent first)
    events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    return events.slice(0, 20);
}

/**
 * Calculate threat statistics
 */
export function calculateStats(cves, kevs, threatData, ransomwareVictims) {
    return {
        criticalCVEs: cves ? cves.filter(c => c.severity === 'critical').length : 0,
        kevCount: kevs ? kevs.length : 0,
        iocCount: threatData && threatData.iocs ? threatData.iocs.length : 0,
        victimCount: ransomwareVictims ? ransomwareVictims.length : 0
    };
}
