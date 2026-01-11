// ============================================
// SECURITY SITUATION MONITOR - CONSTANTS
// API endpoints and configuration
// ============================================

// API Endpoints
export const API_ENDPOINTS = {
    // NVD CVE API 2.0 (No auth required, rate limited)
    NVD_CVE: 'https://services.nvd.nist.gov/rest/json/cves/2.0',

    // CISA Known Exploited Vulnerabilities
    CISA_KEV: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',

    // ThreatFox IOC API (abuse.ch)
    THREATFOX_API: 'https://threatfox-api.abuse.ch/api/v1/',

    // Ransomware.live API
    RANSOMWARE_VICTIMS: 'https://api.ransomware.live/v2/recentvictims',
    RANSOMWARE_GROUPS: 'https://api.ransomware.live/v2/groups',

    // GDELT Project API for geopolitical conflict data
    GDELT_API: 'https://api.gdeltproject.org/api/v2/doc/doc',

    // ACLED (Armed Conflict Location & Event Data Project)
    ACLED_API: 'https://api.acleddata.com/acled/read',

    // USGS Earthquake API
    USGS_EARTHQUAKES: 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson',

    // NewsAPI for live intelligence feeds
    NEWSAPI_GDELT: 'https://api.gdeltproject.org/api/v2/doc/doc',

    // CORS Proxy for APIs that don't support CORS
    CORS_PROXY: 'https://api.allorigins.win/raw?url='
};

// Refresh intervals (in milliseconds)
export const REFRESH_INTERVALS = {
    CVE: 5 * 60 * 1000,        // 5 minutes
    KEV: 30 * 60 * 1000,       // 30 minutes
    THREAT_INTEL: 5 * 60 * 1000, // 5 minutes
    RANSOMWARE: 5 * 60 * 1000,   // 5 minutes
    AUTO_REFRESH: 5 * 60 * 1000  // 5 minutes for full refresh
};

// CVSS Severity thresholds
export const CVSS_SEVERITY = {
    CRITICAL: { min: 9.0, max: 10.0, label: 'critical', color: '#ff4444' },
    HIGH: { min: 7.0, max: 8.9, label: 'high', color: '#ff8844' },
    MEDIUM: { min: 4.0, max: 6.9, label: 'medium', color: '#ffaa00' },
    LOW: { min: 0.1, max: 3.9, label: 'low', color: '#44aa44' },
    NONE: { min: 0, max: 0, label: 'none', color: '#888888' }
};

// Panel configuration
export const PANELS = [
    { id: 'cve', name: 'CVE Threat Feed', enabled: true },
    { id: 'kev', name: 'CISA KEV', enabled: true },
    { id: 'threat-intel', name: 'Threat Intelligence', enabled: true },
    { id: 'malware', name: 'Active Malware', enabled: true },
    { id: 'ransomware', name: 'Ransomware Activity', enabled: true },
    { id: 'groups', name: 'Threat Actors', enabled: true },
    { id: 'correlation', name: 'Correlation Engine', enabled: true },
    { id: 'map', name: 'Global Threat Map', enabled: true },
    { id: 'stats', name: 'Threat Metrics', enabled: true },
    { id: 'timeline', name: 'Attack Timeline', enabled: true }
];

// Malware families to track
export const TRACKED_MALWARE = [
    'Cobalt Strike',
    'AsyncRAT',
    'AgentTesla',
    'RedLine',
    'Raccoon',
    'Emotet',
    'QakBot',
    'IcedID',
    'BumbleBee',
    'SystemBC'
];

// Country code to name mapping (partial)
export const COUNTRY_CODES = {
    'US': 'United States',
    'GB': 'United Kingdom',
    'DE': 'Germany',
    'FR': 'France',
    'CA': 'Canada',
    'AU': 'Australia',
    'JP': 'Japan',
    'CN': 'China',
    'RU': 'Russia',
    'BR': 'Brazil',
    'IN': 'India',
    'IT': 'Italy',
    'ES': 'Spain',
    'NL': 'Netherlands',
    'SE': 'Sweden',
    'CH': 'Switzerland',
    'KR': 'South Korea',
    'MX': 'Mexico',
    'SG': 'Singapore',
    'AE': 'UAE',
    'IR': 'Iran',
    'VE': 'Venezuela',
    'UA': 'Ukraine',
    'SY': 'Syria',
    'IQ': 'Iraq',
    'AF': 'Afghanistan',
    'YE': 'Yemen',
    'LY': 'Libya',
    'SD': 'Sudan',
    'SO': 'Somalia',
    'KP': 'North Korea',
    'PK': 'Pakistan',
    'NG': 'Nigeria',
    'CD': 'Congo (DRC)',
    'ET': 'Ethiopia',
    'MM': 'Myanmar',
    'TW': 'Taiwan',
    'IL': 'Israel',
    'PS': 'Palestine',
    'LB': 'Lebanon',
    'JO': 'Jordan',
    'SA': 'Saudi Arabia',
    'EG': 'Egypt',
    'TN': 'Tunisia',
    'MA': 'Morocco',
    'DZ': 'Algeria'
};

// Geopolitical conflict queries for GDELT
export const CONFLICT_QUERIES = [
    'russia ukraine war',
    'venezuela political crisis',
    'iran nuclear sanctions',
    'north korea missile',
    'china taiwan military',
    'israel palestine conflict',
    'syria civil war',
    'yemen conflict',
    'myanmar coup',
    'sudan conflict',
    'ethiopia tigray',
    'libya conflict',
    'afghanistan taliban',
    'kashmir dispute',
    'south china sea'
];

// Sector mapping
export const SECTORS = {
    'healthcare': 'Healthcare',
    'finance': 'Finance',
    'government': 'Government',
    'education': 'Education',
    'manufacturing': 'Manufacturing',
    'retail': 'Retail',
    'technology': 'Technology',
    'energy': 'Energy',
    'transportation': 'Transportation',
    'legal': 'Legal'
};
