// ============================================
// SECURITY SITUATION MONITOR - THREAT MAP
// D3.js global map with threat visualization
// ============================================

let svg = null;
let projection = null;
let path = null;
let zoom = null;
let g = null;

// Country coordinates for threat markers
const COUNTRY_COORDS = {
    'US': [-95.7, 37.1],
    'United States': [-95.7, 37.1],
    'GB': [-1.2, 52.2],
    'United Kingdom': [-1.2, 52.2],
    'DE': [10.4, 51.2],
    'Germany': [10.4, 51.2],
    'FR': [2.2, 46.2],
    'France': [2.2, 46.2],
    'CA': [-106.3, 56.1],
    'Canada': [-106.3, 56.1],
    'AU': [133.8, -25.3],
    'Australia': [133.8, -25.3],
    'JP': [138.3, 36.2],
    'Japan': [138.3, 36.2],
    'CN': [104.2, 35.9],
    'China': [104.2, 35.9],
    'RU': [105.3, 61.5],
    'Russia': [105.3, 61.5],
    'BR': [-51.9, -14.2],
    'Brazil': [-51.9, -14.2],
    'IN': [78.9, 20.6],
    'India': [78.9, 20.6],
    'IT': [12.6, 41.9],
    'Italy': [12.6, 41.9],
    'ES': [-3.7, 40.5],
    'Spain': [-3.7, 40.5],
    'NL': [5.3, 52.1],
    'Netherlands': [5.3, 52.1],
    'SE': [18.6, 60.1],
    'Sweden': [18.6, 60.1],
    'CH': [8.2, 46.8],
    'Switzerland': [8.2, 46.8],
    'KR': [127.8, 35.9],
    'South Korea': [127.8, 35.9],
    'MX': [-102.6, 23.6],
    'Mexico': [-102.6, 23.6],
    'SG': [103.8, 1.4],
    'Singapore': [103.8, 1.4],
    'AE': [53.8, 23.4],
    'UAE': [53.8, 23.4],
    'PL': [19.1, 51.9],
    'Poland': [19.1, 51.9],
    'BE': [4.5, 50.5],
    'Belgium': [4.5, 50.5],
    'AT': [14.6, 47.5],
    'Austria': [14.6, 47.5],
    'NO': [8.5, 60.5],
    'Norway': [8.5, 60.5],
    'DK': [9.5, 56.3],
    'Denmark': [9.5, 56.3],
    'FI': [25.7, 61.9],
    'Finland': [25.7, 61.9],
    'IE': [-8.2, 53.4],
    'Ireland': [-8.2, 53.4],
    'PT': [-8.2, 39.4],
    'Portugal': [-8.2, 39.4],
    'CZ': [15.5, 49.8],
    'Czech Republic': [15.5, 49.8],
    'IL': [34.9, 31.0],
    'Israel': [34.9, 31.0],
    'ZA': [22.9, -30.6],
    'South Africa': [22.9, -30.6],
    'AR': [-63.6, -38.4],
    'Argentina': [-63.6, -38.4],
    'CL': [-71.5, -35.7],
    'Chile': [-71.5, -35.7],
    'CO': [-74.3, 4.6],
    'Colombia': [-74.3, 4.6],
    'MY': [101.9, 4.2],
    'Malaysia': [101.9, 4.2],
    'TH': [100.5, 15.9],
    'Thailand': [100.5, 15.9],
    'ID': [113.9, -0.8],
    'Indonesia': [113.9, -0.8],
    'PH': [121.8, 12.9],
    'Philippines': [121.8, 12.9],
    'VN': [108.3, 14.1],
    'Vietnam': [108.3, 14.1],
    'TW': [121.0, 23.7],
    'Taiwan': [121.0, 23.7],
    'HK': [114.2, 22.4],
    'Hong Kong': [114.2, 22.4],
    'NZ': [174.9, -40.9],
    'New Zealand': [174.9, -40.9]
};

/**
 * Initialize the threat map
 */
export async function initMap(containerId = 'threat-map') {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Clear existing content
    container.textContent = '';

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 350;

    // Create SVG
    svg = d3.select(`#${containerId}`)
        .append('svg')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet');

    // Create projection
    projection = d3.geoNaturalEarth1()
        .scale(width / 5.5)
        .translate([width / 2, height / 2]);

    path = d3.geoPath().projection(projection);

    // Create zoom behavior
    zoom = d3.zoom()
        .scaleExtent([1, 8])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });

    svg.call(zoom);

    // Create main group for map elements
    g = svg.append('g');

    // Add ocean background
    g.append('rect')
        .attr('class', 'ocean')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', '#0a0a0a');

    // Load and render world map
    try {
        const response = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
        const world = await response.json();

        const countries = topojson.feature(world, world.objects.countries);

        g.selectAll('.country')
            .data(countries.features)
            .enter()
            .append('path')
            .attr('class', 'country')
            .attr('d', path)
            .attr('fill', '#1a1a1a')
            .attr('stroke', '#2a2a2a')
            .attr('stroke-width', 0.5);

    } catch (error) {
        console.error('Error loading map data:', error);
    }
}

/**
 * Update threat markers on the map
 */
export function updateThreatMarkers(ransomwareVictims, iocs) {
    if (!g) return;

    // Remove existing markers
    g.selectAll('.threat-marker').remove();
    g.selectAll('.threat-marker-pulse').remove();

    // Count threats by country
    const countryCounts = {};

    if (ransomwareVictims) {
        ransomwareVictims.forEach(victim => {
            const country = victim.country;
            if (country && COUNTRY_COORDS[country]) {
                countryCounts[country] = (countryCounts[country] || 0) + 1;
            }
        });
    }

    // Add threat markers
    Object.entries(countryCounts).forEach(([country, count]) => {
        const coords = COUNTRY_COORDS[country];
        if (!coords) return;

        const [x, y] = projection(coords);
        if (isNaN(x) || isNaN(y)) return;

        const radius = Math.min(5 + count * 2, 15);

        // Pulse effect
        g.append('circle')
            .attr('class', 'threat-marker-pulse')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', radius)
            .attr('fill', 'none')
            .attr('stroke', '#ff4444')
            .attr('stroke-width', 2)
            .attr('opacity', 0.5)
            .style('animation', 'pulse 2s infinite');

        // Main marker
        g.append('circle')
            .attr('class', 'threat-marker')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', radius)
            .attr('fill', '#ff4444')
            .attr('fill-opacity', 0.6)
            .attr('stroke', '#ff4444')
            .attr('stroke-width', 1)
            .append('title')
            .text(`${country}: ${count} threat(s)`);
    });

    // Highlight countries with threats
    g.selectAll('.country')
        .attr('fill', function() {
            return '#1a1a1a';
        });
}

/**
 * Reset map zoom
 */
export function resetMapZoom() {
    if (svg && zoom) {
        svg.transition()
            .duration(750)
            .call(zoom.transform, d3.zoomIdentity);
    }
}

// Expose reset function globally
window.resetMapZoom = resetMapZoom;
