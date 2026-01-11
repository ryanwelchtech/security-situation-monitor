// ============================================
// SECURITY SITUATION MONITOR - THREAT MAP
// D3.js global map with threat visualization
// ============================================

let svg = null;
let projection = null;
let path = null;
let zoom = null;
let g = null;

// Country coordinates for threat and conflict markers
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
    'New Zealand': [174.9, -40.9],
    'IR': [53.7, 32.4],
    'Iran': [53.7, 32.4],
    'VE': [-66.6, 6.4],
    'Venezuela': [-66.6, 6.4],
    'UA': [31.2, 49.0],
    'Ukraine': [31.2, 49.0],
    'SY': [38.9, 34.8],
    'Syria': [38.9, 34.8],
    'IQ': [43.7, 33.2],
    'Iraq': [43.7, 33.2],
    'AF': [67.7, 33.9],
    'Afghanistan': [67.7, 33.9],
    'YE': [48.5, 15.6],
    'Yemen': [48.5, 15.6],
    'LY': [17.2, 26.3],
    'Libya': [17.2, 26.3],
    'SD': [30.2, 12.9],
    'Sudan': [30.2, 12.9],
    'SO': [46.2, 5.2],
    'Somalia': [46.2, 5.2],
    'KP': [127.5, 40.3],
    'North Korea': [127.5, 40.3],
    'PK': [69.3, 30.4],
    'Pakistan': [69.3, 30.4],
    'NG': [8.7, 9.1],
    'Nigeria': [8.7, 9.1],
    'CD': [21.8, -4.0],
    'Congo (DRC)': [21.8, -4.0],
    'ET': [40.5, 9.1],
    'Ethiopia': [40.5, 9.1],
    'MM': [95.9, 21.9],
    'Myanmar': [95.9, 21.9],
    'PS': [35.2, 31.9],
    'Palestine': [35.2, 31.9],
    'LB': [35.9, 33.9],
    'Lebanon': [35.9, 33.9],
    'JO': [36.2, 30.6],
    'Jordan': [36.2, 30.6],
    'SA': [45.1, 23.9],
    'Saudi Arabia': [45.1, 23.9],
    'EG': [30.8, 26.8],
    'Egypt': [30.8, 26.8],
    'TN': [9.5, 33.9],
    'Tunisia': [9.5, 33.9],
    'MA': [-7.1, 31.8],
    'Morocco': [-7.1, 31.8],
    'DZ': [1.7, 28.0],
    'Algeria': [1.7, 28.0]
};

/**
 * Initialize the threat map
 */
export async function initMap(containerId = 'threat-map') {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Clear existing content
    container.textContent = '';

    const width = container.clientWidth || 1200;
    const height = container.clientHeight || 500;

    // Create SVG
    svg = d3.select(`#${containerId}`)
        .append('svg')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet');

    // Create projection with better scale for larger map
    projection = d3.geoNaturalEarth1()
        .scale(width / 6)
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

    // Add ocean background with blue gradient
    const oceanGradient = svg.append('defs')
        .append('radialGradient')
        .attr('id', 'ocean-gradient')
        .attr('cx', '50%')
        .attr('cy', '50%');

    oceanGradient.append('stop')
        .attr('offset', '0%')
        .attr('stop-color', '#1e4a7a');

    oceanGradient.append('stop')
        .attr('offset', '100%')
        .attr('stop-color', '#0f2844');

    g.append('rect')
        .attr('class', 'ocean')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', 'url(#ocean-gradient)');

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
            .attr('fill', '#2d3f5a')
            .attr('stroke', '#4a5f7a')
            .attr('stroke-width', 0.5);

    } catch (error) {
        console.error('Error loading map data:', error);
    }
}

/**
 * Update conflict, threat, and earthquake markers on the map
 */
export function updateThreatMarkers(conflictData, ransomwareVictims, earthquakes) {
    if (!g) return;

    // Remove existing markers
    g.selectAll('.conflict-marker').remove();
    g.selectAll('.conflict-marker-pulse').remove();
    g.selectAll('.threat-marker').remove();
    g.selectAll('.threat-marker-pulse').remove();
    g.selectAll('.earthquake-marker').remove();
    g.selectAll('.earthquake-marker-pulse').remove();

    // Track all markers to show
    const markers = [];

    // Add conflict markers (primary focus)
    if (conflictData && conflictData.locationCounts) {
        Object.entries(conflictData.locationCounts).forEach(([location, count]) => {
            const coords = COUNTRY_COORDS[location];
            if (coords) {
                markers.push({
                    type: 'conflict',
                    location: location,
                    count: count,
                    coords: coords,
                    severity: count >= 5 ? 'critical' : count >= 3 ? 'high' : 'medium'
                });
            }
        });
    }

    // Add ransomware markers (secondary)
    const ransomwareCounts = {};
    if (ransomwareVictims) {
        ransomwareVictims.forEach(victim => {
            const country = victim.country;
            if (country && COUNTRY_COORDS[country]) {
                ransomwareCounts[country] = (ransomwareCounts[country] || 0) + 1;
            }
        });

        Object.entries(ransomwareCounts).forEach(([country, count]) => {
            const coords = COUNTRY_COORDS[country];
            if (coords) {
                // Don't add if there's already a conflict marker for this location
                const hasConflict = markers.some(m => m.location === country);
                if (!hasConflict) {
                    markers.push({
                        type: 'cyber',
                        location: country,
                        count: count,
                        coords: coords,
                        severity: 'medium'
                    });
                }
            }
        });
    }

    // Add earthquake markers
    if (earthquakes && earthquakes.length > 0) {
        earthquakes.forEach(eq => {
            if (eq.coords && eq.coords.length >= 2) {
                const [x, y] = projection(eq.coords);
                if (!isNaN(x) && !isNaN(y)) {
                    const radius = Math.min(4 + eq.magnitude * 2, 16);
                    const color = '#ff8833'; // Orange for earthquakes

                    // Pulse effect for larger earthquakes
                    if (eq.magnitude >= 4.0) {
                        g.append('circle')
                            .attr('class', 'earthquake-marker-pulse')
                            .attr('cx', x)
                            .attr('cy', y)
                            .attr('r', radius)
                            .attr('fill', 'none')
                            .attr('stroke', color)
                            .attr('stroke-width', 2)
                            .attr('opacity', 0.6)
                            .style('animation', 'pulse 2s infinite');
                    }

                    // Main earthquake marker
                    const eqMarker = g.append('circle')
                        .attr('class', 'earthquake-marker')
                        .attr('cx', x)
                        .attr('cy', y)
                        .attr('r', radius)
                        .attr('fill', color)
                        .attr('fill-opacity', 0.6)
                        .attr('stroke', '#ffaa44')
                        .attr('stroke-width', 1.5)
                        .style('cursor', 'pointer');

                    // Tooltip
                    eqMarker.append('title')
                        .text(`EARTHQUAKE\nMagnitude: ${eq.magnitude}\nLocation: ${eq.location}\nDepth: ${eq.depth.toFixed(1)} km`);

                    // Hover effect
                    eqMarker
                        .on('mouseover', function() {
                            d3.select(this)
                                .transition()
                                .duration(200)
                                .attr('r', radius * 1.3)
                                .attr('fill-opacity', 0.9);
                        })
                        .on('mouseout', function() {
                            d3.select(this)
                                .transition()
                                .duration(200)
                                .attr('r', radius)
                                .attr('fill-opacity', 0.6);
                        })
                        .on('click', function() {
                            if (eq.url) {
                                window.open(eq.url, '_blank');
                            }
                        });
                }
            }
        });
    }

    // Render all markers
    markers.forEach(marker => {
        const [x, y] = projection(marker.coords);
        if (isNaN(x) || isNaN(y)) return;

        const radius = Math.min(8 + marker.count * 1.5, 20);
        const color = marker.type === 'conflict' ? getConflictColor(marker.severity) : '#ff8844';
        const markerClass = marker.type === 'conflict' ? 'conflict-marker' : 'threat-marker';
        const pulseClass = marker.type === 'conflict' ? 'conflict-marker-pulse' : 'threat-marker-pulse';

        // Pulse effect for critical conflicts
        if (marker.severity === 'critical' || marker.count >= 3) {
            g.append('circle')
                .attr('class', pulseClass)
                .attr('cx', x)
                .attr('cy', y)
                .attr('r', radius)
                .attr('fill', 'none')
                .attr('stroke', color)
                .attr('stroke-width', 2)
                .attr('opacity', 0.5)
                .style('animation', 'pulse 2s infinite');
        }

        // Main marker
        const markerElement = g.append('circle')
            .attr('class', markerClass)
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', radius)
            .attr('fill', color)
            .attr('fill-opacity', 0.7)
            .attr('stroke', color)
            .attr('stroke-width', 1.5)
            .style('cursor', 'pointer');

        // Tooltip
        markerElement.append('title')
            .text(`${marker.location}\n${marker.type === 'conflict' ? 'Geopolitical Conflict' : 'Cyber Threat'}\nIncidents: ${marker.count}`);

        // Hover effect
        markerElement
            .on('mouseover', function() {
                d3.select(this)
                    .transition()
                    .duration(200)
                    .attr('r', radius * 1.3)
                    .attr('fill-opacity', 0.9);
            })
            .on('mouseout', function() {
                d3.select(this)
                    .transition()
                    .duration(200)
                    .attr('r', radius)
                    .attr('fill-opacity', 0.7);
            });
    });
}

/**
 * Get color based on conflict severity
 */
function getConflictColor(severity) {
    const colors = {
        'critical': '#ff4444',  // Red
        'high': '#ff8844',      // Orange
        'medium': '#ffaa00',    // Yellow
        'low': '#44aa44'        // Green
    };
    return colors[severity] || colors.medium;
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
