/**
 * Analytics Dashboard JavaScript
 * Handles data fetching, chart rendering, and user interactions
 */

// Configuration
const API_BASE_URL = 'http://localhost:3000/api';
let currentUser = null;
let analyticsData = [];
let charts = {};
let offlineManager;
let socket; // Socket.io instance

// Chart color schemes
const COLORS = {
    primary: '#6366f1',
    secondary: '#8b5cf6',
    success: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#3b82f6',
    gradient: ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981'],
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    console.log('📊 Initializing Analytics Dashboard...');

    // Initialize offline manager
    offlineManager = new OfflineManager();
    await offlineManager.initDB();

    // Check authentication
    await checkAuthentication();

    // Set up event listeners
    setupEventListeners();

    // Monitor network status
    setupNetworkMonitoring();

    // Set default date range (last 30 days)
    setDefaultDateRange(30);

    // Load initial data
    if (currentUser) {
        await loadPreferences();
        await loadAnalyticsData();
        initWebSocket(); // Initialize real-time updates
    }
});

/**
 * Load user preferences for analytics
 */
async function loadPreferences() {
    if (!window.XAYTHEON_AUTH) return;
    const prefs = await window.XAYTHEON_AUTH.fetchPreferences();

    if (prefs && prefs.analytics) {
        const p = prefs.analytics;
        if (p.starsChartType) document.getElementById('stars-chart-type').value = p.starsChartType;
        if (p.followersChartType) document.getElementById('followers-chart-type').value = p.followersChartType;

        // Table visibility
        const tableContainer = document.getElementById('table-container');
        if (p.showTable) {
            tableContainer.style.display = 'block';
        } else {
            tableContainer.style.display = 'none';
        }
    }
}

/**
 * Save analytics preference
 */
function saveAnalyticsPreference(key, value) {
    if (!window.XAYTHEON_AUTH || !window.XAYTHEON_AUTH.isAuthenticated()) return;

    // We need to fetch current prefs first to merge? 
    // API implementation handles merge of `analytics` object keys if we send logic correctly.
    // My controller implementation: newPrefs.analytics = { ...old, ...req.body.analytics }
    // so I can just send the partial update.

    const payload = {
        analytics: {
            [key]: value
        }
    };
    window.XAYTHEON_AUTH.savePreferences(payload);
}

/**
 * Monitor network status
 */
/**
 * Monitor network status
 */
function setupNetworkMonitoring() {
    window.addEventListener('online', () => {
        updateOnlineStatus(true);
        showToast('You are back online! Syncing data...', 'success');
        loadAnalyticsData(true);
    });
    window.addEventListener('offline', () => {
        updateOnlineStatus(false);
        showToast('You are offline. Some features may be limited.', 'error');
    });
    updateOnlineStatus(navigator.onLine);
}

/**
 * Update UI based on online status
 */
function updateOnlineStatus(isOnline) {
    const statusEl = document.getElementById('connection-status');
    const refreshBtn = document.getElementById('refresh-data-btn');

    if (isOnline) {
        statusEl.classList.add('hidden');
        statusEl.innerHTML = '<span class="status-dot online"></span><span class="status-text">ONLINE</span>';
        refreshBtn.disabled = false;
        // Hide badge after delay if needed, or keep logic simple
        statusEl.style.display = 'none';
    } else {
        statusEl.classList.remove('hidden');
        statusEl.innerHTML = '<span class="status-dot offline"></span><span class="status-text">OFFLINE</span>';
        statusEl.style.display = 'flex';
        // refreshBtn.disabled = true; // Optional: disable refresh while offline
    }
}

/**
 * Check if user is authenticated
 */
async function checkAuthentication() {
    try {
        const token = localStorage.getItem('authToken');

        if (!token) {
            showAuthWarning();
            return;
        }

        // Verify token with backend
        const response = await fetch(`${API_BASE_URL}/user/profile`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (response.ok) {
            currentUser = await response.json();
            hideAuthWarning();
        } else {
            showAuthWarning();
        }
    } catch (error) {
        console.error('Authentication check failed:', error);
        showAuthWarning();
    }
}

/**
 * Show authentication warning
 */
function showAuthWarning() {
    const warning = document.getElementById('auth-warning');
    if (warning) {
        warning.style.display = 'flex';
    }

    // Hide main content
    document.getElementById('metrics-grid').style.display = 'none';
    document.querySelector('.charts-grid').style.display = 'none';
    document.querySelector('.table-card').style.display = 'none';
    document.querySelector('.date-range-card').style.display = 'none';
}

/**
 * Hide authentication warning
 */
function hideAuthWarning() {
    const warning = document.getElementById('auth-warning');
    if (warning) {
        warning.style.display = 'none';
    }
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Date range quick buttons
    document.querySelectorAll('[data-range]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const days = parseInt(e.target.dataset.range);
            setDefaultDateRange(days);
            loadAnalyticsData();
        });
    });

    // Date inputs
    document.getElementById('start-date').addEventListener('change', loadAnalyticsData);
    document.getElementById('end-date').addEventListener('change', loadAnalyticsData);

    // Refresh button
    document.getElementById('refresh-data-btn').addEventListener('click', () => {
        loadAnalyticsData(true);
    });

    // Export button
    document.getElementById('export-data-btn').addEventListener('click', showExportModal);

    // Export modal
    document.getElementById('close-export-modal').addEventListener('click', hideExportModal);
    document.querySelectorAll('.export-option').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const format = e.currentTarget.dataset.format;
            exportData(format);
        });
    });

    // Table toggle
    document.getElementById('toggle-table-btn').addEventListener('click', () => {
        toggleTable();
        const container = document.getElementById('table-container');
        saveAnalyticsPreference('showTable', container.style.display !== 'none');
    });

    // Chart type selectors
    document.getElementById('stars-chart-type').addEventListener('change', (e) => {
        updateChartType('stars', e.target.value);
        saveAnalyticsPreference('starsChartType', e.target.value);
    });

    document.getElementById('followers-chart-type').addEventListener('change', (e) => {
        updateChartType('followers', e.target.value);
        saveAnalyticsPreference('followersChartType', e.target.value);
    });
}

/**
 * Set default date range
 */
function setDefaultDateRange(days) {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    document.getElementById('start-date').value = startDate.toISOString().split('T')[0];
    document.getElementById('end-date').value = endDate.toISOString().split('T')[0];
}

/**
 * Load analytics data from API
 */
async function loadAnalyticsData(forceRefresh = false) {
    if (!currentUser) return;

    const startDate = document.getElementById('start-date').value;
    const endDate = document.getElementById('end-date').value;
    const cacheKey = `analytics_${startDate}_${endDate}`;
    const lastUpdatedEl = document.getElementById('last-updated-time');
    const lastUpdatedInfo = document.getElementById('last-updated-info');

    if (!startDate || !endDate) {
        console.warn('Please select both start and end dates');
        return;
    }

    try {
        // Try to fetch from API if online
        if (navigator.onLine) {
            const token = localStorage.getItem('authToken');

            // Fetch snapshots
            const response = await fetch(
                `${API_BASE_URL}/analytics/snapshots?startDate=${startDate}&endDate=${endDate}`,
                {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                    },
                }
            );

            if (!response.ok) {
                throw new Error('Failed to fetch analytics data');
            }

            const data = await response.json();
            analyticsData = data.snapshots || [];

            // Cache the fresh data
            await offlineManager.saveData(cacheKey, analyticsData);

            // Update "Last updated" text
            lastUpdatedEl.textContent = 'Just now';
            lastUpdatedInfo.style.display = 'inline-block';

        } else {
            // Offline: fallback to cache
            throw new Error('Offline');
        }

    } catch (error) {
        console.warn('Fetching unsuccessful, attempting cache...', error);

        // Try loading from cache
        const cachedRecord = await offlineManager.loadData(cacheKey);

        if (cachedRecord && cachedRecord.data) {
            analyticsData = cachedRecord.data;

            if (navigator.onLine) {
                showError('Could not fetch new data. Showing cached version.');
            } else {
                // Determine user-friendly offline message
                console.log('✅ Loaded data from cache');
            }

            // Update "Last updated" timestamp
            lastUpdatedEl.textContent = offlineManager.formatTime(cachedRecord.timestamp);
            lastUpdatedInfo.style.display = 'inline-block';

        } else {
            if (!navigator.onLine) {
                showError('You are offline and no cached data is available for this date range.');
            } else {
                console.error('Error loading analytics data:', error);
                showError('Failed to load analytics data. Please try again.');
            }
            return;
        }
    }

    if (analyticsData.length === 0) {
        showEmptyState();
        return;
    }

    // Update UI
    updateMetrics();
    renderCharts();
    updateTable();
}

/**
 * Update metrics cards
 */
function updateMetrics() {
    if (analyticsData.length === 0) return;

    const latest = analyticsData[analyticsData.length - 1];
    const first = analyticsData[0];

    // Update values
    document.getElementById('metric-stars').textContent = latest.stars.toLocaleString();
    document.getElementById('metric-followers').textContent = latest.followers.toLocaleString();
    document.getElementById('metric-repos').textContent = latest.public_repos.toLocaleString();
    document.getElementById('metric-commits').textContent = latest.total_commits.toLocaleString();

    // Calculate and display changes
    updateMetricChange('stars', first.stars, latest.stars);
    updateMetricChange('followers', first.followers, latest.followers);
    updateMetricChange('repos', first.public_repos, latest.public_repos);
    updateMetricChange('commits', first.total_commits, latest.total_commits);
}

/**
 * Update metric change indicator
 */
function updateMetricChange(metric, oldValue, newValue) {
    const changeEl = document.getElementById(`metric-${metric}-change`);
    const change = newValue - oldValue;
    const percentChange = oldValue > 0 ? ((change / oldValue) * 100).toFixed(1) : 0;

    let className = 'neutral';
    let symbol = '';

    if (change > 0) {
        className = 'positive';
        symbol = '↑';
    } else if (change < 0) {
        className = 'negative';
        symbol = '↓';
    } else {
        symbol = '→';
    }

    changeEl.className = `metric-change ${className}`;
    changeEl.textContent = `${symbol} ${Math.abs(change).toLocaleString()} (${percentChange}%)`;
}

/**
 * Render all charts
 */
function renderCharts() {
    renderStarsChart();
    renderFollowersChart();
    renderReposChart();
    renderCommitsChart();
    renderLanguageChart();
    renderContributionChart();
}

/**
 * Render stars growth chart
 */
function renderStarsChart() {
    const ctx = document.getElementById('stars-chart').getContext('2d');
    const chartType = document.getElementById('stars-chart-type').value;

    if (charts.stars) {
        charts.stars.destroy();
    }

    const labels = analyticsData.map(d => new Date(d.snapshot_date).toLocaleDateString());
    const data = analyticsData.map(d => d.stars);

    charts.stars = new Chart(ctx, {
        type: chartType,
        data: {
            labels,
            datasets: [{
                label: 'Total Stars',
                data,
                backgroundColor: chartType === 'bar' ? COLORS.primary : `${COLORS.primary}20`,
                borderColor: COLORS.primary,
                borderWidth: 2,
                fill: chartType === 'line',
                tension: 0.4,
            }],
        },
        options: getChartOptions('Stars'),
    });
}

/**
 * Render followers growth chart
 */
function renderFollowersChart() {
    const ctx = document.getElementById('followers-chart').getContext('2d');
    const chartType = document.getElementById('followers-chart-type').value;

    if (charts.followers) {
        charts.followers.destroy();
    }

    const labels = analyticsData.map(d => new Date(d.snapshot_date).toLocaleDateString());
    const followersData = analyticsData.map(d => d.followers);
    const followingData = analyticsData.map(d => d.following);

    charts.followers = new Chart(ctx, {
        type: chartType,
        data: {
            labels,
            datasets: [
                {
                    label: 'Followers',
                    data: followersData,
                    backgroundColor: chartType === 'bar' ? COLORS.success : `${COLORS.success}20`,
                    borderColor: COLORS.success,
                    borderWidth: 2,
                    fill: chartType === 'line',
                    tension: 0.4,
                },
                {
                    label: 'Following',
                    data: followingData,
                    backgroundColor: chartType === 'bar' ? COLORS.info : `${COLORS.info}20`,
                    borderColor: COLORS.info,
                    borderWidth: 2,
                    fill: chartType === 'line',
                    tension: 0.4,
                },
            ],
        },
        options: getChartOptions('Followers'),
    });
}

/**
 * Render repositories chart
 */
function renderReposChart() {
    const ctx = document.getElementById('repos-chart').getContext('2d');

    if (charts.repos) {
        charts.repos.destroy();
    }

    const labels = analyticsData.map(d => new Date(d.snapshot_date).toLocaleDateString());
    const data = analyticsData.map(d => d.public_repos);

    charts.repos = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Public Repositories',
                data,
                backgroundColor: `${COLORS.secondary}20`,
                borderColor: COLORS.secondary,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
            }],
        },
        options: getChartOptions('Repositories'),
    });
}

/**
 * Render commits chart
 */
function renderCommitsChart() {
    const ctx = document.getElementById('commits-chart').getContext('2d');

    if (charts.commits) {
        charts.commits.destroy();
    }

    const labels = analyticsData.map(d => new Date(d.snapshot_date).toLocaleDateString());
    const data = analyticsData.map(d => d.total_commits);

    charts.commits = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Total Commits',
                data,
                backgroundColor: COLORS.warning,
                borderColor: COLORS.warning,
                borderWidth: 1,
            }],
        },
        options: getChartOptions('Commits'),
    });
}

/**
 * Render language distribution chart
 */
function renderLanguageChart() {
    const ctx = document.getElementById('language-chart').getContext('2d');

    if (charts.language) {
        charts.language.destroy();
    }

    // Aggregate language stats from latest snapshot
    const latest = analyticsData[analyticsData.length - 1];
    const languageStats = latest.language_stats || {};

    const labels = Object.keys(languageStats);
    const data = Object.values(languageStats);

    if (labels.length === 0) {
        // Show empty state
        ctx.canvas.parentElement.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📊</div><h3>No Language Data</h3><p>Language statistics will appear here once available.</p></div>';
        return;
    }

    charts.language = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: COLORS.gradient,
                borderWidth: 2,
                borderColor: '#fff',
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${percentage}%`;
                        }
                    }
                }
            },
        },
    });
}

/**
 * Render contribution velocity chart
 */
function renderContributionChart() {
    const ctx = document.getElementById('contribution-chart').getContext('2d');

    if (charts.contribution) {
        charts.contribution.destroy();
    }

    const labels = analyticsData.map(d => new Date(d.snapshot_date).toLocaleDateString());
    const data = analyticsData.map(d => d.contribution_count || 0);

    charts.contribution = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Contributions',
                data,
                backgroundColor: `${COLORS.danger}20`,
                borderColor: COLORS.danger,
                borderWidth: 2,
                fill: true,
                tension: 0.4,
            }],
        },
        options: getChartOptions('Contributions'),
    });
}

/**
 * Get common chart options
 */
function getChartOptions(title) {
    return {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                display: true,
                position: 'top',
            },
            tooltip: {
                mode: 'index',
                intersect: false,
            },
        },
        scales: {
            y: {
                beginAtZero: true,
                ticks: {
                    precision: 0,
                },
            },
        },
    };
}

/**
 * Update chart type
 */
function updateChartType(chartName, type) {
    if (chartName === 'stars') {
        renderStarsChart();
    } else if (chartName === 'followers') {
        renderFollowersChart();
    }
}

/**
 * Update data table
 */
function updateTable() {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = '';

    analyticsData.forEach(snapshot => {
        const row = document.createElement('tr');
        row.innerHTML = `
      <td>${new Date(snapshot.snapshot_date).toLocaleDateString()}</td>
      <td>${snapshot.stars.toLocaleString()}</td>
      <td>${snapshot.followers.toLocaleString()}</td>
      <td>${snapshot.following.toLocaleString()}</td>
      <td>${snapshot.public_repos.toLocaleString()}</td>
      <td>${snapshot.total_commits.toLocaleString()}</td>
      <td>${(snapshot.contribution_count || 0).toLocaleString()}</td>
    `;
        tbody.appendChild(row);
    });
}

/**
 * Toggle table visibility
 */
function toggleTable() {
    const container = document.getElementById('table-container');
    container.style.display = container.style.display === 'none' ? 'block' : 'none';
}

/**
 * Show export modal
 */
function showExportModal() {
    document.getElementById('export-modal').style.display = 'flex';
}

/**
 * Hide export modal
 */
function hideExportModal() {
    document.getElementById('export-modal').style.display = 'none';
}

/**
 * Export data
 */
async function exportData(format) {
    try {
        const startDate = document.getElementById('start-date').value;
        const endDate = document.getElementById('end-date').value;
        const token = localStorage.getItem('authToken');

        const response = await fetch(
            `${API_BASE_URL}/analytics/export?format=${format}&startDate=${startDate}&endDate=${endDate}`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            }
        );

        if (!response.ok) {
            throw new Error('Export failed');
        }

        // Download file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `analytics-export-${Date.now()}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        hideExportModal();
        showSuccess(`Data exported successfully as ${format.toUpperCase()}`);
    } catch (error) {
        console.error('Export error:', error);
        showError('Failed to export data. Please try again.');
    }
}

/**
 * Show empty state
 */
function showEmptyState() {
    const metricsGrid = document.getElementById('metrics-grid');
    metricsGrid.innerHTML = `
    <div class="empty-state" style="grid-column: 1 / -1;">
      <div class="empty-state-icon">📊</div>
      <h3>No Analytics Data Available</h3>
      <p>Start tracking your GitHub analytics by creating your first snapshot from the GitHub Dashboard.</p>
    </div>
  `;
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';

    toast.innerHTML = `
        <span class="toast-icon">${icon}</span>
        <span class="toast-message">${message}</span>
    `;

    container.appendChild(toast);

    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.animation = 'toast-out 0.3s ease-in forwards';
        toast.addEventListener('animationend', () => {
            toast.remove();
            if (container.children.length === 0) {
                container.remove();
            }
        });
    }, 4000);
}

/**
 * Show success message
 */
function showSuccess(message) {
    console.log('✅', message);
    showToast(message, 'success');
}

/**
 * Show error message
 */
function showError(message) {
    console.error('❌', message);
    showToast(message, 'error');
}
/**
 * Initialize WebSocket connection
 */
function initWebSocket() {
    if (socket) return;

    const token = localStorage.getItem('authToken');
    if (!token) return;

    const socketUrl = window.location.hostname === 'localhost' ? 'http://localhost:3000' : window.location.origin;
    socket = io(socketUrl, {
        auth: {
            token: token
        },
        transports: ['websocket', 'polling']
    });

    socket.on('connect', () => {
        console.log('🔌 Connected to WebSocket server');
        socket.emit('join_analytics');

        // Show live indicator
        const liveIndicator = document.getElementById('live-indicator');
        if (liveIndicator) {
            liveIndicator.style.display = 'flex';
        }
    });

    socket.on('analytics_update', (update) => {
        // console.log('📡 Real-time update received:', update);
        handleRealTimeUpdate(update);
    });

    socket.on('disconnect', () => {
        console.log('❌ Disconnected from WebSocket server');
        const liveIndicator = document.getElementById('live-indicator');
        if (liveIndicator) {
            liveIndicator.style.display = 'none';
        }
    });

    socket.on('connect_error', (err) => {
        console.error('WebSocket connection error:', err);
    });
}

/**
 * Handle real-time analytics update
 * @param {Object} update 
 */
function handleRealTimeUpdate(update) {
    if (!update || !update.data) return;

    // Flash live indicator
    const liveDot = document.querySelector('.live-dot');
    if (liveDot) {
        liveDot.style.color = '#fff';
        setTimeout(() => {
            liveDot.style.color = 'currentColor';
        }, 300);
    }

    // Update "Last updated" to "LIVE"
    const lastUpdatedInfo = document.getElementById('last-updated-time');
    if (lastUpdatedInfo) {
        lastUpdatedInfo.textContent = 'LIVE';
    }

    // Apply incremental updates to the latest data point
    // In a real app, we might push a new data point or update the existing one
    // Here we'll update existing latest point for visual effect or push if needed

    if (analyticsData.length > 0) {
        const latest = analyticsData[analyticsData.length - 1];

        // Apply changes
        latest.stars += (update.data.stars_change || 0);
        latest.followers += (update.data.followers_change || 0);
        latest.total_commits += (update.data.commits_change || 0);

        // Only re-render if visible
        requestAnimationFrame(() => {
            updateMetrics();

            // Only update charts occasionally or if significant change to avoid performance hit
            // For this demo, we'll update charts too to show movement
            charts.stars.data.datasets[0].data[analyticsData.length - 1] = latest.stars;
            charts.stars.update('none'); // efficient update

            charts.followers.data.datasets[0].data[analyticsData.length - 1] = latest.followers;
            charts.followers.update('none');

            charts.commits.data.datasets[0].data[analyticsData.length - 1] = latest.total_commits;
            charts.commits.update('none');
        });
    }
}
