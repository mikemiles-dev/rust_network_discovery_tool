/**
 * Refresh Module - Auto-refresh timer management
 */
(function(App) {
    'use strict';

    var pauseTimeoutId = null;
    var pausedInterval = null;

    App.Refresh = {
        /**
         * Temporarily pause auto-refresh for a specified duration
         * Used when user is typing to prevent page reload mid-typing
         */
        pauseTemporarily: function(durationMs) {
            durationMs = durationMs || 5000; // Default 5 seconds

            var refreshSelect = document.getElementById('refreshInterval');
            var currentInterval = refreshSelect ? parseInt(refreshSelect.value, 10) : 0;

            // Only pause if auto-refresh is active
            if (currentInterval === 0) {
                return;
            }

            // Clear any existing pause timeout
            if (pauseTimeoutId) {
                clearTimeout(pauseTimeoutId);
            }

            // If not already paused, save the interval and stop refresh
            if (!pausedInterval) {
                pausedInterval = currentInterval;
                // Clear the interval without changing UI state
                if (App.state.refreshIntervalId) {
                    clearInterval(App.state.refreshIntervalId);
                    App.state.refreshIntervalId = null;
                }
            }

            // Set timeout to resume
            pauseTimeoutId = setTimeout(function() {
                if (pausedInterval) {
                    App.Refresh.updateInterval(pausedInterval);
                    pausedInterval = null;
                }
                pauseTimeoutId = null;
            }, durationMs);
        },

        /**
         * Update refresh interval
         */
        updateInterval: function(seconds) {
            // Save preference
            localStorage.setItem('refreshInterval', seconds);

            // Clear existing interval
            if (App.state.refreshIntervalId) {
                clearInterval(App.state.refreshIntervalId);
                App.state.refreshIntervalId = null;
            }

            // Update pulse indicator and button state
            var pulse = document.querySelector('.pulse');
            var toggleBtn = document.getElementById('refreshToggleBtn');

            if (seconds == 0) {
                if (pulse) pulse.classList.add('stopped');
                if (toggleBtn) {
                    toggleBtn.innerHTML = '▶️';
                    toggleBtn.classList.add('play');
                    toggleBtn.title = 'Start auto-refresh';
                }
            } else {
                if (pulse) pulse.classList.remove('stopped');
                if (toggleBtn) {
                    toggleBtn.innerHTML = '⏹️';
                    toggleBtn.classList.remove('play');
                    toggleBtn.title = 'Stop auto-refresh';
                }

                // Set new interval - behavior depends on active tab
                App.state.refreshIntervalId = setInterval(function() {
                    if (App.state.activeTab === 'dns') {
                        // Refresh DNS entries without page reload
                        if (App.Tabs) App.Tabs.refreshDnsEntries();
                    } else if (App.state.activeTab === 'scanner') {
                        // Don't reload page when on scanner tab - scanner has its own polling
                        if (App.Scanner) App.Scanner.pollStatus();
                    } else {
                        // Reload page for network tab, preserving sort and selection
                        App.Refresh.reloadWithState();
                    }
                }, seconds * 1000);
            }
        },

        /**
         * Toggle auto-refresh on/off
         */
        toggle: function() {
            var refreshSelect = document.getElementById('refreshInterval');
            var currentValue = refreshSelect.value;

            if (currentValue == '0') {
                // Currently stopped, start with default 5 seconds
                var lastInterval = localStorage.getItem('lastRefreshInterval') || '5';
                refreshSelect.value = lastInterval;
                App.Refresh.updateInterval(lastInterval);
            } else {
                // Currently running, stop it
                localStorage.setItem('lastRefreshInterval', currentValue);
                refreshSelect.value = '0';
                App.Refresh.updateInterval('0');
            }
        },

        /**
         * Manual refresh - respects current tab
         */
        manual: function() {
            if (App.state.activeTab === 'dns') {
                if (App.Tabs) App.Tabs.refreshDnsEntries();
            } else if (App.state.activeTab === 'scanner') {
                if (App.Scanner) App.Scanner.pollStatus();
            } else {
                App.Refresh.reloadWithState();
            }
        },

        /**
         * Reload page while preserving sort and selection state
         */
        reloadWithState: function() {
            var url = new URL(window.location.href);

            // Save current sort state
            var sortedHeader = document.querySelector('.endpoints-table th.sorted-asc, .endpoints-table th.sorted-desc');
            if (sortedHeader) {
                var sortKey = sortedHeader.dataset.sort;
                var sortDir = sortedHeader.classList.contains('sorted-asc') ? 'asc' : 'desc';
                url.searchParams.set('sort', sortKey);
                url.searchParams.set('sort_dir', sortDir);
            }

            // Save current page for pagination
            if (App.Pagination) {
                var pageState = App.Pagination.getState('endpoints');
                if (pageState && pageState.currentPage > 1) {
                    url.searchParams.set('page', pageState.currentPage);
                }
                if (pageState && pageState.pageSize !== 25) {
                    url.searchParams.set('page_size', pageState.pageSize);
                }
            }

            // Save endpoint search value
            var searchInput = document.getElementById('endpointSearch');
            if (searchInput && searchInput.value.trim()) {
                url.searchParams.set('search', searchInput.value.trim());
            } else {
                url.searchParams.delete('search');
            }

            // Navigate to URL with state
            window.location.href = url.toString();
        },

        /**
         * Initialize refresh interval from saved preference
         */
        init: function() {
            var savedInterval = localStorage.getItem('refreshInterval') || '5';
            var refreshSelect = document.getElementById('refreshInterval');
            if (refreshSelect) {
                refreshSelect.value = savedInterval;
            }
            App.Refresh.updateInterval(savedInterval);
        }
    };

    // Expose functions globally for onclick handlers
    window.updateRefreshInterval = App.Refresh.updateInterval;
    window.toggleRefresh = App.Refresh.toggle;
    window.manualRefresh = App.Refresh.manual;
    window.pauseRefreshTemporarily = App.Refresh.pauseTemporarily;

})(window.App);
