/**
 * Refresh Module - Auto-refresh timer management
 */
(function(App) {
    'use strict';

    App.Refresh = {
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
                        // Reload page for network tab
                        window.location.reload();
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
                window.location.reload();
            }
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

})(window.App);
