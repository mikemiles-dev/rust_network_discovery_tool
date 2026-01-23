/**
 * Settings Module - Handles application settings
 */
(function(window) {
    'use strict';

    /**
     * Load settings from the API and populate the form
     */
    function loadSettings() {
        fetch('/api/settings')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                var settings = data.settings || {};

                // Populate form fields
                var cleanupInterval = document.getElementById('setting-cleanup-interval');
                if (cleanupInterval && settings.cleanup_interval_seconds) {
                    cleanupInterval.value = settings.cleanup_interval_seconds;
                }

                var dataRetention = document.getElementById('setting-data-retention');
                if (dataRetention && settings.data_retention_days) {
                    dataRetention.value = settings.data_retention_days;
                }

                var activeThreshold = document.getElementById('setting-active-threshold');
                if (activeThreshold && settings.active_threshold_seconds) {
                    activeThreshold.value = settings.active_threshold_seconds;
                }

                var autoScanInterval = document.getElementById('setting-auto-scan-interval');
                if (autoScanInterval && settings.auto_scan_interval_minutes !== undefined) {
                    autoScanInterval.value = settings.auto_scan_interval_minutes;
                }

                showStatus('Settings loaded', 'success');
            })
            .catch(function(error) {
                console.error('Error loading settings:', error);
                showStatus('Failed to load settings', 'error');
            });
    }

    /**
     * Save settings to the API
     */
    function saveSettings() {
        var cleanupInterval = document.getElementById('setting-cleanup-interval');
        var dataRetention = document.getElementById('setting-data-retention');
        var activeThreshold = document.getElementById('setting-active-threshold');

        var promises = [];

        if (cleanupInterval) {
            promises.push(
                fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        key: 'cleanup_interval_seconds',
                        value: cleanupInterval.value
                    })
                })
            );
        }

        if (dataRetention) {
            promises.push(
                fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        key: 'data_retention_days',
                        value: dataRetention.value
                    })
                })
            );
        }

        if (activeThreshold) {
            promises.push(
                fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        key: 'active_threshold_seconds',
                        value: activeThreshold.value
                    })
                })
            );
        }

        var autoScanInterval = document.getElementById('setting-auto-scan-interval');
        if (autoScanInterval) {
            promises.push(
                fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        key: 'auto_scan_interval_minutes',
                        value: autoScanInterval.value
                    })
                })
            );
        }

        Promise.all(promises)
            .then(function(responses) {
                return Promise.all(responses.map(function(r) { return r.json(); }));
            })
            .then(function(results) {
                var allSuccess = results.every(function(r) { return r.success; });
                if (allSuccess) {
                    showStatus('Settings saved successfully. Restart the application for timing changes to take effect.', 'success');
                    // Restart auto-scan with new interval
                    if (window.startAutoScan) {
                        window.startAutoScan();
                    }
                } else {
                    showStatus('Some settings failed to save', 'error');
                }
            })
            .catch(function(error) {
                console.error('Error saving settings:', error);
                showStatus('Failed to save settings', 'error');
            });
    }

    /**
     * Show status message
     */
    function showStatus(message, type) {
        var statusEl = document.getElementById('settings-status');
        if (!statusEl) return;

        statusEl.textContent = message;
        statusEl.style.display = 'block';

        if (type === 'success') {
            statusEl.style.background = 'rgba(34, 197, 94, 0.2)';
            statusEl.style.color = '#22c55e';
            statusEl.style.border = '1px solid rgba(34, 197, 94, 0.3)';
        } else if (type === 'error') {
            statusEl.style.background = 'rgba(239, 68, 68, 0.2)';
            statusEl.style.color = '#ef4444';
            statusEl.style.border = '1px solid rgba(239, 68, 68, 0.3)';
        }

        // Hide after 5 seconds
        setTimeout(function() {
            statusEl.style.display = 'none';
        }, 5000);
    }

    // Load settings when switching to the settings tab
    var originalSwitchTab = window.switchTab;
    window.switchTab = function(tabName) {
        if (originalSwitchTab) {
            originalSwitchTab(tabName);
        }
        if (tabName === 'settings') {
            loadSettings();
        }
    };

    // Expose functions globally
    window.loadSettings = loadSettings;
    window.saveSettings = saveSettings;

})(window);
