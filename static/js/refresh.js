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
                    // Skip refresh if device capabilities are loading
                    if (!App.state.deviceCapabilitiesLoaded) {
                        return;
                    }

                    // Skip refresh if any edit input is visible (user is editing)
                    var editInputs = document.querySelectorAll('#endpoint-rename-input, #vendor-edit-input, #model-edit-input');
                    for (var i = 0; i < editInputs.length; i++) {
                        if (editInputs[i].style.display !== 'none') {
                            return;
                        }
                    }

                    // Skip refresh if device type dropdown is open
                    var deviceTypeDropdown = document.getElementById('device-type-dropdown');
                    if (deviceTypeDropdown && deviceTypeDropdown.classList.contains('open')) {
                        return;
                    }

                    if (App.state.activeTab === 'dns') {
                        // Refresh DNS entries without page reload
                        if (App.Tabs) App.Tabs.refreshDnsEntries();
                    } else if (App.state.activeTab === 'scanner') {
                        // Don't reload page when on scanner tab - scanner has its own polling
                        if (App.Scanner) App.Scanner.pollStatus();
                    } else if (App.state.activeTab === 'network') {
                        // Refresh only the endpoint table, not the details panel
                        App.Refresh.refreshEndpointTable();
                    }
                    // No auto-refresh for internet and settings tabs
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
            } else if (App.state.activeTab === 'network') {
                App.Refresh.refreshEndpointTable();
            }
            // No action for internet and settings tabs
        },

        /**
         * Refresh endpoint table without reloading page or affecting endpoint details
         */
        refreshEndpointTable: function() {
            fetch('/api/endpoints/table')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (!data.endpoints) return;

                    // Build a lookup map by lowercase name for quick access
                    var endpointMap = {};
                    data.endpoints.forEach(function(ep) {
                        endpointMap[ep.name.toLowerCase()] = ep;
                    });

                    // Check if there are new endpoints not in the current table
                    var rows = document.querySelectorAll('.endpoint-row');
                    var existingEndpoints = new Set();
                    rows.forEach(function(row) {
                        if (row.dataset.endpoint) {
                            existingEndpoints.add(row.dataset.endpoint.toLowerCase());
                        }
                    });

                    // If new endpoints found, reload the page to show them
                    var hasNewEndpoints = data.endpoints.some(function(ep) {
                        return !existingEndpoints.has(ep.name.toLowerCase());
                    });

                    if (hasNewEndpoints) {
                        console.log('New endpoints detected, reloading page...');
                        App.Refresh.reloadWithState();
                        return;
                    }

                    // Update existing rows in the table
                    rows.forEach(function(row) {
                        var endpointName = row.dataset.endpoint;
                        if (!endpointName) return;

                        var ep = endpointMap[endpointName.toLowerCase()];
                        if (!ep) return;

                        // Update vendor cell (use class selector)
                        var vendorCell = row.querySelector('.vendor-cell');
                        if (vendorCell) {
                            vendorCell.textContent = ep.vendor || '-';
                            vendorCell.title = ep.vendor || 'Unknown';
                        }

                        // Update model cell (use class selector)
                        var modelCell = row.querySelector('.model-cell');
                        if (modelCell) {
                            modelCell.textContent = ep.model || '-';
                            modelCell.title = ep.model || '';
                        }

                        // Update bandwidth cell (use class selector)
                        var bandwidthCell = row.querySelector('.bandwidth-cell');
                        if (bandwidthCell && App.Formatting) {
                            bandwidthCell.dataset.bytes = ep.bytes;
                            bandwidthCell.textContent = App.Formatting.formatBytes(ep.bytes);
                        }

                        // Update last seen cell (use class selector)
                        var lastSeenCell = row.querySelector('.last-seen-cell');
                        if (lastSeenCell) {
                            lastSeenCell.textContent = ep.last_seen;
                        }

                        // Update online status indicator (but respect recent ping results)
                        var statusIndicator = row.querySelector('.status-indicator');
                        if (statusIndicator) {
                            // Skip update if status was recently verified by ping (within 60 seconds)
                            var pingVerified = statusIndicator.dataset.pingVerified;
                            var isPingRecent = pingVerified && (Date.now() - parseInt(pingVerified, 10)) < 60000;

                            if (!isPingRecent) {
                                statusIndicator.className = 'status-indicator ' + (ep.online ? 'online' : 'offline');
                                statusIndicator.title = ep.online ? 'Online' : 'Offline';
                            }
                        }

                        // Update device type data attribute (for CSS styling)
                        if (ep.device_type) {
                            row.dataset.endpointType = ep.device_type;
                        }
                    });

                    // Re-apply filters after update
                    if (typeof applyFilters === 'function') {
                        applyFilters();
                    }
                })
                .catch(function(error) {
                    console.error('Failed to refresh endpoint table:', error);
                });
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

            // Preserve filter states (known/unknown/active/inactive)
            if (App.state.knownVendorsOnly) {
                url.searchParams.set('known', '1');
            }
            if (App.state.unknownVendorsOnly) {
                url.searchParams.set('unknown', '1');
            }
            if (App.state.activeOnly) {
                url.searchParams.set('active', '1');
            }
            if (App.state.inactiveOnly) {
                url.searchParams.set('inactive', '1');
            }

            // Save scroll positions before reload
            sessionStorage.setItem('scrollPosition', window.scrollY.toString());

            // Also save table container scroll if it exists
            var tableWrapper = document.querySelector('.endpoints-table-wrapper');
            if (tableWrapper) {
                sessionStorage.setItem('tableScrollPosition', tableWrapper.scrollTop.toString());
            }

            // Save endpoint details pane scroll if it exists
            var detailsPane = document.querySelector('.protocols-overlay');
            if (detailsPane) {
                sessionStorage.setItem('detailsScrollPosition', detailsPane.scrollTop.toString());
            }

            // Save active detail tab (Details, Network, Control)
            var activeDetailTab = document.querySelector('.detail-tab.active');
            if (activeDetailTab) {
                sessionStorage.setItem('activeDetailTab', activeDetailTab.dataset.tab);
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
