/**
 * Filters Module - Core filtering logic and coordinator
 */
(function(App) {
    'use strict';

    App.Filters = App.Filters || {};

    /**
     * Check if an IP is on the local network (private IP ranges)
     */
    App.Filters.isLocalIP = function(ip) {
        if (!ip) return false;

        var ipv4Private = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[01])\./,
            /^192\.168\./,
            /^127\./,
            /^169\.254\./,
            /^0\.0\.0\.0/,
            /^255\.255\.255\.255/
        ];

        var ipv6Private = [
            /^::1$/,
            /^fe80:/i,
            /^fc00:/i,
            /^fd00:/i,
            /^::$/
        ];

        for (var i = 0; i < ipv4Private.length; i++) {
            if (ipv4Private[i].test(ip)) return true;
        }

        for (var j = 0; j < ipv6Private.length; j++) {
            if (ipv6Private[j].test(ip)) return true;
        }

        return false;
    };

    /**
     * Apply filters to table rows
     */
    App.Filters.apply = function(skipUrlUpdate) {
        // Get filter checkbox states
        var showLocal = document.getElementById('filterLocal')?.checked ?? true;
        var showGateway = document.getElementById('filterGateway')?.checked ?? true;
        var showPrinter = document.getElementById('filterPrinter')?.checked ?? true;
        var showTv = document.getElementById('filterTv')?.checked ?? true;
        var showGaming = document.getElementById('filterGaming')?.checked ?? true;
        var showPhone = document.getElementById('filterPhone')?.checked ?? true;
        var showVirtualization = document.getElementById('filterVirtualization')?.checked ?? true;
        var showSoundbar = document.getElementById('filterSoundbar')?.checked ?? true;
        var showAppliance = document.getElementById('filterAppliance')?.checked ?? true;
        var showOther = document.getElementById('filterOther')?.checked ?? true;

        // Get search term
        var searchInput = document.getElementById('endpointSearch');
        var searchTerm = searchInput ? searchInput.value.trim().toLowerCase() : '';

        // Save filter state to URL (preserve all filter states)
        if (!skipUrlUpdate) {
            var url = new URL(window.location.href);

            if (App.state.activeOnly) {
                url.searchParams.set('active', '1');
            } else {
                url.searchParams.delete('active');
            }
            if (App.state.inactiveOnly) {
                url.searchParams.set('inactive', '1');
            } else {
                url.searchParams.delete('inactive');
            }
            if (App.state.knownVendorsOnly) {
                url.searchParams.set('known', '1');
            } else {
                url.searchParams.delete('known');
            }
            if (App.state.unknownVendorsOnly) {
                url.searchParams.set('unknown', '1');
            } else {
                url.searchParams.delete('unknown');
            }

            url.searchParams.set('filter_local', showLocal ? '1' : '0');
            url.searchParams.set('filter_gateway', showGateway ? '1' : '0');
            url.searchParams.set('filter_printer', showPrinter ? '1' : '0');
            url.searchParams.set('filter_tv', showTv ? '1' : '0');
            url.searchParams.set('filter_gaming', showGaming ? '1' : '0');
            url.searchParams.set('filter_phone', showPhone ? '1' : '0');
            url.searchParams.set('filter_virtualization', showVirtualization ? '1' : '0');
            url.searchParams.set('filter_soundbar', showSoundbar ? '1' : '0');
            url.searchParams.set('filter_appliance', showAppliance ? '1' : '0');
            url.searchParams.set('filter_other', showOther ? '1' : '0');
            if (searchTerm) {
                url.searchParams.set('search', searchTerm);
            } else {
                url.searchParams.delete('search');
            }
            window.history.replaceState({}, '', url);
        }

        // Filter table rows based on endpoint type and search term
        var tableRows = document.querySelectorAll('.endpoint-row');
        tableRows.forEach(function(row) {
            var rowType = row.dataset.endpointType || 'other';
            var shouldShowByType = false;

            if (rowType === 'local' && showLocal) shouldShowByType = true;
            else if (rowType === 'gateway' && showGateway) shouldShowByType = true;
            else if (rowType === 'printer' && showPrinter) shouldShowByType = true;
            else if (rowType === 'tv' && showTv) shouldShowByType = true;
            else if (rowType === 'gaming' && showGaming) shouldShowByType = true;
            else if (rowType === 'phone' && showPhone) shouldShowByType = true;
            else if (rowType === 'virtualization' && showVirtualization) shouldShowByType = true;
            else if (rowType === 'soundbar' && showSoundbar) shouldShowByType = true;
            else if (rowType === 'appliance' && showAppliance) shouldShowByType = true;
            else if (rowType === 'other' && showOther) shouldShowByType = true;

            // Apply search filter if search term exists
            var shouldShowBySearch = true;
            if (searchTerm) {
                var endpointName = (row.dataset.endpointName || '').toLowerCase();
                var endpointVendor = (row.dataset.endpointVendor || '').toLowerCase();
                var endpointModel = (row.dataset.endpointModel || '').toLowerCase();

                shouldShowBySearch = endpointName.includes(searchTerm) ||
                                     endpointVendor.includes(searchTerm) ||
                                     endpointModel.includes(searchTerm);
            }

            // Apply vendor filter if selected
            var shouldShowByVendor = true;
            if (App.state.selectedVendor) {
                var rowVendor = (row.dataset.endpointVendor || '').toLowerCase().trim();
                if (App.state.selectedVendor === '__none__') {
                    shouldShowByVendor = rowVendor === '';
                } else {
                    shouldShowByVendor = rowVendor === App.state.selectedVendor.toLowerCase();
                }
            }

            // Apply "known vendors only" filter if active
            var shouldShowByKnown = true;
            if (App.state.knownVendorsOnly) {
                var rowVendorKnown = (row.dataset.endpointVendor || '').trim();
                shouldShowByKnown = rowVendorKnown !== '';
            }

            // Apply "unknown vendors only" filter if active
            var shouldShowByUnknown = true;
            if (App.state.unknownVendorsOnly) {
                var rowVendorUnknown = (row.dataset.endpointVendor || '').trim();
                shouldShowByUnknown = rowVendorUnknown === '';
            }

            // Apply "active only" filter if active
            var shouldShowByActive = true;
            if (App.state.activeOnly) {
                var isOnline = row.dataset.endpointOnline === 'true';
                shouldShowByActive = isOnline;
            }

            // Apply "inactive only" filter if active
            var shouldShowByInactive = true;
            if (App.state.inactiveOnly) {
                var isOffline = row.dataset.endpointOnline !== 'true';
                shouldShowByInactive = isOffline;
            }

            // Set filtered-out attribute for pagination to use
            var isFilteredOut = !(shouldShowByType && shouldShowBySearch && shouldShowByVendor && shouldShowByKnown && shouldShowByUnknown && shouldShowByActive && shouldShowByInactive);
            row.dataset.filteredOut = isFilteredOut ? 'true' : 'false';
        });

        // Remove filters-pending class to show rows
        document.body.classList.remove('filters-pending');

        // Update pagination after filtering
        if (App.Pagination) {
            App.Pagination.resetToFirstPage('endpoints');
        }

        // Update filter button visual states
        App.Filters.updateFilterButtonStates();
    };

    /**
     * Update visual state of Known/Unknown/Active filter buttons
     */
    App.Filters.updateFilterButtonStates = function() {
        var quickButtons = document.querySelectorAll('.quick-buttons button');
        quickButtons.forEach(function(btn) {
            var onclick = btn.getAttribute('onclick') || '';
            if (onclick.includes('showOnlyActive')) {
                if (App.state.activeOnly) {
                    btn.style.background = 'rgba(34, 197, 94, 0.5)';
                    btn.style.borderColor = '#22c55e';
                    btn.style.boxShadow = '0 0 8px rgba(34, 197, 94, 0.4)';
                } else {
                    btn.style.background = 'rgba(34, 197, 94, 0.2)';
                    btn.style.borderColor = 'rgba(34, 197, 94, 0.4)';
                    btn.style.boxShadow = 'none';
                }
            } else if (onclick.includes('showOnlyInactive')) {
                if (App.state.inactiveOnly) {
                    btn.style.background = 'rgba(107, 114, 128, 0.5)';
                    btn.style.borderColor = '#6b7280';
                    btn.style.boxShadow = '0 0 8px rgba(107, 114, 128, 0.4)';
                } else {
                    btn.style.background = 'rgba(107, 114, 128, 0.2)';
                    btn.style.borderColor = 'rgba(107, 114, 128, 0.4)';
                    btn.style.boxShadow = 'none';
                }
            } else if (onclick.includes('showOnlyKnownVendors')) {
                if (App.state.knownVendorsOnly) {
                    btn.style.background = 'rgba(16, 185, 129, 0.5)';
                    btn.style.borderColor = '#10b981';
                    btn.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.4)';
                } else {
                    btn.style.background = 'rgba(16, 185, 129, 0.2)';
                    btn.style.borderColor = 'rgba(16, 185, 129, 0.4)';
                    btn.style.boxShadow = 'none';
                }
            } else if (onclick.includes('showOnlyUnknown')) {
                if (App.state.unknownVendorsOnly) {
                    btn.style.background = 'rgba(156, 163, 175, 0.5)';
                    btn.style.borderColor = '#9ca3af';
                    btn.style.boxShadow = '0 0 8px rgba(156, 163, 175, 0.4)';
                } else {
                    btn.style.background = 'rgba(156, 163, 175, 0.2)';
                    btn.style.borderColor = 'rgba(156, 163, 175, 0.4)';
                    btn.style.boxShadow = 'none';
                }
            }
        });
    };

    // Expose functions globally for onclick handlers
    window.applyFilters = App.Filters.apply;
    window.selectAllFilters = App.Filters.selectAll;
    window.selectNoneFilters = App.Filters.selectNone;
    window.selectOnlyFilter = App.Filters.selectOnly;
    window.handleFilterClick = App.Filters.handleClick;
    window.filterHostnamesList = App.Filters.filterHostnamesList;
    window.filterPortsList = App.Filters.filterPortsList;
    window.filterIpsList = App.Filters.filterIpsList;
    window.filterMacsList = App.Filters.filterMacsList;
    window.isLocalIP = App.Filters.isLocalIP;
    window.filterByProtocol = App.Filters.filterByProtocol;
    window.clearProtocolFilter = App.Filters.clearProtocolFilter;
    window.filterByGlobalProtocol = App.Filters.filterByGlobalProtocol;
    window.filterByPort = App.Filters.filterByPort;
    window.clearPortFilter = App.Filters.clearPortFilter;
    window.filterByVendor = App.Filters.filterByVendor;
    window.showOnlyKnownVendors = App.Filters.showOnlyKnownVendors;
    window.showOnlyUnknown = App.Filters.showOnlyUnknown;
    window.showOnlyActive = App.Filters.showOnlyActive;
    window.showOnlyInactive = App.Filters.showOnlyInactive;

    /**
     * Clear all filters - search, protocol, vendor, known, and active
     */
    window.clearAllFilters = function() {
        var searchInput = document.getElementById('endpointSearch');
        if (searchInput) {
            searchInput.value = '';
        }

        var protocolSelect = document.getElementById('globalProtocolSelect');
        if (protocolSelect) {
            protocolSelect.value = '';
            App.state.selectedProtocol = null;
        }

        var vendorSelect = document.getElementById('globalVendorSelect');
        if (vendorSelect) {
            vendorSelect.value = '';
            App.state.selectedVendor = null;
        }

        App.state.knownVendorsOnly = false;
        App.state.unknownVendorsOnly = false;
        App.state.activeOnly = false;
        App.state.inactiveOnly = false;

        var url = new URL(window.location.href);
        url.searchParams.delete('known');
        url.searchParams.delete('unknown');
        url.searchParams.delete('active');
        url.searchParams.delete('inactive');
        history.replaceState({}, '', url.toString());

        App.Filters.clearPortFilter();
        App.Filters.apply();
    };

    // Load global protocols on page load
    document.addEventListener('DOMContentLoaded', function() {
        App.Filters.loadGlobalProtocols();
    });

})(window.App);
