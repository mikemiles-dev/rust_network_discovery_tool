/**
 * Filters Quick Module - Quick filter buttons and vendor/protocol dropdowns
 */
(function() {
    'use strict';

    App.Filters = App.Filters || {};

    // Debounce tracking for toggle buttons
    var lastToggleTime = 0;
    var TOGGLE_DEBOUNCE_MS = 300;

    function canToggle() {
        var now = Date.now();
        if (now - lastToggleTime < TOGGLE_DEBOUNCE_MS) {
            return false;
        }
        lastToggleTime = now;
        return true;
    }

    /**
     * Select all device type filters and clear known/unknown/active/inactive filters
     */
    App.Filters.selectAll = function() {
        document.getElementById('filterLocal').checked = true;
        document.getElementById('filterGateway').checked = true;
        document.getElementById('filterPrinter').checked = true;
        document.getElementById('filterTv').checked = true;
        document.getElementById('filterGaming').checked = true;
        document.getElementById('filterPhone').checked = true;
        document.getElementById('filterVirtualization').checked = true;
        document.getElementById('filterSoundbar').checked = true;
        document.getElementById('filterAppliance').checked = true;
        document.getElementById('filterOther').checked = true;

        // Clear known/unknown/active/inactive filter states
        App.state.knownVendorsOnly = false;
        App.state.unknownVendorsOnly = false;
        App.state.activeOnly = false;
        App.state.inactiveOnly = false;

        App.Filters.apply();
    };

    /**
     * Show only endpoints with known vendors
     */
    App.Filters.showOnlyKnownVendors = function() {
        if (!canToggle()) return;

        if (App.state.knownVendorsOnly) {
            return;
        }

        App.state.unknownVendorsOnly = false;
        App.state.knownVendorsOnly = true;

        App.Filters.updateFilterButtonStates();
        App.Filters.apply();
    };

    /**
     * Show only endpoints with unknown vendors
     */
    App.Filters.showOnlyUnknown = function() {
        if (!canToggle()) return;

        if (App.state.unknownVendorsOnly) {
            return;
        }

        App.state.knownVendorsOnly = false;
        App.state.unknownVendorsOnly = true;

        App.Filters.updateFilterButtonStates();
        App.Filters.apply();
    };

    /**
     * Show only endpoints that are currently active (online)
     */
    App.Filters.showOnlyActive = function() {
        if (App.state.activeOnly) {
            return;
        }

        App.state.inactiveOnly = false;
        App.state.activeOnly = true;

        App.Filters.updateFilterButtonStates();
        App.Filters.apply();
    };

    /**
     * Show only endpoints that are currently inactive (offline)
     */
    App.Filters.showOnlyInactive = function() {
        if (App.state.inactiveOnly) {
            return;
        }

        App.state.activeOnly = false;
        App.state.inactiveOnly = true;

        App.Filters.updateFilterButtonStates();
        App.Filters.apply();
    };

    /**
     * Deselect all device type filters
     */
    App.Filters.selectNone = function() {
        document.getElementById('filterLocal').checked = false;
        document.getElementById('filterGateway').checked = false;
        document.getElementById('filterPrinter').checked = false;
        document.getElementById('filterTv').checked = false;
        document.getElementById('filterGaming').checked = false;
        document.getElementById('filterPhone').checked = false;
        document.getElementById('filterVirtualization').checked = false;
        document.getElementById('filterSoundbar').checked = false;
        document.getElementById('filterAppliance').checked = false;
        document.getElementById('filterOther').checked = false;
        App.Filters.apply();
    };

    /**
     * Select only the specified filter (uncheck all others)
     */
    App.Filters.selectOnly = function(filterId) {
        document.getElementById('filterLocal').checked = false;
        document.getElementById('filterGateway').checked = false;
        document.getElementById('filterPrinter').checked = false;
        document.getElementById('filterTv').checked = false;
        document.getElementById('filterGaming').checked = false;
        document.getElementById('filterPhone').checked = false;
        document.getElementById('filterVirtualization').checked = false;
        document.getElementById('filterSoundbar').checked = false;
        document.getElementById('filterAppliance').checked = false;
        document.getElementById('filterOther').checked = false;

        var checkbox = document.getElementById(filterId);
        if (checkbox) {
            checkbox.checked = true;
        }

        App.Filters.apply();
    };

    /**
     * Handle filter checkbox click - supports Alt+click to select only
     */
    App.Filters.handleClick = function(event, filterId) {
        if (event.altKey) {
            event.preventDefault();
            event.stopPropagation();
            App.Filters.selectOnly(filterId);
        }
    };

    /**
     * Load all protocols into the global protocol dropdown
     */
    App.Filters.loadGlobalProtocols = function() {
        var select = document.getElementById('globalProtocolSelect');
        if (!select) return;

        fetch('/api/protocols')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                select.innerHTML = '<option value="">All Protocols</option>';

                if (data.protocols && data.protocols.length > 0) {
                    data.protocols.forEach(function(protocol) {
                        var option = document.createElement('option');
                        option.value = protocol;
                        option.textContent = protocol;
                        select.appendChild(option);
                    });
                }
            })
            .catch(function(err) {
                console.error('Failed to load protocols:', err);
            });
    };

    /**
     * Filter endpoints by global protocol selection
     */
    App.Filters.filterByGlobalProtocol = function(protocol) {
        App.state.selectedProtocol = protocol || null;

        var url = new URL(window.location.href);
        if (protocol) {
            url.searchParams.set('filter_protocol', protocol);
        } else {
            url.searchParams.delete('filter_protocol');
        }
        window.history.replaceState({}, '', url);

        if (!protocol) {
            App.Filters.apply();
            return;
        }

        fetch('/api/protocol/' + encodeURIComponent(protocol) + '/endpoints')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                var protocolEndpoints = new Set(data.endpoints || []);

                var rows = document.querySelectorAll('#endpoints-table tbody tr');
                rows.forEach(function(row) {
                    var endpointName = row.dataset.endpointName;
                    if (protocolEndpoints.has(endpointName)) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            })
            .catch(function(err) {
                console.error('Failed to filter by protocol:', err);
            });
    };

    /**
     * Filter endpoints by vendor
     */
    App.Filters.filterByVendor = function(vendor) {
        App.state.selectedVendor = vendor || null;

        var url = new URL(window.location.href);
        if (vendor) {
            url.searchParams.set('filter_vendor', vendor);
        } else {
            url.searchParams.delete('filter_vendor');
        }
        window.history.replaceState({}, '', url);

        App.Filters.apply();
    };

})();
