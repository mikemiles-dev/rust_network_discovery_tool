/**
 * Filters Module - Type filtering for endpoints table
 */
(function(App) {
    'use strict';

    App.Filters = {
        /**
         * Check if an IP is on the local network (private IP ranges)
         */
        isLocalIP: function(ip) {
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
        },

        /**
         * Select all device type filters
         */
        selectAll: function() {
            document.getElementById('filterLocal').checked = true;
            document.getElementById('filterGateway').checked = true;
            document.getElementById('filterInternet').checked = true;
            document.getElementById('filterPrinter').checked = true;
            document.getElementById('filterTv').checked = true;
            document.getElementById('filterGaming').checked = true;
            document.getElementById('filterPhone').checked = true;
            document.getElementById('filterVirtualization').checked = true;
            document.getElementById('filterSoundbar').checked = true;
            document.getElementById('filterAppliance').checked = true;
            document.getElementById('filterOther').checked = true;
            App.Filters.apply();
        },

        /**
         * Deselect all device type filters
         */
        selectNone: function() {
            document.getElementById('filterLocal').checked = false;
            document.getElementById('filterGateway').checked = false;
            document.getElementById('filterInternet').checked = false;
            document.getElementById('filterPrinter').checked = false;
            document.getElementById('filterTv').checked = false;
            document.getElementById('filterGaming').checked = false;
            document.getElementById('filterPhone').checked = false;
            document.getElementById('filterVirtualization').checked = false;
            document.getElementById('filterSoundbar').checked = false;
            document.getElementById('filterAppliance').checked = false;
            document.getElementById('filterOther').checked = false;
            App.Filters.apply();
        },

        /**
         * Select all local device type filters (everything except internet)
         */
        selectLocal: function() {
            document.getElementById('filterLocal').checked = true;
            document.getElementById('filterGateway').checked = true;
            document.getElementById('filterInternet').checked = false;
            document.getElementById('filterPrinter').checked = true;
            document.getElementById('filterTv').checked = true;
            document.getElementById('filterGaming').checked = true;
            document.getElementById('filterPhone').checked = true;
            document.getElementById('filterVirtualization').checked = true;
            document.getElementById('filterSoundbar').checked = true;
            document.getElementById('filterAppliance').checked = true;
            document.getElementById('filterOther').checked = true;
            App.Filters.apply();
        },

        /**
         * Apply filters to table rows
         */
        apply: function(skipUrlUpdate) {
            // Get filter checkbox states
            var showLocal = document.getElementById('filterLocal')?.checked ?? true;
            var showGateway = document.getElementById('filterGateway')?.checked ?? true;
            var showInternet = document.getElementById('filterInternet')?.checked ?? true;
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

            // Save filter state to URL
            if (!skipUrlUpdate) {
                var url = new URL(window.location.href);
                url.searchParams.set('filter_local', showLocal ? '1' : '0');
                url.searchParams.set('filter_gateway', showGateway ? '1' : '0');
                url.searchParams.set('filter_internet', showInternet ? '1' : '0');
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
                else if (rowType === 'internet' && showInternet) shouldShowByType = true;
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

                row.style.display = (shouldShowByType && shouldShowBySearch) ? '' : 'none';
            });

            // Remove filters-pending class to show rows (prevents flash of unfiltered content)
            document.body.classList.remove('filters-pending');

            // Filter IPs in endpoint details based on internet filter
            if (!showInternet) {
                var ipItems = document.querySelectorAll('#ips-container .hostname-item');
                ipItems.forEach(function(item) {
                    var ip = item.textContent.trim();
                    if (!App.Filters.isLocalIP(ip)) {
                        item.style.display = 'none';
                    } else {
                        item.style.display = 'block';
                    }
                });
            } else {
                var ipItems = document.querySelectorAll('#ips-container .hostname-item');
                ipItems.forEach(function(item) {
                    item.style.display = 'block';
                });
            }
        },

        /**
         * Filter hostnames list in right pane
         */
        filterHostnamesList: function(searchTerm, skipUrlUpdate) {
            var normalizedSearch = searchTerm.trim().toLowerCase();
            var hostnameItems = document.querySelectorAll('#hostnames-container .listbox-item');

            if (!skipUrlUpdate) {
                var url = new URL(window.location.href);
                if (normalizedSearch) {
                    url.searchParams.set('filter_hostnames', searchTerm);
                } else {
                    url.searchParams.delete('filter_hostnames');
                }
                window.history.replaceState({}, '', url);
            }

            hostnameItems.forEach(function(item) {
                var hostname = item.textContent.toLowerCase();
                if (normalizedSearch === '' || hostname.includes(normalizedSearch)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        },

        /**
         * Filter ports list in right pane
         */
        filterPortsList: function(searchTerm, skipUrlUpdate) {
            var normalizedSearch = searchTerm.trim().toLowerCase();
            var portItems = document.querySelectorAll('#ports-container .listbox-item');

            if (!skipUrlUpdate) {
                var url = new URL(window.location.href);
                if (normalizedSearch) {
                    url.searchParams.set('filter_ports', searchTerm);
                } else {
                    url.searchParams.delete('filter_ports');
                }
                window.history.replaceState({}, '', url);
            }

            portItems.forEach(function(item) {
                var port = item.textContent.toLowerCase();
                if (normalizedSearch === '' || port.includes(normalizedSearch)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        },

        /**
         * Filter IPs list in right pane
         */
        filterIpsList: function(searchTerm, skipUrlUpdate) {
            var normalizedSearch = searchTerm.trim().toLowerCase();
            var ipItems = document.querySelectorAll('#ips-container .hostname-item');

            if (!skipUrlUpdate) {
                var url = new URL(window.location.href);
                if (normalizedSearch) {
                    url.searchParams.set('filter_ips', searchTerm);
                } else {
                    url.searchParams.delete('filter_ips');
                }
                window.history.replaceState({}, '', url);
            }

            ipItems.forEach(function(item) {
                var ip = item.textContent.toLowerCase();
                if (normalizedSearch === '' || ip.includes(normalizedSearch)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        },

        /**
         * Filter MACs list in right pane
         */
        filterMacsList: function(searchTerm, skipUrlUpdate) {
            var normalizedSearch = searchTerm.trim().toLowerCase();
            var macItems = document.querySelectorAll('#macs-container .hostname-item');

            if (!skipUrlUpdate) {
                var url = new URL(window.location.href);
                if (normalizedSearch) {
                    url.searchParams.set('filter_macs', searchTerm);
                } else {
                    url.searchParams.delete('filter_macs');
                }
                window.history.replaceState({}, '', url);
            }

            macItems.forEach(function(item) {
                var mac = item.textContent.toLowerCase();
                if (normalizedSearch === '' || mac.includes(normalizedSearch)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        },

        /**
         * Filter by protocol - highlights protocol and filters communications table
         */
        filterByProtocol: function(protocol, element) {
            // Toggle selection
            if (element.classList.contains('selected')) {
                App.Filters.clearProtocolFilter();
                return;
            }

            // Clear previous selection
            document.querySelectorAll('#protocols-container .protocol-badge').forEach(function(badge) {
                badge.classList.remove('selected');
            });

            // Select this protocol
            element.classList.add('selected');

            // Show the clear button
            var clearBtn = document.querySelector('.clear-filter-btn');
            if (clearBtn) clearBtn.style.display = '';

            // Filter communications table by protocol if it exists
            var commRows = document.querySelectorAll('.communication-row');
            commRows.forEach(function(row) {
                var rowProtocol = row.dataset.protocol;
                if (rowProtocol === protocol) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        },

        /**
         * Clear protocol filter
         */
        clearProtocolFilter: function() {
            // Remove selection from all protocols
            document.querySelectorAll('#protocols-container .protocol-badge').forEach(function(badge) {
                badge.classList.remove('selected');
            });

            // Hide the clear button
            var clearBtn = document.querySelector('.clear-filter-btn');
            if (clearBtn) clearBtn.style.display = 'none';

            // Show all communications
            var commRows = document.querySelectorAll('.communication-row');
            commRows.forEach(function(row) {
                row.style.display = '';
            });
        },

        /**
         * Filter by port - highlights port and filters communications table
         */
        filterByPort: function(port, element) {
            // Toggle selection
            if (element.classList.contains('selected')) {
                App.Filters.clearPortFilter();
                return;
            }

            // Clear previous selection
            document.querySelectorAll('#ports-container .listbox-item').forEach(function(item) {
                item.classList.remove('selected');
            });

            // Select this port
            element.classList.add('selected');

            // Show the clear button
            var clearBtn = document.querySelector('.clear-port-filter-btn');
            if (clearBtn) clearBtn.style.display = '';

            // Filter communications table by port if it exists
            var commRows = document.querySelectorAll('.communication-row');
            commRows.forEach(function(row) {
                var rowSrcPort = row.dataset.srcPort;
                var rowDstPort = row.dataset.dstPort;
                if (rowSrcPort === port || rowDstPort === port) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        },

        /**
         * Clear port filter
         */
        clearPortFilter: function() {
            // Remove selection from all ports
            document.querySelectorAll('#ports-container .listbox-item').forEach(function(item) {
                item.classList.remove('selected');
            });

            // Hide the clear button
            var clearBtn = document.querySelector('.clear-port-filter-btn');
            if (clearBtn) clearBtn.style.display = 'none';

            // Show all communications
            var commRows = document.querySelectorAll('.communication-row');
            commRows.forEach(function(row) {
                row.style.display = '';
            });
        }
    };

    // Expose functions globally for onclick handlers
    window.applyFilters = App.Filters.apply;
    window.selectAllFilters = App.Filters.selectAll;
    window.selectNoneFilters = App.Filters.selectNone;
    window.selectLocalFilters = App.Filters.selectLocal;
    window.filterHostnamesList = App.Filters.filterHostnamesList;
    window.filterPortsList = App.Filters.filterPortsList;
    window.filterIpsList = App.Filters.filterIpsList;
    window.filterMacsList = App.Filters.filterMacsList;
    window.isLocalIP = App.Filters.isLocalIP;
    window.filterByProtocol = App.Filters.filterByProtocol;
    window.clearProtocolFilter = App.Filters.clearProtocolFilter;
    window.filterByPort = App.Filters.filterByPort;
    window.clearPortFilter = App.Filters.clearPortFilter;

})(window.App);
