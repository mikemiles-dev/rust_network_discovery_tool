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
         * Select home device type filters (local devices you'd find in a home)
         */
        selectHome: function() {
            document.getElementById('filterLocal').checked = false;
            document.getElementById('filterGateway').checked = false;
            document.getElementById('filterInternet').checked = false;
            document.getElementById('filterPrinter').checked = true;
            document.getElementById('filterTv').checked = true;
            document.getElementById('filterGaming').checked = true;
            document.getElementById('filterPhone').checked = true;
            document.getElementById('filterVirtualization').checked = false;
            document.getElementById('filterSoundbar').checked = true;
            document.getElementById('filterAppliance').checked = true;
            document.getElementById('filterOther').checked = false;
            App.Filters.apply();
        },

        /**
         * Select only the specified filter (uncheck all others)
         */
        selectOnly: function(filterId) {
            // Uncheck all filters first
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

            // Check only the specified filter
            var checkbox = document.getElementById(filterId);
            if (checkbox) {
                checkbox.checked = true;
            }

            App.Filters.apply();
        },

        /**
         * Handle filter checkbox click - supports Alt+click to select only
         */
        handleClick: function(event, filterId) {
            if (event.altKey) {
                event.preventDefault();
                event.stopPropagation();
                App.Filters.selectOnly(filterId);
            }
            // Normal click is handled by the checkbox's onchange
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

                // Apply vendor filter if selected
                var shouldShowByVendor = true;
                if (App.state.selectedVendor) {
                    var rowVendor = (row.dataset.endpointVendor || '').toLowerCase();
                    shouldShowByVendor = rowVendor === App.state.selectedVendor.toLowerCase();
                }

                // Set filtered-out attribute for pagination to use
                var isFilteredOut = !(shouldShowByType && shouldShowBySearch && shouldShowByVendor);
                row.dataset.filteredOut = isFilteredOut ? 'true' : 'false';
            });

            // Remove filters-pending class to show rows (prevents flash of unfiltered content)
            document.body.classList.remove('filters-pending');

            // Update pagination after filtering
            if (App.Pagination) {
                App.Pagination.resetToFirstPage('endpoints');
            }

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
         * Show dropdown with all endpoints using this protocol
         */
        filterByProtocol: function(protocol, element) {
            // Toggle - if clicking the same protocol, hide dropdown
            if (element.classList.contains('selected')) {
                element.classList.remove('selected');
                App.Filters.hideProtocolDropdown();
                return;
            }

            // Clear previous selection
            document.querySelectorAll('#protocols-container .protocol-badge').forEach(function(badge) {
                badge.classList.remove('selected');
            });

            // Select this protocol
            element.classList.add('selected');

            // Show the protocol endpoints dropdown
            App.Filters.showProtocolDropdown(protocol, element);
        },

        /**
         * Show dropdown with endpoints using this protocol
         */
        showProtocolDropdown: function(protocol, element) {
            var dropdown = document.getElementById('protocol-dropdown');
            var content = document.getElementById('protocol-dropdown-content');
            var nameSpan = document.getElementById('protocol-dropdown-name');

            if (!dropdown || !content) return;

            // Set protocol name in header
            nameSpan.textContent = protocol;

            // Show loading state
            content.innerHTML = '<div class="protocol-dropdown-loading">Loading...</div>';

            // Position the dropdown near the clicked element
            var rect = element.getBoundingClientRect();
            dropdown.style.left = rect.left + 'px';
            dropdown.style.top = (rect.bottom + 4) + 'px';

            // Make sure dropdown doesn't go off screen
            dropdown.classList.add('show');
            var dropdownRect = dropdown.getBoundingClientRect();
            if (dropdownRect.right > window.innerWidth) {
                dropdown.style.left = (window.innerWidth - dropdownRect.width - 10) + 'px';
            }
            if (dropdownRect.bottom > window.innerHeight) {
                dropdown.style.top = (rect.top - dropdownRect.height - 4) + 'px';
            }

            // Get scan interval and current endpoint from URL
            var urlParams = new URLSearchParams(window.location.search);
            var scanInterval = urlParams.get('scan_interval') || '60';
            var currentEndpoint = urlParams.get('node') || '';

            // Fetch endpoints that THIS endpoint communicated with over this protocol
            var apiUrl = '/api/protocol/' + encodeURIComponent(protocol) + '/endpoints?scan_interval=' + scanInterval;
            if (currentEndpoint) {
                apiUrl += '&from_endpoint=' + encodeURIComponent(currentEndpoint);
            }

            fetch(apiUrl)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (data.endpoints && data.endpoints.length > 0) {
                        content.innerHTML = data.endpoints.map(function(endpoint) {
                            return '<div class="protocol-dropdown-item" onclick="App.Filters.selectEndpointFromDropdown(\'' + endpoint.replace(/'/g, "\\'") + '\')">' + endpoint + '</div>';
                        }).join('');
                    } else {
                        content.innerHTML = '<div class="protocol-dropdown-empty">No endpoints found</div>';
                    }
                })
                .catch(function(err) {
                    content.innerHTML = '<div class="protocol-dropdown-empty">Error loading endpoints</div>';
                });
        },

        /**
         * Hide the protocol dropdown
         */
        hideProtocolDropdown: function() {
            var dropdown = document.getElementById('protocol-dropdown');
            if (dropdown) {
                dropdown.classList.remove('show');
            }
        },

        /**
         * Select an endpoint from the protocol dropdown
         */
        selectEndpointFromDropdown: function(endpoint) {
            // Navigate to the endpoint
            var urlParams = new URLSearchParams(window.location.search);
            urlParams.set('node', endpoint);
            window.location.search = urlParams.toString();
        },

        /**
         * Clear protocol selection and hide dropdown
         */
        clearProtocolFilter: function() {
            // Remove selection from all protocols
            document.querySelectorAll('#protocols-container .protocol-badge').forEach(function(badge) {
                badge.classList.remove('selected');
            });

            // Hide dropdown
            App.Filters.hideProtocolDropdown();
        },

        /**
         * Load all protocols into the global protocol dropdown
         */
        loadGlobalProtocols: function() {
            var select = document.getElementById('globalProtocolSelect');
            if (!select) return;

            var urlParams = new URLSearchParams(window.location.search);
            var scanInterval = urlParams.get('scan_interval') || '60';

            fetch('/api/protocols?scan_interval=' + scanInterval)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    // Keep the first "All Protocols" option
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
        },

        /**
         * Filter endpoints by global protocol selection
         * Shows only endpoints that use the selected protocol
         */
        filterByGlobalProtocol: function(protocol) {
            App.state.selectedProtocol = protocol || null;

            // Save protocol to URL
            var url = new URL(window.location.href);
            if (protocol) {
                url.searchParams.set('filter_protocol', protocol);
            } else {
                url.searchParams.delete('filter_protocol');
            }
            window.history.replaceState({}, '', url);

            if (!protocol) {
                // Clear filter - show all endpoints
                App.Filters.apply();
                return;
            }

            var urlParams = new URLSearchParams(window.location.search);
            var scanInterval = urlParams.get('scan_interval') || '60';

            // Fetch all endpoints using this protocol
            fetch('/api/protocol/' + encodeURIComponent(protocol) + '/endpoints?scan_interval=' + scanInterval)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var protocolEndpoints = new Set(data.endpoints || []);

                    // Filter the endpoint rows
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
        },

        /**
         * Filter endpoints by vendor
         */
        filterByVendor: function(vendor) {
            App.state.selectedVendor = vendor || null;

            // Save vendor to URL
            var url = new URL(window.location.href);
            if (vendor) {
                url.searchParams.set('filter_vendor', vendor);
            } else {
                url.searchParams.delete('filter_vendor');
            }
            window.history.replaceState({}, '', url);

            // Apply filters with vendor constraint
            App.Filters.apply();
        }
    };

    // Expose functions globally for onclick handlers
    window.applyFilters = App.Filters.apply;
    window.selectAllFilters = App.Filters.selectAll;
    window.selectNoneFilters = App.Filters.selectNone;
    window.selectLocalFilters = App.Filters.selectLocal;
    window.selectHomeFilters = App.Filters.selectHome;
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

    // Load global protocols on page load
    document.addEventListener('DOMContentLoaded', function() {
        App.Filters.loadGlobalProtocols();
    });

})(window.App);
