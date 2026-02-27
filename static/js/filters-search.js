/**
 * Filters Search Module - Right-pane search and protocol/port/vendor filtering
 */
(function() {
    'use strict';

    App.Filters = App.Filters || {};

    /**
     * Filter hostnames list in right pane
     */
    App.Filters.filterHostnamesList = function(searchTerm, skipUrlUpdate) {
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
    };

    /**
     * Filter ports list in right pane
     */
    App.Filters.filterPortsList = function(searchTerm, skipUrlUpdate) {
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
    };

    /**
     * Filter IPs list in right pane
     */
    App.Filters.filterIpsList = function(searchTerm, skipUrlUpdate) {
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
    };

    /**
     * Filter MACs list in right pane
     */
    App.Filters.filterMacsList = function(searchTerm, skipUrlUpdate) {
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
    };

    /**
     * Show dropdown with all endpoints using this protocol
     */
    App.Filters.filterByProtocol = function(protocol, element) {
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
    };

    /**
     * Show dropdown with endpoints using this protocol
     */
    App.Filters.showProtocolDropdown = function(protocol, element) {
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

        // Get current endpoint from URL
        var urlParams = new URLSearchParams(window.location.search);
        var currentEndpoint = urlParams.get('node') || '';

        // Fetch endpoints that THIS endpoint communicated with over this protocol
        var apiUrl = '/api/protocol/' + encodeURIComponent(protocol) + '/endpoints';
        if (currentEndpoint) {
            apiUrl += '?from_endpoint=' + encodeURIComponent(currentEndpoint);
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
    };

    /**
     * Hide the protocol dropdown
     */
    App.Filters.hideProtocolDropdown = function() {
        var dropdown = document.getElementById('protocol-dropdown');
        if (dropdown) {
            dropdown.classList.remove('show');
        }
    };

    /**
     * Select an endpoint from the protocol dropdown
     */
    App.Filters.selectEndpointFromDropdown = function(endpoint) {
        var urlParams = new URLSearchParams(window.location.search);
        urlParams.set('node', endpoint);
        window.location.search = urlParams.toString();
    };

    /**
     * Clear protocol selection and hide dropdown
     */
    App.Filters.clearProtocolFilter = function() {
        document.querySelectorAll('#protocols-container .protocol-badge').forEach(function(badge) {
            badge.classList.remove('selected');
        });
        App.Filters.hideProtocolDropdown();
    };

    /**
     * Filter by port - highlights port and filters communications table
     */
    App.Filters.filterByPort = function(port, element) {
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
    };

    /**
     * Clear port filter
     */
    App.Filters.clearPortFilter = function() {
        document.querySelectorAll('#ports-container .listbox-item').forEach(function(item) {
            item.classList.remove('selected');
        });
        var clearBtn = document.querySelector('.clear-port-filter-btn');
        if (clearBtn) clearBtn.style.display = 'none';
        var commRows = document.querySelectorAll('.communication-row');
        commRows.forEach(function(row) {
            row.style.display = '';
        });
    };

})();
