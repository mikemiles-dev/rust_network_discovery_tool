/**
 * App Module - Main initialization
 * Ties all modules together and handles DOMContentLoaded
 */
(function(App) {
    'use strict';

    App.init = function(config) {
        // Set endpoint name for classification module if provided
        if (config && config.endpointName && App.Classification) {
            App.Classification.setEndpointName(config.endpointName);
        }

        // Setup classification dropdown close handler
        if (App.Classification) {
            App.Classification.setupDropdownClose();
        }

        // Setup protocol dropdown close handler (click outside to close)
        document.addEventListener('click', function(e) {
            var dropdown = document.getElementById('protocol-dropdown');
            if (dropdown && dropdown.classList.contains('show')) {
                // Check if click is outside dropdown and not on a protocol badge
                if (!dropdown.contains(e.target) && !e.target.classList.contains('protocol-badge')) {
                    if (App.Filters && App.Filters.hideProtocolDropdown) {
                        App.Filters.hideProtocolDropdown();
                    }
                }
            }
        });

        // Check scan capabilities on load
        if (App.Scanner) {
            App.Scanner.checkCapabilities();
        }

        // Apply filters on page load
        if (App.Filters) {
            App.Filters.apply(true);
        }
    };

    // DOMContentLoaded handler
    document.addEventListener('DOMContentLoaded', function() {
        // Restore tab from URL parameter
        var urlParams = new URLSearchParams(window.location.search);
        var tabParam = urlParams.get('tab');
        if (tabParam && App.Tabs) {
            // Find the tab button and simulate click
            var tabBtn = document.querySelector('.tab-btn[onclick*="' + tabParam + '"]');
            if (tabBtn) {
                App.Tabs.switchTab(tabParam, { target: tabBtn });
            }
        }

        // Format byte displays
        var bytesInElem = document.getElementById('bytes-in');
        var bytesOutElem = document.getElementById('bytes-out');

        if (bytesInElem && App.Formatting) {
            var bytesIn = parseInt(bytesInElem.textContent);
            if (!isNaN(bytesIn)) {
                bytesInElem.textContent = App.Formatting.formatBytes(bytesIn);
            }
        }

        if (bytesOutElem && App.Formatting) {
            var bytesOut = parseInt(bytesOutElem.textContent);
            if (!isNaN(bytesOut)) {
                bytesOutElem.textContent = App.Formatting.formatBytes(bytesOut);
            }
        }

        // Format endpoint bytes in the list
        document.querySelectorAll('.endpoint-bytes').forEach(function(elem) {
            var bytes = parseInt(elem.textContent);
            if (!isNaN(bytes) && bytes > 0 && App.Formatting) {
                elem.textContent = App.Formatting.formatBytes(bytes);
            }
        });

        // Restore filter states from URL
        var urlParams = new URLSearchParams(window.location.search);

        var filterLocal = urlParams.get('filter_local');
        var filterGateway = urlParams.get('filter_gateway');
        var filterInternet = urlParams.get('filter_internet');
        var filterPrinter = urlParams.get('filter_printer');
        var filterTv = urlParams.get('filter_tv');
        var filterGaming = urlParams.get('filter_gaming');
        var filterPhone = urlParams.get('filter_phone');
        var filterVirtualization = urlParams.get('filter_virtualization');
        var filterSoundbar = urlParams.get('filter_soundbar');
        var filterAppliance = urlParams.get('filter_appliance');
        var filterOther = urlParams.get('filter_other');

        // Set checkbox states (default to checked if not specified)
        var checkboxes = {
            'filterLocal': filterLocal,
            'filterGateway': filterGateway,
            'filterInternet': filterInternet,
            'filterPrinter': filterPrinter,
            'filterTv': filterTv,
            'filterGaming': filterGaming,
            'filterPhone': filterPhone,
            'filterVirtualization': filterVirtualization,
            'filterSoundbar': filterSoundbar,
            'filterAppliance': filterAppliance,
            'filterOther': filterOther
        };

        for (var id in checkboxes) {
            var checkbox = document.getElementById(id);
            var value = checkboxes[id];
            if (checkbox && value !== null) {
                checkbox.checked = value === '1';
            }
        }

        // Restore endpoint search from URL and autofocus
        var searchValue = urlParams.get('search');
        var searchInput = document.getElementById('endpointSearch');
        if (searchInput) {
            if (searchValue) {
                searchInput.value = searchValue;
            }
            // Autofocus the search input
            searchInput.focus();
        }

        // Restore right pane search filters from URL
        var filterHostnamesValue = urlParams.get('filter_hostnames');
        var filterPortsValue = urlParams.get('filter_ports');
        var filterIpsValue = urlParams.get('filter_ips');
        var filterMacsValue = urlParams.get('filter_macs');

        if (filterHostnamesValue && App.Filters) {
            var hostnamesInput = document.getElementById('hostnamesListSearch');
            if (hostnamesInput) {
                hostnamesInput.value = filterHostnamesValue;
                App.Filters.filterHostnamesList(filterHostnamesValue, true);
            }
        }

        if (filterPortsValue && App.Filters) {
            var portsInput = document.getElementById('portsListSearch');
            if (portsInput) {
                portsInput.value = filterPortsValue;
                App.Filters.filterPortsList(filterPortsValue, true);
            }
        }

        if (filterIpsValue && App.Filters) {
            var ipsInput = document.getElementById('ipsListSearch');
            if (ipsInput) {
                ipsInput.value = filterIpsValue;
                App.Filters.filterIpsList(filterIpsValue, true);
            }
        }

        if (filterMacsValue && App.Filters) {
            var macsInput = document.getElementById('macsListSearch');
            if (macsInput) {
                macsInput.value = filterMacsValue;
                App.Filters.filterMacsList(filterMacsValue, true);
            }
        }

        // Restore vendor filter from URL
        var filterVendorValue = urlParams.get('filter_vendor');
        if (filterVendorValue) {
            App.state.selectedVendor = filterVendorValue;
            var vendorSelect = document.getElementById('globalVendorSelect');
            if (vendorSelect) {
                vendorSelect.value = filterVendorValue;
            }
        }

        // Restore protocol filter from URL
        var filterProtocolValue = urlParams.get('filter_protocol');
        if (filterProtocolValue) {
            App.state.selectedProtocol = filterProtocolValue;
            var protocolSelect = document.getElementById('globalProtocolSelect');
            if (protocolSelect) {
                // Protocol options are loaded async, so set value after a short delay
                setTimeout(function() {
                    protocolSelect.value = filterProtocolValue;
                    // Apply the protocol filter
                    if (App.Filters) {
                        App.Filters.filterByGlobalProtocol(filterProtocolValue);
                    }
                }, 100);
            }
        }

        // Apply filters on page load
        if (App.Filters) {
            App.Filters.apply(true);
        }

        // Initialize table sorting
        App.initTableSorting();

        // Restore sort state from URL params
        App.restoreSortState();

        // Initialize pagination for both tables
        if (App.Pagination) {
            App.Pagination.init('endpoints');
            App.Pagination.init('mdns');

            // Restore pagination state from URL params
            App.restorePaginationState();
        }

        // Initialize refresh interval
        if (App.Refresh) {
            App.Refresh.init();
        }

        // Restore scroll positions after refresh
        var savedScroll = sessionStorage.getItem('scrollPosition');
        var savedTableScroll = sessionStorage.getItem('tableScrollPosition');
        var savedDetailsScroll = sessionStorage.getItem('detailsScrollPosition');
        if (savedScroll || savedTableScroll || savedDetailsScroll) {
            sessionStorage.removeItem('scrollPosition');
            sessionStorage.removeItem('tableScrollPosition');
            sessionStorage.removeItem('detailsScrollPosition');
            // Delay to ensure DOM is fully rendered and all other init is complete
            setTimeout(function() {
                if (savedScroll) {
                    window.scrollTo(0, parseInt(savedScroll, 10));
                }
                if (savedTableScroll) {
                    var tableWrapper = document.querySelector('.endpoints-table-wrapper');
                    if (tableWrapper) {
                        tableWrapper.scrollTop = parseInt(savedTableScroll, 10);
                    }
                }
                if (savedDetailsScroll) {
                    var detailsPane = document.querySelector('.protocols-overlay');
                    if (detailsPane) {
                        detailsPane.scrollTop = parseInt(savedDetailsScroll, 10);
                    }
                }
            }, 150);
        }
    });

    /**
     * Parse "last seen" text into seconds for sorting
     * @param {string} text - Text like "Just now", "5 min ago", "2 hours ago"
     * @returns {number} Seconds ago (lower = more recent)
     */
    function parseLastSeen(text) {
        if (!text || text === '-') return Infinity;
        text = text.trim().toLowerCase();
        if (text === 'just now') return 0;

        var match = text.match(/(\d+)\s*(min|hour|day|sec)/);
        if (match) {
            var num = parseInt(match[1], 10);
            var unit = match[2];
            if (unit.startsWith('sec')) return num;
            if (unit.startsWith('min')) return num * 60;
            if (unit.startsWith('hour')) return num * 3600;
            if (unit.startsWith('day')) return num * 86400;
        }
        return Infinity;
    }

    // Table sorting functionality
    App.initTableSorting = function() {
        var table = document.getElementById('endpoints-table');
        if (!table) return;

        var headers = table.querySelectorAll('th.sortable');
        headers.forEach(function(header) {
            header.addEventListener('click', function() {
                var sortKey = header.dataset.sort;
                var isAsc = header.classList.contains('sorted-asc');

                headers.forEach(function(h) {
                    h.classList.remove('sorted-asc', 'sorted-desc');
                });

                if (isAsc) {
                    header.classList.add('sorted-desc');
                    App.sortTable(sortKey, false);
                } else {
                    header.classList.add('sorted-asc');
                    App.sortTable(sortKey, true);
                }
            });
        });
    };

    App.sortTable = function(sortKey, ascending) {
        var table = document.getElementById('endpoints-table');
        if (!table) return;

        var tbody = table.querySelector('tbody');
        var rows = Array.from(tbody.querySelectorAll('tr'));

        rows.sort(function(a, b) {
            var aVal, bVal;

            switch (sortKey) {
                case 'type':
                    aVal = a.dataset.endpointType || '';
                    bVal = b.dataset.endpointType || '';
                    break;
                case 'name':
                    aVal = (a.querySelector('.endpoint-name-cell')?.textContent || '').toLowerCase();
                    bVal = (b.querySelector('.endpoint-name-cell')?.textContent || '').toLowerCase();
                    break;
                case 'vendor':
                    aVal = (a.querySelector('.vendor-cell')?.textContent || '').toLowerCase();
                    bVal = (b.querySelector('.vendor-cell')?.textContent || '').toLowerCase();
                    break;
                case 'model':
                    aVal = (a.querySelector('.model-cell')?.textContent || '').toLowerCase();
                    bVal = (b.querySelector('.model-cell')?.textContent || '').toLowerCase();
                    break;
                case 'bandwidth':
                    aVal = parseInt(a.dataset.endpointBytes, 10) || 0;
                    bVal = parseInt(b.dataset.endpointBytes, 10) || 0;
                    return ascending ? aVal - bVal : bVal - aVal;
                case 'last_seen':
                    // Parse "Just now", "X min ago", "X hours ago" etc
                    aVal = parseLastSeen(a.querySelector('.last-seen-cell')?.textContent || '');
                    bVal = parseLastSeen(b.querySelector('.last-seen-cell')?.textContent || '');
                    return ascending ? aVal - bVal : bVal - aVal;
                default:
                    aVal = '';
                    bVal = '';
            }

            if (aVal < bVal) return ascending ? -1 : 1;
            if (aVal > bVal) return ascending ? 1 : -1;
            return 0;
        });

        rows.forEach(function(row) {
            tbody.appendChild(row);
        });

        // Reset pagination to first page after sorting (but not when restoring from URL)
        if (App.Pagination && !App.state.restoringState) {
            App.Pagination.resetToFirstPage('endpoints');
        }
    };

    /**
     * Restore sort state from URL parameters
     */
    App.restoreSortState = function() {
        var urlParams = new URLSearchParams(window.location.search);
        var sortKey = urlParams.get('sort');
        var sortDir = urlParams.get('sort_dir');

        if (sortKey) {
            var table = document.getElementById('endpoints-table');
            if (!table) return;

            var headers = table.querySelectorAll('th.sortable');
            var targetHeader = null;

            headers.forEach(function(header) {
                header.classList.remove('sorted-asc', 'sorted-desc');
                if (header.dataset.sort === sortKey) {
                    targetHeader = header;
                }
            });

            if (targetHeader) {
                var ascending = sortDir !== 'desc';
                targetHeader.classList.add(ascending ? 'sorted-asc' : 'sorted-desc');

                // Set flag to prevent pagination reset during restore
                App.state.restoringState = true;
                App.sortTable(sortKey, ascending);
                App.state.restoringState = false;
            }
        }
    };

    /**
     * Restore pagination state from URL parameters
     */
    App.restorePaginationState = function() {
        var urlParams = new URLSearchParams(window.location.search);
        var page = urlParams.get('page');
        var pageSize = urlParams.get('page_size');

        if (pageSize && App.Pagination) {
            var select = document.getElementById('endpoints-page-size');
            if (select) {
                select.value = pageSize;
                App.Pagination.changePageSize('endpoints', pageSize);
            }
        }

        if (page && App.Pagination) {
            var pageNum = parseInt(page, 10);
            if (pageNum > 1) {
                App.Pagination.goToPage('endpoints', pageNum, { skipScroll: true });
            }
        }
    };

})(window.App);
