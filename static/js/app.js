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

        // Restore endpoint search from URL
        var searchValue = urlParams.get('search');
        if (searchValue) {
            var searchInput = document.getElementById('endpointSearch');
            if (searchInput) {
                searchInput.value = searchValue;
            }
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

        // Apply filters on page load
        if (App.Filters) {
            App.Filters.apply(true);
        }

        // Initialize table sorting
        App.initTableSorting();

        // Initialize refresh interval
        if (App.Refresh) {
            App.Refresh.init();
        }
    });

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
    };

})(window.App);
