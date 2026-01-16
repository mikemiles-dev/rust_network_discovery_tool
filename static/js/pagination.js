/**
 * Pagination Module - Handles table pagination for endpoints and mDNS tables
 */
(function(App) {
    'use strict';

    // Pagination state for each table
    var state = {
        endpoints: {
            currentPage: 1,
            pageSize: 25,
            totalRows: 0,
            visibleRows: 0
        },
        mdns: {
            currentPage: 1,
            pageSize: 50,
            totalRows: 0,
            visibleRows: 0
        }
    };

    App.Pagination = {
        /**
         * Initialize pagination for a table
         * @param {string} tableType - 'endpoints' or 'mdns'
         */
        init: function(tableType) {
            var config = getTableConfig(tableType);
            if (!config) return;

            var tbody = document.querySelector(config.tableSelector + ' tbody');
            if (!tbody) return;

            var rows = tbody.querySelectorAll('tr:not(.empty-row)');
            state[tableType].totalRows = rows.length;
            state[tableType].visibleRows = rows.length;
            state[tableType].currentPage = 1;

            this.update(tableType);
        },

        /**
         * Update pagination display and row visibility
         * @param {string} tableType - 'endpoints' or 'mdns'
         */
        update: function(tableType) {
            var config = getTableConfig(tableType);
            if (!config) return;

            var tbody = document.querySelector(config.tableSelector + ' tbody');
            if (!tbody) return;

            var allRows = tbody.querySelectorAll('tr:not(.empty-row)');
            var pageState = state[tableType];

            // Count visible rows (not hidden by filters)
            var visibleRows = [];
            allRows.forEach(function(row) {
                // Check if row is hidden by filter (has display:none from filter, not pagination)
                var isFilteredOut = row.dataset.filteredOut === 'true';
                if (!isFilteredOut) {
                    visibleRows.push(row);
                }
            });

            pageState.visibleRows = visibleRows.length;

            // Calculate pagination
            var pageSize = pageState.pageSize;
            var totalPages = pageSize === 'all' ? 1 : Math.ceil(visibleRows.length / pageSize);

            // Ensure current page is valid
            if (pageState.currentPage > totalPages) {
                pageState.currentPage = Math.max(1, totalPages);
            }

            var startIndex = pageSize === 'all' ? 0 : (pageState.currentPage - 1) * pageSize;
            var endIndex = pageSize === 'all' ? visibleRows.length : Math.min(startIndex + pageSize, visibleRows.length);

            // Show/hide rows based on pagination
            var visibleIndex = 0;
            allRows.forEach(function(row) {
                var isFilteredOut = row.dataset.filteredOut === 'true';
                if (isFilteredOut) {
                    row.style.display = 'none';
                } else {
                    if (visibleIndex >= startIndex && visibleIndex < endIndex) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                    visibleIndex++;
                }
            });

            // Update info text
            var infoSpan = document.getElementById(tableType + '-page-info');
            if (infoSpan) {
                if (visibleRows.length === 0) {
                    infoSpan.textContent = 'No entries';
                } else {
                    infoSpan.textContent = 'Showing ' + (startIndex + 1) + '-' + endIndex + ' of ' + visibleRows.length;
                }
            }

            // Update page controls
            this.updateControls(tableType, totalPages);
        },

        /**
         * Update pagination control buttons
         * @param {string} tableType - 'endpoints' or 'mdns'
         * @param {number} totalPages - Total number of pages
         */
        updateControls: function(tableType, totalPages) {
            var controlsDiv = document.getElementById(tableType + '-page-controls');
            if (!controlsDiv) return;

            var pageState = state[tableType];
            var currentPage = pageState.currentPage;
            var html = '';

            if (totalPages <= 1) {
                controlsDiv.innerHTML = '';
                return;
            }

            // Previous button
            html += '<button class="pagination-btn" onclick="App.Pagination.goToPage(\'' + tableType + '\', ' + (currentPage - 1) + ')" ' +
                    (currentPage === 1 ? 'disabled' : '') + '>&laquo;</button>';

            // Page number buttons with ellipsis for large page counts
            var pages = getPageNumbers(currentPage, totalPages);
            var lastPage = 0;

            pages.forEach(function(page) {
                if (page - lastPage > 1) {
                    html += '<span class="pagination-ellipsis">...</span>';
                }
                html += '<button class="pagination-btn' + (page === currentPage ? ' active' : '') + '" ' +
                        'onclick="App.Pagination.goToPage(\'' + tableType + '\', ' + page + ')">' + page + '</button>';
                lastPage = page;
            });

            // Next button
            html += '<button class="pagination-btn" onclick="App.Pagination.goToPage(\'' + tableType + '\', ' + (currentPage + 1) + ')" ' +
                    (currentPage === totalPages ? 'disabled' : '') + '>&raquo;</button>';

            controlsDiv.innerHTML = html;
        },

        /**
         * Go to a specific page
         * @param {string} tableType - 'endpoints' or 'mdns'
         * @param {number} page - Page number to go to
         * @param {Object} options - Optional settings (skipScroll: true to prevent scroll reset)
         */
        goToPage: function(tableType, page, options) {
            var pageState = state[tableType];
            var totalPages = pageState.pageSize === 'all' ? 1 :
                Math.ceil(pageState.visibleRows / pageState.pageSize);

            if (page < 1 || page > totalPages) return;

            pageState.currentPage = page;
            this.update(tableType);

            // Scroll table to top (unless skipScroll is set during state restoration)
            if (!options || !options.skipScroll) {
                var config = getTableConfig(tableType);
                if (config) {
                    var container = document.querySelector(config.containerSelector);
                    if (container) {
                        container.scrollTop = 0;
                    }
                }
            }
        },

        /**
         * Change page size
         * @param {string} tableType - 'endpoints' or 'mdns'
         * @param {string|number} size - New page size or 'all'
         */
        changePageSize: function(tableType, size) {
            var pageState = state[tableType];
            pageState.pageSize = size === 'all' ? 'all' : parseInt(size, 10);
            pageState.currentPage = 1;
            this.update(tableType);
        },

        /**
         * Reset to first page (called after sorting or filtering)
         * @param {string} tableType - 'endpoints' or 'mdns'
         */
        resetToFirstPage: function(tableType) {
            if (state[tableType]) {
                state[tableType].currentPage = 1;
                this.update(tableType);
            }
        },

        /**
         * Get current state for a table
         * @param {string} tableType - 'endpoints' or 'mdns'
         */
        getState: function(tableType) {
            return state[tableType];
        }
    };

    /**
     * Get configuration for a table type
     * @param {string} tableType - 'endpoints' or 'mdns'
     * @returns {Object|null} Table configuration
     */
    function getTableConfig(tableType) {
        var configs = {
            endpoints: {
                tableSelector: '#endpoints-table',
                containerSelector: '.endpoints-table-wrapper'
            },
            mdns: {
                tableSelector: '#mdns-table',
                containerSelector: '.dns-table-container'
            }
        };
        return configs[tableType] || null;
    }

    /**
     * Calculate which page numbers to show
     * @param {number} current - Current page
     * @param {number} total - Total pages
     * @returns {number[]} Array of page numbers to display
     */
    function getPageNumbers(current, total) {
        var pages = [];
        var delta = 2; // Number of pages to show on each side of current

        // Always show first page
        pages.push(1);

        // Calculate range around current page
        var rangeStart = Math.max(2, current - delta);
        var rangeEnd = Math.min(total - 1, current + delta);

        // Add pages in range
        for (var i = rangeStart; i <= rangeEnd; i++) {
            if (pages.indexOf(i) === -1) {
                pages.push(i);
            }
        }

        // Always show last page if more than 1 page
        if (total > 1 && pages.indexOf(total) === -1) {
            pages.push(total);
        }

        return pages.sort(function(a, b) { return a - b; });
    }

    // Global function for page size change (called from onchange)
    window.changePageSize = function(tableType) {
        var select = document.getElementById(tableType + '-page-size');
        if (select) {
            App.Pagination.changePageSize(tableType, select.value);
        }
    };

})(window.App);
