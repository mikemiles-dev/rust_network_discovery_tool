/**
 * Internet Module - Internet destinations management
 */
(function(App) {
    'use strict';

    var destinations = [];
    var filteredDestinations = [];
    var sortColumn = 'last_seen';
    var sortDirection = 'desc';
    var currentPage = 1;
    var pageSize = 50;
    var searchTerm = '';

    App.Internet = {
        /**
         * Initialize the Internet module
         */
        init: function() {
            // Load data when the Internet tab is first shown
            if (App.state.activeTab === 'internet') {
                App.Internet.refresh();
            }
        },

        /**
         * Refresh the internet destinations table
         */
        refresh: function() {
            fetch('/api/internet')
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('Failed to fetch internet destinations');
                    }
                    return response.json();
                })
                .then(function(data) {
                    destinations = data.destinations || [];
                    App.Internet.render();
                })
                .catch(function(err) {
                    console.error('Error fetching internet destinations:', err);
                    App.Internet.renderError('Failed to load internet destinations');
                });
        },

        /**
         * Render the internet destinations table
         */
        render: function() {
            var tbody = document.getElementById('internet-table-body');
            if (!tbody) return;

            // Apply filtering and sorting
            filteredDestinations = App.Internet.filterDestinations(destinations);
            var sorted = App.Internet.sortDestinations(filteredDestinations);

            if (sorted.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No internet destinations recorded yet.</td></tr>';
                App.Internet.updatePaginationInfo(0, 0, 0);
                App.Internet.updatePaginationControls(0);
                return;
            }

            // Calculate pagination
            var totalItems = sorted.length;
            var effectivePageSize = pageSize === 'all' ? totalItems : pageSize;
            var totalPages = Math.ceil(totalItems / effectivePageSize);

            // Ensure current page is valid
            if (currentPage > totalPages) {
                currentPage = Math.max(1, totalPages);
            }

            var startIndex = (currentPage - 1) * effectivePageSize;
            var endIndex = Math.min(startIndex + effectivePageSize, totalItems);
            var pageItems = sorted.slice(startIndex, endIndex);

            var html = '';
            pageItems.forEach(function(dest) {
                var firstSeen = App.Internet.formatTimestamp(dest.first_seen_at);
                var lastSeen = App.Internet.formatTimestamp(dest.last_seen_at);

                html += '<tr class="internet-row" data-hostname="' + App.Utils.escapeHtml(dest.hostname) + '">';
                html += '<td>' + App.Utils.escapeHtml(dest.hostname) + '</td>';
                html += '<td style="text-align: right;">' + (dest.packet_count || 0).toLocaleString() + '</td>';
                html += '<td>' + firstSeen + '</td>';
                html += '<td>' + lastSeen + '</td>';
                html += '</tr>';
            });

            tbody.innerHTML = html;
            App.Internet.updateSortIndicators();
            App.Internet.updatePaginationInfo(startIndex + 1, endIndex, totalItems);
            App.Internet.updatePaginationControls(totalPages);
        },

        /**
         * Filter destinations by search term
         */
        filterDestinations: function(data) {
            if (!searchTerm) return data;
            var term = searchTerm.toLowerCase();
            return data.filter(function(dest) {
                return (dest.hostname || '').toLowerCase().includes(term);
            });
        },

        /**
         * Update pagination info text
         */
        updatePaginationInfo: function(start, end, total) {
            var infoSpan = document.getElementById('internet-page-info');
            if (infoSpan) {
                if (total === 0) {
                    infoSpan.textContent = 'No entries';
                } else {
                    infoSpan.textContent = 'Showing ' + start + '-' + end + ' of ' + total;
                }
            }
        },

        /**
         * Update pagination control buttons
         */
        updatePaginationControls: function(totalPages) {
            var controlsDiv = document.getElementById('internet-page-controls');
            if (!controlsDiv) return;

            if (totalPages <= 1) {
                controlsDiv.innerHTML = '';
                return;
            }

            var html = '';

            // Previous button
            html += '<button class="pagination-btn" onclick="App.Internet.goToPage(' + (currentPage - 1) + ')" ' +
                    (currentPage === 1 ? 'disabled' : '') + '>&laquo;</button>';

            // Page number buttons
            var pages = App.Internet.getPageNumbers(currentPage, totalPages);
            var lastPage = 0;

            pages.forEach(function(page) {
                if (page - lastPage > 1) {
                    html += '<span class="pagination-ellipsis">...</span>';
                }
                html += '<button class="pagination-btn' + (page === currentPage ? ' active' : '') + '" ' +
                        'onclick="App.Internet.goToPage(' + page + ')">' + page + '</button>';
                lastPage = page;
            });

            // Next button
            html += '<button class="pagination-btn" onclick="App.Internet.goToPage(' + (currentPage + 1) + ')" ' +
                    (currentPage === totalPages ? 'disabled' : '') + '>&raquo;</button>';

            controlsDiv.innerHTML = html;
        },

        /**
         * Calculate which page numbers to show
         */
        getPageNumbers: function(current, total) {
            var pages = [];
            var delta = 2;

            pages.push(1);

            var rangeStart = Math.max(2, current - delta);
            var rangeEnd = Math.min(total - 1, current + delta);

            for (var i = rangeStart; i <= rangeEnd; i++) {
                if (pages.indexOf(i) === -1) {
                    pages.push(i);
                }
            }

            if (total > 1 && pages.indexOf(total) === -1) {
                pages.push(total);
            }

            return pages.sort(function(a, b) { return a - b; });
        },

        /**
         * Go to a specific page
         */
        goToPage: function(page) {
            var totalItems = filteredDestinations.length;
            var effectivePageSize = pageSize === 'all' ? totalItems : pageSize;
            var totalPages = Math.ceil(totalItems / effectivePageSize);

            if (page < 1 || page > totalPages) return;

            currentPage = page;
            App.Internet.render();
        },

        /**
         * Change page size
         */
        changePageSize: function(size) {
            pageSize = size === 'all' ? 'all' : parseInt(size, 10);
            currentPage = 1;
            App.Internet.render();
        },

        /**
         * Render an error message
         */
        renderError: function(message) {
            var tbody = document.getElementById('internet-table-body');
            if (!tbody) return;

            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #f87171; padding: 2rem;">' +
                App.Utils.escapeHtml(message) + '</td></tr>';
        },

        /**
         * Sort destinations by current column and direction
         */
        sortDestinations: function(data) {
            var sorted = data.slice();
            var dir = sortDirection === 'asc' ? 1 : -1;

            sorted.sort(function(a, b) {
                var valA, valB;

                switch (sortColumn) {
                    case 'hostname':
                        valA = (a.hostname || '').toLowerCase();
                        valB = (b.hostname || '').toLowerCase();
                        return dir * valA.localeCompare(valB);
                    case 'packets':
                        valA = a.packet_count || 0;
                        valB = b.packet_count || 0;
                        return dir * (valA - valB);
                    case 'first_seen':
                        valA = a.first_seen_at || 0;
                        valB = b.first_seen_at || 0;
                        return dir * (valA - valB);
                    case 'last_seen':
                    default:
                        valA = a.last_seen_at || 0;
                        valB = b.last_seen_at || 0;
                        return dir * (valA - valB);
                }
            });

            return sorted;
        },

        /**
         * Update sort indicators in the table header
         */
        updateSortIndicators: function() {
            var columns = ['hostname', 'packets', 'first_seen', 'last_seen'];
            columns.forEach(function(col) {
                var indicator = document.getElementById('sort-' + col);
                if (indicator) {
                    if (col === sortColumn) {
                        indicator.textContent = sortDirection === 'asc' ? ' ▲' : ' ▼';
                    } else {
                        indicator.textContent = '';
                    }
                }
            });
        },

        /**
         * Format Unix timestamp to readable date string
         */
        formatTimestamp: function(timestamp) {
            if (!timestamp) return 'N/A';
            var date = new Date(timestamp * 1000);
            return date.toLocaleString();
        },

        /**
         * Filter the internet table by search term
         */
        filter: function(term) {
            searchTerm = (term || '').toLowerCase().trim();
            currentPage = 1;
            App.Internet.render();
        },

        /**
         * Sort the table by the specified column
         */
        sort: function(column) {
            if (sortColumn === column) {
                // Toggle direction
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                // Default to descending for numeric columns, ascending for text
                sortDirection = column === 'hostname' ? 'asc' : 'desc';
            }

            currentPage = 1;
            App.Internet.render();
        }
    };

    // Expose global functions for onclick handlers
    window.refreshInternetTable = App.Internet.refresh;
    window.filterInternetTable = App.Internet.filter;
    window.sortInternetTable = App.Internet.sort;

})(window.App);
