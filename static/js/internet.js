/**
 * Internet Module - Internet destinations management
 */
(function(App) {
    'use strict';

    var destinations = [];
    var sortColumn = 'last_seen';
    var sortDirection = 'desc';

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

            if (destinations.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No internet destinations recorded yet.</td></tr>';
                return;
            }

            // Sort destinations
            var sorted = App.Internet.sortDestinations(destinations);

            var html = '';
            sorted.forEach(function(dest) {
                var totalBytes = (dest.bytes_in || 0) + (dest.bytes_out || 0);
                var firstSeen = App.Internet.formatTimestamp(dest.first_seen_at);
                var lastSeen = App.Internet.formatTimestamp(dest.last_seen_at);
                var traffic = App.Formatting.formatBytes(totalBytes);

                html += '<tr class="internet-row" data-hostname="' + App.Utils.escapeHtml(dest.hostname) + '">';
                html += '<td>' + App.Utils.escapeHtml(dest.hostname) + '</td>';
                html += '<td style="text-align: right;">' + (dest.packet_count || 0).toLocaleString() + '</td>';
                html += '<td style="text-align: right;">' + traffic + '</td>';
                html += '<td>' + firstSeen + '</td>';
                html += '<td>' + lastSeen + '</td>';
                html += '</tr>';
            });

            tbody.innerHTML = html;
            App.Internet.updateSortIndicators();
        },

        /**
         * Render an error message
         */
        renderError: function(message) {
            var tbody = document.getElementById('internet-table-body');
            if (!tbody) return;

            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #f87171; padding: 2rem;">' +
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
                    case 'traffic':
                        valA = (a.bytes_in || 0) + (a.bytes_out || 0);
                        valB = (b.bytes_in || 0) + (b.bytes_out || 0);
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
            var columns = ['hostname', 'packets', 'traffic', 'first_seen', 'last_seen'];
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
        filter: function(searchTerm) {
            var term = searchTerm.toLowerCase().trim();
            var rows = document.querySelectorAll('#internet-table-body .internet-row');

            rows.forEach(function(row) {
                var hostname = row.dataset.hostname.toLowerCase();
                if (term === '' || hostname.includes(term)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
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

            App.Internet.render();
        }
    };

    // Expose global functions for onclick handlers
    window.refreshInternetTable = App.Internet.refresh;
    window.filterInternetTable = App.Internet.filter;
    window.sortInternetTable = App.Internet.sort;

})(window.App);
