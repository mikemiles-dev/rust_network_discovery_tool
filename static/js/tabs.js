/**
 * Tabs Module - Tab navigation management
 */
(function(App) {
    'use strict';

    App.Tabs = {
        /**
         * Switch to a different tab
         */
        switchTab: function(tabName, event) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(function(tab) {
                tab.classList.remove('active');
            });
            // Deactivate all tab buttons
            document.querySelectorAll('.tab-btn').forEach(function(btn) {
                btn.classList.remove('active');
            });
            // Show selected tab content
            document.getElementById(tabName + '-tab').classList.add('active');
            // Activate clicked button
            if (event && event.target) {
                event.target.classList.add('active');
            }

            // Update active tab state
            App.state.activeTab = tabName;

            // Save tab to URL for persistence across refresh
            var url = new URL(window.location.href);
            if (tabName === 'network') {
                // Remove tab param for default tab
                url.searchParams.delete('tab');
            } else {
                url.searchParams.set('tab', tabName);
            }
            window.history.replaceState({}, '', url.toString());

            // If switching to DNS tab, do an immediate refresh of DNS entries
            if (tabName === 'dns') {
                App.Tabs.refreshDnsEntries();
            }

            // If switching to Internet tab, refresh internet destinations
            if (tabName === 'internet' && App.Internet) {
                App.Internet.refresh();
            }

            // If switching to Scanner tab, check capabilities
            if (tabName === 'scanner' && App.Scanner) {
                App.Scanner.checkCapabilities();
            }
        },

        /**
         * Fetch and update DNS entries table
         */
        refreshDnsEntries: function() {
            fetch('/api/dns-entries')
                .then(function(response) {
                    return response.json();
                })
                .then(function(entries) {
                    var tbody = document.querySelector('.dns-table tbody');
                    if (!tbody) return;

                    // Use DocumentFragment for batched DOM updates
                    var fragment = document.createDocumentFragment();

                    if (entries.length === 0) {
                        var row = document.createElement('tr');
                        row.innerHTML = '<td colspan="4" style="text-align: center; color: var(--text-secondary);">No mDNS entries discovered yet</td>';
                        fragment.appendChild(row);
                    } else {
                        entries.forEach(function(entry) {
                            var row = document.createElement('tr');
                            row.innerHTML =
                                '<td>' + App.Utils.escapeHtml(entry.timestamp) + '</td>' +
                                '<td>' + App.Utils.escapeHtml(entry.ip) + '</td>' +
                                '<td>' + App.Utils.escapeHtml(entry.hostname) + '</td>' +
                                '<td>' + App.Utils.escapeHtml(entry.services) + '</td>';
                            fragment.appendChild(row);
                        });
                    }

                    // Single DOM operation: clear and append all at once
                    tbody.innerHTML = '';
                    tbody.appendChild(fragment);
                })
                .catch(function(error) {
                    // Silently fail - DNS refresh is non-critical
                });
        }
    };

    // Expose switchTab globally for onclick handlers
    window.switchTab = function(tabName) {
        App.Tabs.switchTab(tabName, event);
    };

})(window.App);
