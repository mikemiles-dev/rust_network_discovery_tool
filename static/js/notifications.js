/**
 * Notifications Module - Event notification display and management
 */
(function(App) {
    'use strict';

    var lastTimestamp = 0;
    var badgeIntervalId = null;
    var searchTimeout = null;

    var paging = {
        page: 1,
        pageSize: 50,
        total: 0,
        search: ''
    };

    App.Notifications = {
        /**
         * Full fetch and render of notifications for the current page/search
         */
        refresh: function() {
            var offset = (paging.page - 1) * paging.pageSize;
            var url = '/api/notifications?limit=' + paging.pageSize + '&offset=' + offset;
            if (paging.search) {
                url += '&search=' + encodeURIComponent(paging.search);
            }
            fetch(url)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (!data.notifications) return;
                    paging.total = data.total || 0;
                    App.Notifications.render(data.notifications);
                    App.Notifications.renderPagination();
                    App.Notifications.updateBadge(data.notifications);
                    if (data.notifications.length > 0) {
                        lastTimestamp = data.notifications[0].created_at;
                    }
                })
                .catch(function(error) {
                    console.error('Failed to fetch notifications:', error);
                });
        },

        /**
         * Incremental poll - only fetch new notifications since last check (for badge)
         */
        poll: function() {
            var url = '/api/notifications?since=' + lastTimestamp + '&limit=50';
            fetch(url)
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (!data.notifications) return;
                    App.Notifications.updateBadge(data.notifications);
                    if (data.notifications.length > 0) {
                        lastTimestamp = data.notifications[0].created_at;
                    }
                })
                .catch(function() {});
        },

        /**
         * Handle search input with debounce
         */
        onSearch: function() {
            if (searchTimeout) clearTimeout(searchTimeout);
            searchTimeout = setTimeout(function() {
                var input = document.getElementById('notifications-search');
                paging.search = input ? input.value.trim() : '';
                paging.page = 1;
                App.Notifications.refresh();
            }, 300);
        },

        /**
         * Handle page size change
         */
        changePageSize: function() {
            var select = document.getElementById('notifications-page-size');
            if (select) {
                paging.pageSize = parseInt(select.value, 10);
                paging.page = 1;
                App.Notifications.refresh();
            }
        },

        /**
         * Go to a specific page
         */
        goToPage: function(page) {
            var totalPages = Math.ceil(paging.total / paging.pageSize) || 1;
            if (page < 1 || page > totalPages) return;
            paging.page = page;
            App.Notifications.refresh();
            // Scroll list to top
            var list = document.getElementById('notifications-list');
            if (list) list.scrollTop = 0;
        },

        /**
         * Render notification items into the list container
         */
        render: function(items) {
            var list = document.getElementById('notifications-list');
            if (!list) return;

            if (items.length === 0) {
                var msg = paging.search
                    ? 'No notifications match "' + App.Utils.escapeHtml(paging.search) + '"'
                    : 'No notifications yet. Network events will appear here.';
                list.innerHTML = '<div class="notification-empty">' + msg + '</div>';
                return;
            }

            var fragment = document.createDocumentFragment();

            items.forEach(function(item) {
                var div = document.createElement('div');
                div.className = 'notification-item';
                div.dataset.id = item.id;

                var icon = document.createElement('span');
                icon.className = 'notification-icon';
                icon.textContent = App.Notifications.iconFor(item.event_type);

                var body = document.createElement('div');
                body.className = 'notification-body';

                var hasLink = item.endpoint_name && item.event_type !== 'endpoint_deleted';
                var title;
                if (hasLink) {
                    title = document.createElement('a');
                    title.className = 'notification-title notification-link';
                    title.textContent = item.title;
                    title.href = '/?node=' + encodeURIComponent(item.endpoint_name);
                    title.onclick = function(e) {
                        e.preventDefault();
                        App.Notifications.navigateToEndpoint(item.endpoint_name);
                    };
                } else {
                    title = document.createElement('div');
                    title.className = 'notification-title';
                    title.textContent = item.title;
                }
                body.appendChild(title);

                if (item.details) {
                    var details = document.createElement('div');
                    details.className = 'notification-details';
                    details.textContent = item.details;
                    body.appendChild(details);
                }

                var time = document.createElement('div');
                time.className = 'notification-time';
                time.textContent = App.Notifications.formatTime(item.created_at);
                body.appendChild(time);

                var dismiss = document.createElement('button');
                dismiss.className = 'notification-dismiss';
                dismiss.title = 'Dismiss';
                dismiss.textContent = '\u00d7';
                dismiss.onclick = function() {
                    App.Notifications.dismiss(item.id, div);
                };

                div.appendChild(icon);
                div.appendChild(body);
                div.appendChild(dismiss);
                fragment.appendChild(div);
            });

            list.innerHTML = '';
            list.appendChild(fragment);
        },

        /**
         * Render pagination controls
         */
        renderPagination: function() {
            var container = document.getElementById('notifications-pagination');
            if (!container) return;

            var totalPages = Math.ceil(paging.total / paging.pageSize) || 1;
            var current = paging.page;

            if (paging.total === 0) {
                container.innerHTML = '';
                return;
            }

            var html = '';

            // Info text
            var start = (current - 1) * paging.pageSize + 1;
            var end = Math.min(current * paging.pageSize, paging.total);
            html += '<span class="notif-page-info">' + start + '-' + end + ' of ' + paging.total + '</span>';

            if (totalPages <= 1) {
                container.innerHTML = html;
                return;
            }

            // Prev button
            html += '<button class="notif-page-btn" onclick="App.Notifications.goToPage(' + (current - 1) + ')" ' +
                    (current === 1 ? 'disabled' : '') + '>&laquo;</button>';

            // Page numbers
            var pages = getPageNumbers(current, totalPages);
            var lastPage = 0;
            pages.forEach(function(p) {
                if (p - lastPage > 1) {
                    html += '<span class="notif-page-ellipsis">...</span>';
                }
                html += '<button class="notif-page-btn' + (p === current ? ' active' : '') + '" ' +
                        'onclick="App.Notifications.goToPage(' + p + ')">' + p + '</button>';
                lastPage = p;
            });

            // Next button
            html += '<button class="notif-page-btn" onclick="App.Notifications.goToPage(' + (current + 1) + ')" ' +
                    (current === totalPages ? 'disabled' : '') + '>&raquo;</button>';

            container.innerHTML = html;
        },

        /**
         * Map event types to icons
         */
        iconFor: function(eventType) {
            var icons = {
                'endpoint_discovered': '\uD83D\uDD0D',
                'endpoint_deleted': '\uD83D\uDDD1\uFE0F',
                'endpoints_merged': '\uD83D\uDD17',
                'endpoint_renamed': '\u270F\uFE0F',
                'endpoint_reclassified': '\uD83C\uDFF7\uFE0F',
                'scan_started': '\u25B6\uFE0F',
                'scan_stopped': '\u23F9\uFE0F',
                'model_identified': '\uD83D\uDCF1'
            };
            return icons[eventType] || '\uD83D\uDD14';
        },

        /**
         * Format unix timestamp to relative time
         */
        formatTime: function(ts) {
            var now = Math.floor(Date.now() / 1000);
            var diff = now - ts;
            if (diff < 60) return 'Just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        },

        /**
         * Dismiss a single notification
         */
        dismiss: function(id, element) {
            fetch('/api/notifications/dismiss', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids: [id] })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success && element) {
                    element.style.transition = 'opacity 0.2s';
                    element.style.opacity = '0';
                    setTimeout(function() {
                        element.remove();
                        paging.total = Math.max(0, paging.total - 1);
                        App.Notifications.renderPagination();
                        var list = document.getElementById('notifications-list');
                        if (list && list.querySelectorAll('.notification-item').length === 0) {
                            // Last item on this page dismissed, go back or refresh
                            if (paging.page > 1) {
                                paging.page--;
                            }
                            App.Notifications.refresh();
                        }
                    }, 200);
                    App.Notifications.decrementBadge();
                }
            })
            .catch(function() {});
        },

        /**
         * Dismiss all notifications
         */
        clearAll: function() {
            fetch('/api/notifications/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    paging.page = 1;
                    paging.total = 0;
                    var list = document.getElementById('notifications-list');
                    if (list) {
                        list.innerHTML = '<div class="notification-empty">No notifications yet. Network events will appear here.</div>';
                    }
                    App.Notifications.renderPagination();
                    App.Notifications.setBadge(0);
                }
            })
            .catch(function() {});
        },

        /**
         * Update badge count from notification items
         */
        updateBadge: function(items) {
            // Use total from server when available (more accurate than page count)
            if (!paging.search && paging.page === 1) {
                App.Notifications.setBadge(paging.total);
            }
        },

        /**
         * Set badge to a specific count
         */
        setBadge: function(count) {
            var badge = document.getElementById('notification-badge');
            if (!badge) return;
            if (count > 0) {
                badge.textContent = count > 99 ? '99+' : count;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        },

        /**
         * Decrement badge count by 1
         */
        decrementBadge: function() {
            var badge = document.getElementById('notification-badge');
            if (!badge || badge.style.display === 'none') return;
            var current = parseInt(badge.textContent, 10) || 0;
            App.Notifications.setBadge(Math.max(0, current - 1));
        },

        /**
         * Navigate to an endpoint on the network tab
         */
        navigateToEndpoint: function(endpointName) {
            var url = new URL(window.location.href);
            url.searchParams.set('node', endpointName);
            url.searchParams.delete('tab');
            window.location.href = url.toString();
        },

        /**
         * Start background badge polling (every 30s when not on notifications tab)
         */
        startBadgePolling: function() {
            if (badgeIntervalId) return;

            // Initial badge count fetch
            fetch('/api/notifications?limit=1')
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.total !== undefined) {
                        App.Notifications.setBadge(data.total);
                    }
                })
                .catch(function() {});

            badgeIntervalId = setInterval(function() {
                if (App.state.activeTab !== 'notifications') {
                    fetch('/api/notifications?limit=1')
                        .then(function(r) { return r.json(); })
                        .then(function(data) {
                            if (data.total !== undefined) {
                                App.Notifications.setBadge(data.total);
                            }
                        })
                        .catch(function() {});
                }
            }, 30000);
        }
    };

    /**
     * Calculate which page numbers to show
     */
    function getPageNumbers(current, total) {
        var pages = [];
        var delta = 2;
        pages.push(1);
        var rangeStart = Math.max(2, current - delta);
        var rangeEnd = Math.min(total - 1, current + delta);
        for (var i = rangeStart; i <= rangeEnd; i++) {
            if (pages.indexOf(i) === -1) pages.push(i);
        }
        if (total > 1 && pages.indexOf(total) === -1) pages.push(total);
        return pages.sort(function(a, b) { return a - b; });
    }

})(window.App);
