/**
 * Formatting Module - Data formatters for display
 */
(function(App) {
    'use strict';

    App.Formatting = {
        /**
         * Format bytes to human readable string
         */
        formatBytes: function(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },

        /**
         * Format bandwidth for table display
         */
        formatTableBandwidth: function(sent, received) {
            const formatBytes = App.Formatting.formatBytes;
            if (sent === 0 && received === 0) {
                return '<span class="no-data">No data</span>';
            }
            return '<span class="bandwidth-sent">↑ ' + formatBytes(sent) + '</span> ' +
                   '<span class="bandwidth-received">↓ ' + formatBytes(received) + '</span>';
        },

        /**
         * Format time duration
         */
        formatDuration: function(seconds) {
            if (seconds < 60) {
                return seconds + 's';
            } else if (seconds < 3600) {
                return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
            } else {
                const hours = Math.floor(seconds / 3600);
                const mins = Math.floor((seconds % 3600) / 60);
                return hours + 'h ' + mins + 'm';
            }
        },

        /**
         * Format timestamp to locale string
         */
        formatTimestamp: function(timestamp) {
            if (!timestamp) return 'N/A';
            const date = new Date(timestamp);
            return date.toLocaleString();
        },

        /**
         * Format MAC address with separators
         */
        formatMac: function(mac) {
            if (!mac) return 'Unknown';
            return mac.toUpperCase();
        },

        /**
         * Format ThinQ device status
         */
        formatThinQStatus: function(status, deviceType) {
            if (!status) return '<p class="error">No status available</p>';

            let html = '<div class="thinq-status-grid">';

            // Common fields
            if (status.online !== undefined) {
                html += '<div class="status-item"><span class="label">Online:</span><span class="value">' +
                        (status.online ? '✓ Yes' : '✗ No') + '</span></div>';
            }

            // Device-specific fields based on type
            if (deviceType === 'washer' || deviceType === 'dryer') {
                if (status.state) {
                    html += '<div class="status-item"><span class="label">State:</span><span class="value">' +
                            status.state + '</span></div>';
                }
                if (status.remainingTime !== undefined) {
                    html += '<div class="status-item"><span class="label">Remaining:</span><span class="value">' +
                            App.Formatting.formatDuration(status.remainingTime) + '</span></div>';
                }
            } else if (deviceType === 'refrigerator') {
                if (status.fridgeTemp !== undefined) {
                    html += '<div class="status-item"><span class="label">Fridge Temp:</span><span class="value">' +
                            status.fridgeTemp + '°</span></div>';
                }
                if (status.freezerTemp !== undefined) {
                    html += '<div class="status-item"><span class="label">Freezer Temp:</span><span class="value">' +
                            status.freezerTemp + '°</span></div>';
                }
            } else if (deviceType === 'ac' || deviceType === 'air_conditioner') {
                if (status.currentTemp !== undefined) {
                    html += '<div class="status-item"><span class="label">Current Temp:</span><span class="value">' +
                            status.currentTemp + '°</span></div>';
                }
                if (status.targetTemp !== undefined) {
                    html += '<div class="status-item"><span class="label">Target Temp:</span><span class="value">' +
                            status.targetTemp + '°</span></div>';
                }
                if (status.mode) {
                    html += '<div class="status-item"><span class="label">Mode:</span><span class="value">' +
                            status.mode + '</span></div>';
                }
            } else if (deviceType === 'tv') {
                if (status.power !== undefined) {
                    html += '<div class="status-item"><span class="label">Power:</span><span class="value">' +
                            (status.power ? 'On' : 'Off') + '</span></div>';
                }
                if (status.volume !== undefined) {
                    html += '<div class="status-item"><span class="label">Volume:</span><span class="value">' +
                            status.volume + '</span></div>';
                }
                if (status.channel) {
                    html += '<div class="status-item"><span class="label">Channel:</span><span class="value">' +
                            status.channel + '</span></div>';
                }
            }

            // Show all other fields
            for (const [key, value] of Object.entries(status)) {
                if (['online', 'state', 'remainingTime', 'fridgeTemp', 'freezerTemp',
                     'currentTemp', 'targetTemp', 'mode', 'power', 'volume', 'channel'].includes(key)) {
                    continue;
                }
                html += '<div class="status-item"><span class="label">' +
                        App.Utils.escapeHtml(key) + ':</span><span class="value">' +
                        App.Utils.escapeHtml(String(value)) + '</span></div>';
            }

            html += '</div>';
            return html;
        }
    };

})(window.App);
