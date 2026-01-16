/**
 * Utils Module - Shared state and utility functions
 * Must be loaded first before other modules
 */
(function(global) {
    'use strict';

    // Initialize App namespace with shared state
    global.App = {
        state: {
            activeTab: 'network',
            selectedProtocol: null,
            selectedPort: null,
            selectedVendor: null,
            refreshIntervalId: null,
            savedRefreshInterval: null,
            currentDeviceIp: null,
            currentDeviceType: null,
            deviceCapabilitiesLoaded: false,
            currentThinQDeviceId: null,
            currentThinQDeviceType: null,
            restoringState: false
        }
    };

    // Utility functions
    global.App.Utils = {
        /**
         * Escape HTML to prevent XSS
         */
        escapeHtml: function(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        /**
         * Debounce function for performance optimization
         */
        debounce: function(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        },

        /**
         * Check if IP is in local/private range
         */
        isLocalIP: function(ip) {
            if (!ip) return false;
            return ip.startsWith('192.168.') ||
                   ip.startsWith('10.') ||
                   ip.startsWith('172.16.') ||
                   ip.startsWith('172.17.') ||
                   ip.startsWith('172.18.') ||
                   ip.startsWith('172.19.') ||
                   ip.startsWith('172.20.') ||
                   ip.startsWith('172.21.') ||
                   ip.startsWith('172.22.') ||
                   ip.startsWith('172.23.') ||
                   ip.startsWith('172.24.') ||
                   ip.startsWith('172.25.') ||
                   ip.startsWith('172.26.') ||
                   ip.startsWith('172.27.') ||
                   ip.startsWith('172.28.') ||
                   ip.startsWith('172.29.') ||
                   ip.startsWith('172.30.') ||
                   ip.startsWith('172.31.') ||
                   ip === '127.0.0.1';
        },

        /**
         * Copy text to clipboard with visual feedback
         */
        copyToClipboard: function(text, buttonElement) {
            navigator.clipboard.writeText(text).then(function() {
                if (buttonElement) {
                    const originalText = buttonElement.textContent;
                    buttonElement.textContent = 'Copied!';
                    buttonElement.classList.add('copied');
                    setTimeout(function() {
                        buttonElement.textContent = originalText;
                        buttonElement.classList.remove('copied');
                    }, 1500);
                }
            }).catch(function(err) {
                console.error('Failed to copy:', err);
            });
        },

        /**
         * Get first IP from comma-separated list
         */
        getFirstIp: function(ipsString) {
            if (!ipsString) return '';
            const parts = ipsString.split(',');
            return parts[0].trim();
        },

        /**
         * Compare two IP addresses for sorting
         */
        compareIps: function(ip1, ip2) {
            const parts1 = ip1.split('.').map(Number);
            const parts2 = ip2.split('.').map(Number);
            for (let i = 0; i < 4; i++) {
                if (parts1[i] !== parts2[i]) {
                    return parts1[i] - parts2[i];
                }
            }
            return 0;
        }
    };

})(window);
