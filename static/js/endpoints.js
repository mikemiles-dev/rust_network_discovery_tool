/**
 * Endpoints Module - Endpoint details panel management
 */
(function(App) {
    'use strict';

    App.Endpoints = {
        /**
         * Get device type emoji and label
         */
        getDeviceTypeInfo: function(deviceType) {
            var types = {
                'gateway': { emoji: '', label: 'Gateway' },
                'internet': { emoji: '', label: 'Internet' },
                'printer': { emoji: '', label: 'Printer' },
                'tv': { emoji: '', label: 'TV' },
                'gaming': { emoji: '', label: 'Gaming' },
                'phone': { emoji: '', label: 'Phone' },
                'virtualization': { emoji: '', label: 'VM' },
                'soundbar': { emoji: '', label: 'Soundbar' },
                'appliance': { emoji: '', label: 'Appliance' },
                'local': { emoji: '', label: 'Local' }
            };
            return types[deviceType] || { emoji: '?', label: 'Other' };
        },

        /**
         * Update endpoint details panel with data from API
         */
        updateDetails: function(data) {
            // Update endpoint name
            var nameDisplay = document.getElementById('endpoint-name-display');
            if (nameDisplay) {
                var nameSpan = nameDisplay.querySelector('span');
                if (nameSpan) nameSpan.textContent = data.endpoint_name;
            }

            // Update device type button
            var deviceTypeBtn = document.getElementById('device-type-btn');
            if (deviceTypeBtn) {
                if (data.is_manual_override) {
                    deviceTypeBtn.classList.add('manual-override');
                } else {
                    deviceTypeBtn.classList.remove('manual-override');
                }
            }

            // Update current device type display
            var deviceTypeInfo = App.Endpoints.getDeviceTypeInfo(data.device_type);
            var currentDeviceType = document.getElementById('current-device-type');
            if (currentDeviceType) {
                currentDeviceType.textContent = deviceTypeInfo.emoji + ' ' + deviceTypeInfo.label;
            }

            // Update manual override indicator
            var manualOverrideIndicator = document.getElementById('manual-override-indicator');
            if (manualOverrideIndicator) {
                manualOverrideIndicator.style.display = data.is_manual_override ? '' : 'none';
            }

            // Update vendor badge
            var vendorBadge = document.getElementById('device-vendor-badge');
            if (vendorBadge) {
                if (data.device_vendor) {
                    vendorBadge.textContent = data.device_vendor;
                    vendorBadge.style.display = '';
                } else {
                    vendorBadge.style.display = 'none';
                }
            }

            // Update model badge
            var modelBadge = document.getElementById('device-model-badge');
            if (modelBadge) {
                if (data.device_model) {
                    modelBadge.textContent = data.device_model;
                    modelBadge.style.display = '';
                } else {
                    modelBadge.style.display = 'none';
                }
            }

            // Update stat badges
            var statNumbers = document.querySelectorAll('.stats .stat-number');
            if (statNumbers.length >= 5) {
                statNumbers[0].textContent = data.ips.length;
                statNumbers[1].textContent = data.macs.length;
                statNumbers[2].textContent = data.hostnames.length;
                statNumbers[3].textContent = data.ports.length;
                statNumbers[4].textContent = data.protocols.length;
            }

            // Update bytes in/out
            var bytesIn = document.getElementById('bytes-in');
            var bytesOut = document.getElementById('bytes-out');
            if (bytesIn) bytesIn.textContent = App.Formatting.formatBytes(data.bytes_in);
            if (bytesOut) bytesOut.textContent = App.Formatting.formatBytes(data.bytes_out);

            // Update protocols container
            var protocolsContainer = document.getElementById('protocols-container');
            if (protocolsContainer) {
                protocolsContainer.innerHTML = data.protocols.length > 0
                    ? data.protocols.map(function(p) { return '<div class="protocol-badge" data-protocol="' + p + '" onclick="filterByProtocol(\'' + p + '\', this)">' + p + '</div>'; }).join('')
                    : '<div class="empty-state">No protocols</div>';
            }

            // Update ports container
            var portsContainer = document.getElementById('ports-container');
            if (portsContainer) {
                portsContainer.innerHTML = data.ports.length > 0
                    ? data.ports.map(function(p) { return '<div class="protocol-badge" data-port="' + p + '" onclick="filterByPort(\'' + p + '\', this)">' + p + '</div>'; }).join('')
                    : '<div class="empty-state">No ports</div>';
            }

            // Update hostnames container
            var hostnamesContainer = document.getElementById('hostnames-container');
            if (hostnamesContainer) {
                hostnamesContainer.innerHTML = data.hostnames.length > 0
                    ? data.hostnames.map(function(h) { return '<div class="hostname-item">' + h + '</div>'; }).join('')
                    : '<div class="empty-state">No hostnames</div>';
            }

            // Update IPs container
            var ipsContainer = document.getElementById('ips-container');
            if (ipsContainer) {
                ipsContainer.innerHTML = data.ips.length > 0
                    ? data.ips.map(function(ip) { return '<div class="hostname-item">' + ip + '</div>'; }).join('')
                    : '<div class="empty-state">No IP addresses</div>';
            }

            // Update MACs container
            var macsContainer = document.getElementById('macs-container');
            if (macsContainer) {
                macsContainer.innerHTML = data.macs.length > 0
                    ? data.macs.map(function(mac) { return '<div class="hostname-item">' + mac + '</div>'; }).join('')
                    : '<div class="empty-state">No MAC addresses</div>';
            }

            // Show the device type selector
            var deviceTypeSelector = document.querySelector('.device-type-selector');
            if (deviceTypeSelector) {
                deviceTypeSelector.style.display = '';
            }

            // Update classification module with new endpoint name
            if (App.Classification) {
                App.Classification.setEndpointName(data.endpoint_name);
            }
        },

        /**
         * Select a node and update URL
         */
        selectNode: function(nodeId) {
            // Check if clicking on already selected row - toggle off
            var currentRow = document.querySelector('.endpoint-row[data-endpoint="' + nodeId + '"]');
            if (currentRow && currentRow.classList.contains('selected')) {
                App.Endpoints.unselectNode();
                return;
            }

            // Update URL without reload
            var url = new URL(window.location.href);
            url.searchParams.set('node', nodeId);
            history.pushState({ node: nodeId }, '', url.toString());

            // Update table row selection
            document.querySelectorAll('.endpoint-row.selected').forEach(function(row) {
                row.classList.remove('selected');
            });
            if (currentRow) {
                currentRow.classList.add('selected');
            }

            // Fetch endpoint details and update panel
            fetch('/api/endpoint/' + encodeURIComponent(nodeId) + '/details')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    App.Endpoints.updateDetails(data);
                })
                .catch(function(error) {
                    console.error('Error fetching endpoint details:', error);
                    // Fall back to page reload on error
                    window.location.href = url.toString();
                });
        },

        /**
         * Unselect node and update URL
         */
        unselectNode: function() {
            var url = new URL(window.location.href);
            url.searchParams.delete('node');
            history.pushState({}, '', url.toString());

            // Clear table row selection
            document.querySelectorAll('.endpoint-row.selected').forEach(function(row) {
                row.classList.remove('selected');
            });

            // Clear endpoint details content
            var nameDisplay = document.querySelector('#endpoint-name-display span');
            if (nameDisplay) nameDisplay.textContent = 'No endpoint selected';

            // Clear device type
            var deviceType = document.getElementById('current-device-type');
            if (deviceType) deviceType.textContent = '';

            // Hide device type selector
            var deviceTypeSelector = document.querySelector('.device-type-selector');
            if (deviceTypeSelector) deviceTypeSelector.style.display = 'none';

            // Hide manual override indicator
            var manualOverride = document.getElementById('manual-override-indicator');
            if (manualOverride) manualOverride.style.display = 'none';

            // Hide vendor and model badges
            var vendorBadge = document.getElementById('device-vendor-badge');
            if (vendorBadge) vendorBadge.style.display = 'none';
            var modelBadge = document.getElementById('device-model-badge');
            if (modelBadge) modelBadge.style.display = 'none';

            // Clear stats
            document.querySelectorAll('.stats .stat-number').forEach(function(el) {
                el.textContent = '0';
            });

            // Clear all containers
            var containers = ['protocols-container', 'ports-container', 'hostnames-container', 'ips-container', 'macs-container'];
            containers.forEach(function(containerId) {
                var container = document.getElementById(containerId);
                if (container) {
                    container.innerHTML = '<div class="empty-state">No endpoint selected</div>';
                }
            });

            // Clear bytes display
            var bytesIn = document.getElementById('bytes-in');
            var bytesOut = document.getElementById('bytes-out');
            if (bytesIn) bytesIn.textContent = '0 B';
            if (bytesOut) bytesOut.textContent = '0 B';
        },

        /**
         * Select scan interval
         */
        selectScanInterval: function(interval) {
            var url = new URL(window.location.href);
            url.searchParams.set('scan_interval', interval);
            window.location.href = url.toString();
        },

        /**
         * Scroll to section in details panel
         */
        scrollToSection: function(sectionId) {
            var section = document.getElementById(sectionId);
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    };

    // Expose functions globally for onclick handlers
    window.selectNode = App.Endpoints.selectNode;
    window.unselectNode = App.Endpoints.unselectNode;
    window.selectScanInterval = App.Endpoints.selectScanInterval;
    window.scrollToSection = App.Endpoints.scrollToSection;
    window.getDeviceTypeInfo = App.Endpoints.getDeviceTypeInfo;
    window.updateEndpointDetails = App.Endpoints.updateDetails;

})(window.App);
