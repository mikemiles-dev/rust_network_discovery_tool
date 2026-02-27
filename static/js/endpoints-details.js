/**
 * Endpoints Details Module - Details panel rendering
 */
(function() {
    'use strict';

    App.Endpoints = App.Endpoints || {};

    /**
     * Get device type emoji and label
     */
    App.Endpoints.getDeviceTypeInfo = function(deviceType) {
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
    };

    /**
     * Check if a device is controllable (Roku, Samsung TV, LG ThinQ)
     */
    App.Endpoints.isControllableDevice = function(deviceType, endpointName) {
        var dt = (deviceType || '').toLowerCase();
        var name = (endpointName || '').toLowerCase();

        // Check device type - "tv" covers Roku, Samsung, LG TVs; "appliance" covers LG ThinQ
        if (dt === 'tv' || dt === 'appliance' || dt === 'roku' || dt === 'samsung' || dt === 'samsung_tv' || dt.indexOf('lg_thinq') === 0) {
            return true;
        }

        // Check endpoint name hints
        if (name.indexOf('roku') !== -1) return true;
        if (name.indexOf('samsung') !== -1) return true;
        if (name.indexOf('lma') !== -1) return true;  // LG ThinQ appliances

        return false;
    };

    /**
     * Update endpoint details panel with data from API
     */
    App.Endpoints.updateDetails = function(data) {
        // Update endpoint name
        var nameDisplay = document.getElementById('endpoint-name-display');
        if (nameDisplay) {
            var nameSpan = nameDisplay.querySelector('span');
            if (nameSpan) nameSpan.textContent = data.endpoint_name;
        }

        // Show the rename button (hidden when no endpoint selected on page load)
        var renameBtn = document.getElementById('rename-btn');
        if (renameBtn) {
            renameBtn.style.display = '';
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

        // Update vendor badge and add button
        var vendorBadge = document.getElementById('device-vendor-badge');
        var addVendorBtn = document.getElementById('add-vendor-btn');
        if (vendorBadge) {
            if (data.device_vendor) {
                vendorBadge.textContent = data.device_vendor;
                vendorBadge.style.display = '';
                if (addVendorBtn) addVendorBtn.style.display = 'none';
            } else {
                vendorBadge.style.display = 'none';
                if (addVendorBtn) addVendorBtn.style.display = '';
            }
        }

        // Update model badge and add button
        var modelBadge = document.getElementById('device-model-badge');
        var addModelBtn = document.getElementById('add-model-btn');
        if (modelBadge) {
            if (data.device_model) {
                modelBadge.textContent = data.device_model;
                modelBadge.style.display = '';
                if (addModelBtn) addModelBtn.style.display = 'none';
            } else {
                modelBadge.style.display = 'none';
                if (addModelBtn) addModelBtn.style.display = '';
            }
        }

        // Start polling for model updates if this looks like a device being probed
        var genericModels = ['HP Device', 'Amazon Device', 'Amazon Echo', 'Google Device', ''];
        var isGenericModel = !data.device_model || genericModels.indexOf(data.device_model) !== -1;
        var isHpDevice = data.device_vendor === 'HP';
        if (isGenericModel && isHpDevice) {
            App.Endpoints.startModelPolling(data.endpoint_name, data.device_model || '');
        } else {
            App.Endpoints.stopModelPolling();
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
                ? data.ports.map(function(p) { return '<div class="listbox-item" data-port="' + p + '" onclick="filterByPort(\'' + p + '\', this)">' + p + '</div>'; }).join('')
                : '<div class="empty-state">No ports</div>';
        }

        // Update hostnames container
        var hostnamesContainer = document.getElementById('hostnames-container');
        if (hostnamesContainer) {
            hostnamesContainer.innerHTML = data.hostnames.length > 0
                ? data.hostnames.map(function(h) { return '<div class="listbox-item">' + h + '</div>'; }).join('')
                : '<div class="empty-state">No hostnames</div>';
        }

        // Update IPs container (with probe buttons for IPs without hostnames)
        var ipsContainer = document.getElementById('ips-container');
        if (ipsContainer) {
            var hasHostnames = data.hostnames && data.hostnames.length > 0;
            ipsContainer.innerHTML = data.ips.length > 0
                ? data.ips.map(function(ip) {
                    var probeBtn = !hasHostnames
                        ? ' <button class="probe-btn" onclick="probeHostname(\'' + ip + '\')">Probe</button>'
                        : '';
                    return '<div class="hostname-item">' + ip + probeBtn + '</div>';
                }).join('')
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

        // Update control-content data attributes for network actions
        var controlContent = document.getElementById('control-content');
        if (controlContent) {
            controlContent.dataset.ips = data.ips.join(',');
            controlContent.dataset.endpointName = data.endpoint_name;
            if (data.device_type) {
                controlContent.dataset.deviceType = data.device_type;
            }
        }

        // Show/hide Control tab based on whether device is controllable
        var controlTabBtn = document.getElementById('control-tab-btn');
        if (controlTabBtn) {
            var isControllable = App.Endpoints.isControllableDevice(data.device_type, data.endpoint_name);
            controlTabBtn.style.display = isControllable ? '' : 'none';

            // If Control tab was active but device is not controllable, switch to Details
            if (!isControllable && controlTabBtn.classList.contains('active')) {
                var detailsTab = document.querySelector('.detail-tab[data-tab="details-tab-content"]');
                if (detailsTab) {
                    switchDetailTab(detailsTab, 'details-tab-content');
                }
            }
        }

        // Show endpoint actions (merge/delete buttons) and bind handlers
        var actionsContainer = document.getElementById('endpoint-actions-container');
        if (actionsContainer) {
            actionsContainer.style.display = '';
            var mergeBtn = document.getElementById('merge-endpoint-btn');
            var deleteBtn = document.getElementById('delete-endpoint-btn');
            if (mergeBtn) {
                mergeBtn.onclick = function() { App.Endpoints.mergeEndpoint(data.endpoint_name); };
            }
            if (deleteBtn) {
                deleteBtn.onclick = function() { App.Endpoints.deleteEndpoint(data.endpoint_name); };
            }
        }
    };

    /**
     * Show loading state in the details panel
     */
    App.Endpoints.showLoading = function(nodeName) {
        // Update endpoint name to show we're loading
        var nameDisplay = document.getElementById('endpoint-name-display');
        if (nameDisplay) {
            var nameSpan = nameDisplay.querySelector('span');
            if (nameSpan) nameSpan.textContent = nodeName || 'Loading...';
        }

        // Clear device type while loading
        var currentDeviceType = document.getElementById('current-device-type');
        if (currentDeviceType) currentDeviceType.textContent = '';

        // Hide vendor/model badges
        var vendorBadge = document.getElementById('device-vendor-badge');
        if (vendorBadge) vendorBadge.style.display = 'none';
        var modelBadge = document.getElementById('device-model-badge');
        if (modelBadge) modelBadge.style.display = 'none';

        // Reset stats to show loading
        document.querySelectorAll('.stats .stat-number').forEach(function(el) {
            el.textContent = '-';
        });

        // Show loading in all containers
        var containers = ['protocols-container', 'ports-container', 'hostnames-container', 'ips-container', 'macs-container'];
        containers.forEach(function(containerId) {
            var container = document.getElementById(containerId);
            if (container) {
                container.innerHTML = '<div class="empty-state">Loading...</div>';
            }
        });

        // Reset bytes display
        var bytesIn = document.getElementById('bytes-in');
        var bytesOut = document.getElementById('bytes-out');
        if (bytesIn) bytesIn.textContent = '-';
        if (bytesOut) bytesOut.textContent = '-';
    };

})();
