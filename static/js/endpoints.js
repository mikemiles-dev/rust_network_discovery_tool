/**
 * Endpoints Module - Endpoint details panel management
 */
(function(App) {
    'use strict';

    // Model polling state
    var modelPollIntervalId = null;
    var currentPollingEndpoint = null;

    App.Endpoints = {
        /**
         * Start polling for model updates (for devices being probed)
         */
        startModelPolling: function(endpointName, currentModel) {
            // Stop any existing polling
            App.Endpoints.stopModelPolling();

            currentPollingEndpoint = endpointName;
            var pollCount = 0;
            var maxPolls = 20; // Poll for max 10 seconds (every 500ms)

            modelPollIntervalId = setInterval(function() {
                pollCount++;

                // Stop polling after max attempts
                if (pollCount >= maxPolls) {
                    App.Endpoints.stopModelPolling();
                    return;
                }

                // Fetch updated endpoint details
                fetch('/api/endpoint/' + encodeURIComponent(endpointName) + '/details')
                    .then(function(response) { return response.json(); })
                    .then(function(data) {
                        // Check if model has changed
                        if (data.device_model && data.device_model !== currentModel) {
                            // Update the model badge
                            var modelBadge = document.getElementById('device-model-badge');
                            if (modelBadge) {
                                modelBadge.textContent = data.device_model;
                                modelBadge.style.display = '';
                                // Add a brief highlight animation
                                modelBadge.style.transition = 'background-color 0.3s';
                                modelBadge.style.backgroundColor = 'rgba(139, 92, 246, 0.4)';
                                setTimeout(function() {
                                    modelBadge.style.backgroundColor = '';
                                }, 500);
                            }

                            // Also update the table row if visible
                            var tableRow = document.querySelector('.endpoint-row[data-endpoint="' + endpointName + '"]');
                            if (tableRow) {
                                var modelCell = tableRow.querySelector('.model-cell');
                                if (modelCell) {
                                    modelCell.textContent = data.device_model;
                                }
                            }

                            // Stop polling - we got the updated model
                            App.Endpoints.stopModelPolling();
                        }
                    })
                    .catch(function() {
                        // Ignore errors during polling
                    });
            }, 500); // Poll every 500ms for faster updates
        },

        /**
         * Stop model polling
         */
        stopModelPolling: function() {
            if (modelPollIntervalId) {
                clearInterval(modelPollIntervalId);
                modelPollIntervalId = null;
            }
            currentPollingEndpoint = null;
        },
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
            // (HP Device, Amazon Device, etc. are generic fallbacks that may be updated)
            // Also poll for HP vendor with no/empty model
            var genericModels = ['HP Device', 'Amazon Device', 'Amazon Echo', 'Google Device', ''];
            var isGenericModel = !data.device_model || genericModels.indexOf(data.device_model) !== -1;
            var isHpDevice = data.device_vendor === 'HP';
            if (isGenericModel && isHpDevice) {
                App.Endpoints.startModelPolling(data.endpoint_name, data.device_model || '');
            } else {
                // Stop any existing polling if we have a specific model
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
                        // Show probe button if no hostnames are known
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

            // Update control-content data attributes for network actions (ping, probe, etc.)
            var controlContent = document.getElementById('control-content');
            if (controlContent) {
                controlContent.dataset.ips = data.ips.join(',');
                controlContent.dataset.endpointName = data.endpoint_name;
                if (data.device_type) {
                    controlContent.dataset.deviceType = data.device_type;
                }
            }
        },

        /**
         * Show loading state in the details panel
         */
        showLoading: function(nodeName) {
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

            // Stop any existing model polling
            App.Endpoints.stopModelPolling();

            // Reset to Details tab when selecting a new endpoint, unless restoring from refresh
            var savedDetailTab = sessionStorage.getItem('activeDetailTab');
            if (!savedDetailTab) {
                var detailsTabBtn = document.querySelector('.detail-tab[data-tab="details-tab-content"]');
                if (detailsTabBtn && App.DeviceControl) {
                    App.DeviceControl.switchDetailTab(detailsTabBtn, 'details-tab-content');
                }
            }

            // Reset device capabilities loaded flag for new device
            App.state.deviceCapabilitiesLoaded = true;

            // Clear Network tab results from previous endpoint
            ['ping-result', 'probe-hostname-result', 'probe-model-result', 'port-scan-result', 'probe-netbios-result'].forEach(function(id) {
                var el = document.getElementById(id);
                if (el) {
                    el.style.display = 'none';
                    el.innerHTML = '';
                }
            });

            // Show the endpoint details overlay (may be hidden when no endpoint selected)
            var overlay = document.querySelector('.protocols-overlay');
            if (overlay) {
                overlay.style.display = '';
            }

            // Show loading state immediately to avoid showing stale data
            App.Endpoints.showLoading(nodeId);

            // Fetch endpoint details and update panel
            fetch('/api/endpoint/' + encodeURIComponent(nodeId) + '/details')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    App.Endpoints.updateDetails(data);
                    // Trigger background probe for more device info (SNMP, NetBIOS)
                    App.Endpoints.probeEndpoint(nodeId);
                })
                .catch(function(error) {
                    console.error('Error fetching endpoint details:', error);
                    // Fall back to page reload on error
                    window.location.href = url.toString();
                });
        },

        /**
         * Probe endpoint for additional device info (SNMP, NetBIOS)
         * Runs in background and updates UI if new info found
         */
        probeEndpoint: function(endpointName) {
            fetch('/api/endpoint/probe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint_name: endpointName })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    // Refresh details if we found new info
                    console.log('Probe found info:', result);
                    // Re-fetch details to show updated info
                    fetch('/api/endpoint/' + encodeURIComponent(endpointName) + '/details')
                        .then(function(response) { return response.json(); })
                        .then(function(data) {
                            App.Endpoints.updateDetails(data);
                        });
                }
            })
            .catch(function(error) {
                console.log('Probe failed (device may not support SNMP/NetBIOS):', error);
            });
        },

        /**
         * Unselect node and update URL
         */
        unselectNode: function() {
            // Stop any existing model polling
            App.Endpoints.stopModelPolling();

            var url = new URL(window.location.href);
            url.searchParams.delete('node');
            history.pushState({}, '', url.toString());

            // Clear table row selection
            document.querySelectorAll('.endpoint-row.selected').forEach(function(row) {
                row.classList.remove('selected');
            });

            // Hide the endpoint details overlay
            var overlay = document.querySelector('.protocols-overlay');
            if (overlay) {
                overlay.style.display = 'none';
            }

            // Clear endpoint details content
            var nameDisplay = document.querySelector('#endpoint-name-display span');
            if (nameDisplay) nameDisplay.textContent = 'No endpoint selected';

            // Hide rename button
            var renameBtn = document.getElementById('rename-btn');
            if (renameBtn) renameBtn.style.display = 'none';

            // Clear device type
            var deviceType = document.getElementById('current-device-type');
            if (deviceType) deviceType.textContent = '';

            // Hide device type selector
            var deviceTypeSelector = document.querySelector('.device-type-selector');
            if (deviceTypeSelector) deviceTypeSelector.style.display = 'none';

            // Hide manual override indicator
            var manualOverride = document.getElementById('manual-override-indicator');
            if (manualOverride) manualOverride.style.display = 'none';

            // Hide vendor and model badges and add buttons
            var vendorBadge = document.getElementById('device-vendor-badge');
            if (vendorBadge) vendorBadge.style.display = 'none';
            var modelBadge = document.getElementById('device-model-badge');
            if (modelBadge) modelBadge.style.display = 'none';
            var addVendorBtn = document.getElementById('add-vendor-btn');
            if (addVendorBtn) addVendorBtn.style.display = 'none';
            var addModelBtn = document.getElementById('add-model-btn');
            if (addModelBtn) addModelBtn.style.display = 'none';

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
         * Scroll to section in details panel
         */
        scrollToSection: function(sectionId) {
            var section = document.getElementById(sectionId);
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        },

        /**
         * Probe an IP address for its hostname using reverse DNS/mDNS
         */
        probeHostname: function(ip) {
            var btn = event.target;
            var originalText = btn.textContent;
            btn.textContent = 'Probing...';
            btn.disabled = true;

            fetch('/api/probe-hostname', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success && result.hostname) {
                    alert('Hostname found: ' + result.hostname);
                    // Refresh the page to show the new hostname
                    window.location.reload();
                } else {
                    alert('No hostname found for ' + ip + '. The device may not respond to reverse DNS queries.');
                    btn.textContent = originalText;
                    btn.disabled = false;
                }
            })
            .catch(function(error) {
                alert('Error probing hostname: ' + error);
                btn.textContent = originalText;
                btn.disabled = false;
            });
        },

        /**
         * Merge this endpoint into another endpoint
         */
        mergeEndpoint: function(sourceEndpoint) {
            var targetEndpoint = prompt('Merge "' + sourceEndpoint + '" into which endpoint?\n\nEnter the name, hostname, or IP of the target endpoint:');

            if (!targetEndpoint || !targetEndpoint.trim()) {
                return;
            }

            targetEndpoint = targetEndpoint.trim();

            if (targetEndpoint.toLowerCase() === sourceEndpoint.toLowerCase()) {
                alert('Cannot merge an endpoint into itself.');
                return;
            }

            if (!confirm('Merge "' + sourceEndpoint + '" into "' + targetEndpoint + '"?\n\nAll communications, attributes, and scan data from "' + sourceEndpoint + '" will be moved to "' + targetEndpoint + '", and "' + sourceEndpoint + '" will be deleted.')) {
                return;
            }

            fetch('/api/endpoint/merge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: targetEndpoint,
                    source: sourceEndpoint
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    alert(result.message);
                    // Navigate to the target endpoint
                    var url = new URL(window.location.href);
                    url.searchParams.set('node', targetEndpoint);
                    window.location.href = url.toString();
                } else {
                    alert('Failed to merge endpoints: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Error merging endpoints: ' + error);
            });
        },

        /**
         * Delete an endpoint and all associated data
         */
        deleteEndpoint: function(endpointName) {
            if (!confirm('Are you sure you want to delete "' + endpointName + '"?\n\nThis will permanently remove the endpoint and all associated communications.')) {
                return;
            }

            fetch('/api/endpoint/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint_name: endpointName })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    // Navigate to home page without the deleted endpoint
                    var url = new URL(window.location.href);
                    url.searchParams.delete('node');
                    window.location.href = url.toString();
                } else {
                    alert('Failed to delete endpoint: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Error deleting endpoint: ' + error);
            });
        }
    };

    /**
     * Handle keyboard navigation for endpoint table
     */
    function handleKeyboardNavigation(e) {
        // Only handle arrow keys when on network tab
        if (App.state.activeTab !== 'network') return;

        // Don't interfere with input fields
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
            return;
        }

        if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown' && e.key !== 'Escape') {
            return;
        }

        e.preventDefault();

        // Handle Escape to deselect
        if (e.key === 'Escape') {
            App.Endpoints.unselectNode();
            return;
        }

        // Get all visible endpoint rows
        var rows = Array.from(document.querySelectorAll('.endpoint-row')).filter(function(row) {
            return row.style.display !== 'none' && row.offsetParent !== null;
        });

        if (rows.length === 0) return;

        // Find currently selected row
        var selectedRow = document.querySelector('.endpoint-row.selected');
        var currentIndex = selectedRow ? rows.indexOf(selectedRow) : -1;

        var newIndex;
        if (e.key === 'ArrowDown') {
            newIndex = currentIndex < rows.length - 1 ? currentIndex + 1 : 0;
        } else {
            newIndex = currentIndex > 0 ? currentIndex - 1 : rows.length - 1;
        }

        var newRow = rows[newIndex];
        if (newRow) {
            var nodeId = newRow.dataset.endpoint;
            if (nodeId) {
                App.Endpoints.selectNode(nodeId);
                // Scroll row into view
                newRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            }
        }
    }

    // Add keyboard event listener
    document.addEventListener('keydown', handleKeyboardNavigation);

    // Expose functions globally for onclick handlers
    window.selectNode = App.Endpoints.selectNode;
    window.unselectNode = App.Endpoints.unselectNode;
    window.scrollToSection = App.Endpoints.scrollToSection;
    window.probeHostname = App.Endpoints.probeHostname;
    window.mergeEndpoint = App.Endpoints.mergeEndpoint;
    window.deleteEndpoint = App.Endpoints.deleteEndpoint;
    window.getDeviceTypeInfo = App.Endpoints.getDeviceTypeInfo;
    window.updateEndpointDetails = App.Endpoints.updateDetails;

})(window.App);
