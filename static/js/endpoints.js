/**
 * Endpoints Module - Selection, navigation, probing coordinator
 */
(function(App) {
    'use strict';

    // Model polling state
    var modelPollIntervalId = null;
    var currentPollingEndpoint = null;

    App.Endpoints = App.Endpoints || {};

    /**
     * Start polling for model updates (for devices being probed)
     */
    App.Endpoints.startModelPolling = function(endpointName, currentModel) {
        // Stop any existing polling
        App.Endpoints.stopModelPolling();

        currentPollingEndpoint = endpointName;
        var pollCount = 0;
        var maxPolls = 5; // Poll for max 10 seconds (every 2000ms)

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
        }, 2000); // Poll every 2s (5 polls = 10s window)
    };

    /**
     * Stop model polling
     */
    App.Endpoints.stopModelPolling = function() {
        if (modelPollIntervalId) {
            clearInterval(modelPollIntervalId);
            modelPollIntervalId = null;
        }
        currentPollingEndpoint = null;
    };

    /**
     * Select a node and update URL
     */
    App.Endpoints.selectNode = function(nodeId) {
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
    };

    /**
     * Probe endpoint for additional device info (SNMP, NetBIOS)
     * Runs in background and updates UI if new info found
     */
    App.Endpoints.probeEndpoint = function(endpointName) {
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
                        // Stop model polling if probe found a specific model
                        var genericModels = ['HP Device', 'Amazon Device', 'Amazon Echo', 'Google Device', ''];
                        if (data.device_model && genericModels.indexOf(data.device_model) === -1) {
                            App.Endpoints.stopModelPolling();
                        }
                    });
            }
        })
        .catch(function(error) {
            console.log('Probe failed (device may not support SNMP/NetBIOS):', error);
        });
    };

    /**
     * Unselect node and update URL
     */
    App.Endpoints.unselectNode = function() {
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

        // Hide endpoint actions container
        var actionsContainer = document.getElementById('endpoint-actions-container');
        if (actionsContainer) actionsContainer.style.display = 'none';

        // Hide Control tab (will be shown again when a controllable device is selected)
        var controlTabBtn = document.getElementById('control-tab-btn');
        if (controlTabBtn) controlTabBtn.style.display = 'none';

        // Reset device capabilities so they reload for the next device
        App.state.deviceCapabilitiesLoaded = false;

        // Reset to Details tab if Control tab was active
        var detailsTab = document.querySelector('.detail-tab[data-tab="details-tab-content"]');
        var controlTabContent = document.getElementById('control-tab-content');
        if (detailsTab && controlTabContent && controlTabContent.classList.contains('active')) {
            switchDetailTab(detailsTab, 'details-tab-content');
        }
    };

    /**
     * Scroll to section in details panel
     */
    App.Endpoints.scrollToSection = function(sectionId) {
        var section = document.getElementById(sectionId);
        if (section) {
            section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    };

    /**
     * Probe an IP address for its hostname using reverse DNS/mDNS
     */
    App.Endpoints.probeHostname = function(ip) {
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
