/**
 * Device Control Module - Device control (Roku, Samsung, WOL, etc.)
 */
(function(App) {
    'use strict';

    App.DeviceControl = {
        /**
         * Switch between Details and Control tabs
         */
        switchDetailTab: function(btn, tabId) {
            // Deactivate all tabs
            document.querySelectorAll('.detail-tab').forEach(function(t) {
                t.classList.remove('active');
            });
            document.querySelectorAll('.detail-tab-content').forEach(function(c) {
                c.classList.remove('active');
            });

            // Activate clicked tab
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');

            // Load device capabilities when Control tab is clicked
            if (tabId === 'control-tab-content' && !App.state.deviceCapabilitiesLoaded) {
                App.DeviceControl.loadCapabilities();
            }
        },

        /**
         * Load device capabilities from the API
         */
        loadCapabilities: function() {
            // Mark as loading to prevent refresh interruption
            App.state.deviceCapabilitiesLoaded = false;

            var loadingEl = document.getElementById('control-loading');
            var contentEl = document.getElementById('control-content');
            var noControlEl = document.getElementById('no-control-message');
            var pairingRequiredEl = document.getElementById('pairing-required');
            var rokuRemoteEl = document.getElementById('roku-remote');
            var samsungRemoteEl = document.getElementById('samsung-remote');
            var thinqSetupEl = document.getElementById('thinq-setup-required');
            var thinqRemoteEl = document.getElementById('thinq-remote');
            var deviceInfoEl = document.getElementById('device-info-section');
            var appsSectionEl = document.getElementById('apps-section');

            var hideAll = function() {
                if (noControlEl) noControlEl.style.display = 'none';
                if (pairingRequiredEl) pairingRequiredEl.style.display = 'none';
                if (rokuRemoteEl) rokuRemoteEl.style.display = 'none';
                if (samsungRemoteEl) samsungRemoteEl.style.display = 'none';
                if (thinqSetupEl) thinqSetupEl.style.display = 'none';
                if (thinqRemoteEl) thinqRemoteEl.style.display = 'none';
                if (deviceInfoEl) deviceInfoEl.style.display = 'none';
                if (appsSectionEl) appsSectionEl.style.display = 'none';
            };

            if (loadingEl) loadingEl.style.display = 'block';
            if (contentEl) contentEl.style.display = 'none';
            hideAll();

            // Get device IP from data attribute set by template
            var controlContent = document.getElementById('control-content');
            var ipsStr = controlContent ? controlContent.dataset.ips || '' : '';
            var ips = ipsStr.split(',').filter(function(ip) { return ip.trim(); });

            if (ips.length === 0) {
                if (loadingEl) loadingEl.style.display = 'none';
                if (contentEl) contentEl.style.display = 'block';
                if (noControlEl) noControlEl.style.display = 'block';
                App.state.deviceCapabilitiesLoaded = true;
                return;
            }

            App.state.currentDeviceIp = ips[0].trim();

            // Get device type and hostname from data attributes
            var deviceType = controlContent ? controlContent.dataset.deviceType || null : null;
            var endpointName = controlContent ? controlContent.dataset.endpointName || '' : '';

            var url = '/api/device/capabilities?ip=' + encodeURIComponent(App.state.currentDeviceIp);
            if (deviceType) url += '&device_type=' + encodeURIComponent(deviceType);
            if (endpointName) url += '&hostname=' + encodeURIComponent(endpointName);

            // Add timeout for slow/unreachable devices
            var controller = new AbortController();
            var timeoutId = setTimeout(function() { controller.abort(); }, 8000);

            fetch(url, { signal: controller.signal })
                .then(function(response) {
                    clearTimeout(timeoutId);
                    return response.json();
                })
                .then(function(capabilities) {
                    if (loadingEl) loadingEl.style.display = 'none';
                    if (contentEl) contentEl.style.display = 'block';
                    hideAll();

                    if (capabilities.can_control) {
                        App.state.currentDeviceType = capabilities.device_type;

                        // Check if pairing is required (Samsung TVs)
                        if (capabilities.needs_pairing && !capabilities.is_paired) {
                            if (pairingRequiredEl) pairingRequiredEl.style.display = 'block';
                            App.state.deviceCapabilitiesLoaded = true;
                            return;
                        }

                        // Show device info if available
                        if (capabilities.device_info && deviceInfoEl) {
                            deviceInfoEl.style.display = 'block';
                            var modelEl = document.getElementById('device-model');
                            var info = capabilities.device_info;
                            var infoText = info.name || info.model || (capabilities.device_type === 'roku' ? 'Roku Device' : 'Samsung TV');
                            if (info.software_version) {
                                infoText += ' (v' + info.software_version + ')';
                            }
                            if (modelEl) modelEl.textContent = infoText;
                        }

                        // Show device-specific controls
                        if (capabilities.device_type === 'roku') {
                            if (rokuRemoteEl) rokuRemoteEl.style.display = 'block';

                            // Show apps if available
                            if (capabilities.apps && capabilities.apps.length > 0 && appsSectionEl) {
                                appsSectionEl.style.display = 'block';
                                var appsGrid = document.getElementById('apps-grid');
                                if (appsGrid) {
                                    appsGrid.innerHTML = '';

                                    capabilities.apps.forEach(function(app) {
                                        var btn = document.createElement('button');
                                        btn.className = 'app-btn';
                                        btn.onclick = function() { App.DeviceControl.launchApp(app.id); };
                                        btn.title = app.name;

                                        if (app.icon_url) {
                                            var img = document.createElement('img');
                                            img.src = app.icon_url;
                                            img.alt = app.name;
                                            img.onerror = function() { img.style.display = 'none'; };
                                            btn.appendChild(img);
                                        }

                                        var name = document.createElement('span');
                                        name.textContent = app.name.length > 12 ? app.name.substring(0, 12) + '...' : app.name;
                                        btn.appendChild(name);

                                        appsGrid.appendChild(btn);
                                    });
                                }
                            }
                        } else if (capabilities.device_type === 'samsung') {
                            if (samsungRemoteEl) samsungRemoteEl.style.display = 'block';
                        } else if (capabilities.device_type && capabilities.device_type.startsWith('lg_thinq')) {
                            // Check if ThinQ is configured
                            if (App.ThinQ) {
                                App.ThinQ.handleDevice(capabilities, thinqSetupEl, thinqRemoteEl, deviceInfoEl);
                            }
                        }
                    } else {
                        // Check if this might be a ThinQ-compatible device
                        if (endpointName.toLowerCase().includes('lma') || endpointName.toLowerCase().includes('lg')) {
                            if (App.ThinQ) {
                                App.ThinQ.handleDevice(null, thinqSetupEl, thinqRemoteEl, deviceInfoEl);
                            }
                        } else {
                            if (noControlEl) noControlEl.style.display = 'block';
                        }
                    }

                    App.state.deviceCapabilitiesLoaded = true;
                })
                .catch(function(error) {
                    clearTimeout(timeoutId);
                    console.error('Failed to load device capabilities:', error);
                    if (loadingEl) loadingEl.style.display = 'none';
                    if (contentEl) contentEl.style.display = 'block';
                    hideAll();
                    if (noControlEl) {
                        noControlEl.style.display = 'block';
                        // Show timeout message if it was an abort
                        if (error.name === 'AbortError') {
                            noControlEl.innerHTML = '<p>Device not reachable (connection timeout)</p><p style="font-size: 0.8rem; color: var(--text-secondary);">The device may be on an isolated network (e.g., iPhone hotspot)</p>';
                        }
                    }
                    App.state.deviceCapabilitiesLoaded = true;
                });
        },

        /**
         * Send a command to the device
         */
        sendCommand: function(command) {
            if (!App.state.currentDeviceIp || !App.state.currentDeviceType) {
                console.error('No device selected');
                return;
            }

            fetch('/api/device/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: App.state.currentDeviceIp,
                    command: command,
                    device_type: App.state.currentDeviceType
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (!result.success) {
                    console.error('Command failed:', result.message);
                }
            })
            .catch(function(error) {
                console.error('Failed to send command:', error);
            });
        },

        /**
         * Launch an app on the device
         */
        launchApp: function(appId) {
            if (!App.state.currentDeviceIp || !App.state.currentDeviceType) {
                console.error('No device selected');
                return;
            }

            fetch('/api/device/launch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: App.state.currentDeviceIp,
                    app_id: appId,
                    device_type: App.state.currentDeviceType
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (!result.success) {
                    console.error('App launch failed:', result.message);
                }
            })
            .catch(function(error) {
                console.error('Failed to launch app:', error);
            });
        },

        /**
         * Pair with a device (Samsung TVs)
         */
        pairDevice: function() {
            if (!App.state.currentDeviceIp || !App.state.currentDeviceType) {
                console.error('No device selected');
                return;
            }

            var statusEl = document.getElementById('pairing-status');
            if (statusEl) {
                statusEl.textContent = 'Connecting... Please check your TV for an approval prompt.';
                statusEl.style.color = 'var(--accent-primary)';
            }

            fetch('/api/device/pair', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: App.state.currentDeviceIp,
                    device_type: App.state.currentDeviceType
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    if (statusEl) {
                        statusEl.textContent = result.message;
                        statusEl.style.color = 'var(--accent-success)';
                    }
                    // Reload capabilities to show the remote
                    App.state.deviceCapabilitiesLoaded = false;
                    setTimeout(function() { App.DeviceControl.loadCapabilities(); }, 1000);
                } else {
                    if (statusEl) {
                        statusEl.textContent = result.message;
                        statusEl.style.color = '#ef4444';
                    }
                }
            })
            .catch(function(error) {
                console.error('Pairing failed:', error);
                if (statusEl) {
                    statusEl.textContent = 'Pairing failed. Please try again.';
                    statusEl.style.color = '#ef4444';
                }
            });
        }
    };

    // Expose functions globally for onclick handlers
    window.switchDetailTab = App.DeviceControl.switchDetailTab;
    window.loadDeviceCapabilities = App.DeviceControl.loadCapabilities;
    window.sendCommand = App.DeviceControl.sendCommand;
    window.launchApp = App.DeviceControl.launchApp;
    window.pairDevice = App.DeviceControl.pairDevice;

})(window.App);
