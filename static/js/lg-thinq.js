/**
 * LG ThinQ Module - LG ThinQ smart appliance integration
 */
(function(App) {
    'use strict';

    App.ThinQ = {
        /**
         * Handle ThinQ device - check if configured and show appropriate UI
         */
        handleDevice: function(capabilities, setupEl, remoteEl, deviceInfoEl) {
            fetch('/api/thinq/status')
                .then(function(response) { return response.json(); })
                .then(function(status) {
                    if (!status.configured) {
                        if (setupEl) setupEl.style.display = 'block';
                        return;
                    }

                    // ThinQ is configured - find matching device
                    var matchedDevice = null;
                    if (capabilities && capabilities.device_type && capabilities.device_type.includes(':')) {
                        var deviceId = capabilities.device_type.split(':')[1];
                        matchedDevice = status.devices.find(function(d) {
                            return d.device_id === deviceId;
                        });
                    }

                    if (!matchedDevice && status.devices.length > 0) {
                        matchedDevice = status.devices[0];
                    }

                    if (matchedDevice) {
                        App.state.currentThinQDeviceId = matchedDevice.device_id;
                        App.state.currentThinQDeviceType = matchedDevice.device_type;
                        App.state.currentDeviceType = 'lg_thinq:' + matchedDevice.device_id;

                        // Show device info
                        if (deviceInfoEl) {
                            deviceInfoEl.style.display = 'block';
                            var modelEl = document.getElementById('device-model');
                            var infoText = matchedDevice.name || matchedDevice.device_type;
                            if (matchedDevice.model) {
                                infoText += ' (' + matchedDevice.model + ')';
                            }
                            infoText += matchedDevice.online ? ' - Online' : ' - Offline';
                            if (modelEl) modelEl.textContent = infoText;
                        }

                        // Show remote and populate controls
                        if (remoteEl) {
                            remoteEl.style.display = 'block';
                            App.ThinQ.populateControls(matchedDevice);
                            App.ThinQ.refreshStatus();
                        }
                    } else {
                        // No devices found
                        var statusEl = document.getElementById('thinq-device-status');
                        if (statusEl) {
                            statusEl.textContent = 'No ThinQ devices found. Make sure your appliances are registered in the LG ThinQ app.';
                        }
                        if (remoteEl) remoteEl.style.display = 'block';
                    }
                })
                .catch(function(error) {
                    console.error('Failed to check ThinQ status:', error);
                    if (setupEl) setupEl.style.display = 'block';
                });
        },

        /**
         * Populate ThinQ controls based on device type
         */
        populateControls: function(device) {
            var controlsEl = document.getElementById('thinq-controls');
            if (!controlsEl) return;

            controlsEl.innerHTML = '';
            var deviceType = device.device_type.toLowerCase();

            var addButton = function(label, command) {
                var btn = document.createElement('button');
                btn.className = 'remote-btn';
                btn.onclick = function() { App.ThinQ.sendCommand(command); };
                btn.textContent = label;
                btn.style.flex = '1';
                btn.style.minWidth = '100px';
                controlsEl.appendChild(btn);
            };

            if (deviceType.includes('dishwasher')) {
                addButton('Get Status', 'status');
                addButton('Start', 'start');
                addButton('Stop', 'stop');
            } else if (deviceType.includes('washer') || deviceType.includes('washing')) {
                addButton('Get Status', 'status');
                addButton('Start', 'start');
                addButton('Pause', 'pause');
                addButton('Stop', 'stop');
            } else if (deviceType.includes('dryer')) {
                addButton('Get Status', 'status');
                addButton('Start', 'start');
                addButton('Pause', 'pause');
                addButton('Stop', 'stop');
            } else if (deviceType.includes('refrigerator') || deviceType.includes('fridge')) {
                addButton('Get Status', 'status');
                addButton('Express Freeze', 'express_freeze');
                addButton('Eco Mode', 'eco_mode');
            } else if (deviceType.includes('air') || deviceType.includes('ac')) {
                addButton('Get Status', 'status');
                addButton('Power On', 'power_on');
                addButton('Power Off', 'power_off');
            } else {
                addButton('Get Status', 'status');
            }
        },

        /**
         * Setup ThinQ with PAT token
         */
        setup: function() {
            var patToken = document.getElementById('thinq-pat-token').value.trim();
            var countryCode = document.getElementById('thinq-country-code').value;
            var statusEl = document.getElementById('thinq-setup-status');

            if (!patToken) {
                if (statusEl) {
                    statusEl.textContent = 'Please enter your Personal Access Token.';
                    statusEl.style.color = '#ef4444';
                }
                return;
            }

            if (statusEl) {
                statusEl.textContent = 'Connecting to LG ThinQ...';
                statusEl.style.color = 'var(--accent-primary)';
            }

            fetch('/api/thinq/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    pat_token: patToken,
                    country_code: countryCode
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    if (statusEl) {
                        statusEl.textContent = result.message;
                        statusEl.style.color = 'var(--accent-success)';
                    }
                    // Reload capabilities to show controls
                    App.state.deviceCapabilitiesLoaded = false;
                    setTimeout(function() {
                        if (App.DeviceControl) App.DeviceControl.loadCapabilities();
                    }, 1000);
                } else {
                    if (statusEl) {
                        statusEl.textContent = result.message;
                        statusEl.style.color = '#ef4444';
                    }
                }
            })
            .catch(function(error) {
                console.error('ThinQ setup failed:', error);
                if (statusEl) {
                    statusEl.textContent = 'Setup failed. Please check your token and try again.';
                    statusEl.style.color = '#ef4444';
                }
            });
        },

        /**
         * Refresh ThinQ device status
         */
        refreshStatus: function() {
            if (!App.state.currentThinQDeviceId) {
                return;
            }

            var statusEl = document.getElementById('thinq-device-status');
            if (statusEl) statusEl.textContent = 'Refreshing status...';

            fetch('/api/device/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: App.state.currentDeviceIp || '0.0.0.0',
                    command: 'status',
                    device_type: 'lg_thinq:' + App.state.currentThinQDeviceId
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    var statusText = result.message;
                    if (result.data) {
                        statusText = App.ThinQ.formatStatus(result.data);
                    }
                    if (statusEl) {
                        statusEl.innerHTML = statusText;
                        statusEl.style.color = 'var(--text-secondary)';
                    }
                } else {
                    if (statusEl) {
                        statusEl.textContent = result.message;
                        statusEl.style.color = '#ef4444';
                    }
                }
            })
            .catch(function(error) {
                console.error('Failed to refresh ThinQ status:', error);
                if (statusEl) {
                    statusEl.textContent = 'Failed to get device status.';
                    statusEl.style.color = '#ef4444';
                }
            });
        },

        /**
         * Format ThinQ status data for display
         */
        formatStatus: function(data) {
            if (typeof data === 'string') {
                return data;
            }

            var html = '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.25rem;">';
            for (var key in data) {
                if (data.hasOwnProperty(key)) {
                    var label = key.replace(/_/g, ' ').replace(/\b\w/g, function(c) {
                        return c.toUpperCase();
                    });
                    html += '<div style="color: var(--text-secondary);">' + label + ':</div>';
                    html += '<div style="color: var(--text-primary);">' + data[key] + '</div>';
                }
            }
            html += '</div>';
            return html;
        },

        /**
         * Send ThinQ command
         */
        sendCommand: function(command) {
            if (!App.state.currentThinQDeviceId) {
                console.error('No ThinQ device selected');
                return;
            }

            var statusEl = document.getElementById('thinq-device-status');
            if (statusEl) statusEl.textContent = 'Sending ' + command + '...';

            fetch('/api/device/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: App.state.currentDeviceIp || '0.0.0.0',
                    command: command,
                    device_type: 'lg_thinq:' + App.state.currentThinQDeviceId
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    if (command === 'status' && result.data) {
                        if (statusEl) statusEl.innerHTML = App.ThinQ.formatStatus(result.data);
                    } else {
                        if (statusEl) {
                            statusEl.textContent = result.message;
                            statusEl.style.color = 'var(--accent-success)';
                        }
                        // Refresh status after a command
                        setTimeout(function() { App.ThinQ.refreshStatus(); }, 2000);
                    }
                } else {
                    if (statusEl) {
                        statusEl.textContent = result.message;
                        statusEl.style.color = '#ef4444';
                    }
                }
            })
            .catch(function(error) {
                console.error('ThinQ command failed:', error);
                if (statusEl) {
                    statusEl.textContent = 'Command failed. Please try again.';
                    statusEl.style.color = '#ef4444';
                }
            });
        },

        /**
         * Disconnect ThinQ
         */
        disconnect: function() {
            if (!confirm('Are you sure you want to disconnect from LG ThinQ? You will need to re-enter your PAT token.')) {
                return;
            }

            fetch('/api/thinq/disconnect', { method: 'POST' })
                .then(function() {
                    // Reload to show setup form
                    App.state.deviceCapabilitiesLoaded = false;
                    if (App.DeviceControl) App.DeviceControl.loadCapabilities();
                })
                .catch(function(error) {
                    console.error('Failed to disconnect ThinQ:', error);
                });
        }
    };

    // Expose functions globally for onclick handlers
    window.handleThinQDevice = App.ThinQ.handleDevice;
    window.populateThinQControls = App.ThinQ.populateControls;
    window.setupThinQ = App.ThinQ.setup;
    window.refreshThinQStatus = App.ThinQ.refreshStatus;
    window.formatThinQStatus = App.ThinQ.formatStatus;
    window.sendThinQCommand = App.ThinQ.sendCommand;
    window.disconnectThinQ = App.ThinQ.disconnect;

})(window.App);
