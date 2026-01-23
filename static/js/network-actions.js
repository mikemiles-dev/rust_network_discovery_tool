/**
 * Network Actions Module - Ping, probe, and scan functions
 */
(function(App) {
    'use strict';

    App.NetworkActions = {
        /**
         * Get the current device IP
         */
        getDeviceIp: function() {
            var controlContent = document.getElementById('control-content');
            if (controlContent) {
                var ips = controlContent.dataset.ips;
                if (ips) {
                    return ips.split(',')[0].trim();
                }
            }
            return App.state.currentDeviceIp;
        },

        /**
         * Ping the current device
         */
        ping: function() {
            var ip = App.NetworkActions.getDeviceIp();
            if (!ip) {
                alert('No device IP available');
                return;
            }

            var resultEl = document.getElementById('ping-result');
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.innerHTML = '<span style="color: rgba(255,255,255,0.7);">Pinging ' + ip + '...</span>';
            }

            fetch('/api/ping', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (resultEl) {
                    if (result.success) {
                        var latency = result.latency_ms ? result.latency_ms.toFixed(2) + ' ms' : 'N/A';
                        resultEl.innerHTML = '<span style="color: #22c55e;">&#10003; Host is reachable</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">Latency: ' + latency + '</span>';
                    } else {
                        resultEl.innerHTML = '<span style="color: #ef4444;">&#10007; Host unreachable</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">' + (result.message || 'No response') + '</span>';
                    }
                }
            })
            .catch(function(error) {
                if (resultEl) {
                    resultEl.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
                }
            });
        },

        /**
         * Probe hostname via reverse DNS/mDNS
         */
        probeHostname: function() {
            var ip = App.NetworkActions.getDeviceIp();
            if (!ip) {
                alert('No device IP available');
                return;
            }

            var resultEl = document.getElementById('probe-hostname-result');
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.innerHTML = '<span style="color: rgba(255,255,255,0.7);">Probing hostname for ' + ip + '...</span>';
            }

            fetch('/api/probe-hostname', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (resultEl) {
                    if (result.hostname) {
                        var currentName = App.NetworkActions.getCurrentEndpointName();
                        var applyButton = '';
                        if (result.hostname !== currentName) {
                            applyButton = '<br><button onclick="App.NetworkActions.applyHostname(\'' +
                                App.Utils.escapeHtml(result.hostname).replace(/'/g, "\\'") +
                                '\')" style="margin-top: 0.5rem; padding: 0.35rem 0.75rem; background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.4); color: #10b981; border-radius: 0.25rem; cursor: pointer; font-size: 0.8rem;">Apply as endpoint name</button>';
                        }

                        resultEl.innerHTML = '<span style="color: #22c55e;">&#10003; Hostname found: </span>' +
                            '<span style="color: white; font-weight: 500;">' + App.Utils.escapeHtml(result.hostname) + '</span>' + applyButton;
                    } else {
                        resultEl.innerHTML = '<span style="color: #f59e0b;">No hostname found</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">Could not resolve via DNS or mDNS</span>';
                    }
                }
            })
            .catch(function(error) {
                if (resultEl) {
                    resultEl.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
                }
            });
        },

        /**
         * Probe device model via web interface
         */
        probeModel: function() {
            var ip = App.NetworkActions.getDeviceIp();
            if (!ip) {
                alert('No device IP available');
                return;
            }

            var resultEl = document.getElementById('probe-model-result');
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.innerHTML = '<span style="color: rgba(255,255,255,0.7);">Probing model for ' + ip + '...</span>';
            }

            fetch('/api/endpoint/probe/model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (resultEl) {
                    if (result.model) {
                        resultEl.innerHTML = '<span style="color: #22c55e;">&#10003; Model detected</span><br>' +
                            '<span style="color: white; font-weight: 500;">' + result.model + '</span>';
                    } else {
                        resultEl.innerHTML = '<span style="color: #f59e0b;">No model detected</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">' + (result.message || 'Could not detect device model') + '</span>';
                    }
                }
            })
            .catch(function(error) {
                if (resultEl) {
                    resultEl.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
                }
            });
        },

        /**
         * Scan common ports on the device
         */
        portScan: function() {
            var ip = App.NetworkActions.getDeviceIp();
            if (!ip) {
                alert('No device IP available');
                return;
            }

            var resultEl = document.getElementById('port-scan-result');
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.innerHTML = '<span style="color: rgba(255,255,255,0.7);">Scanning ports on ' + ip + '...</span>';
            }

            fetch('/api/port-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (resultEl) {
                    if (result.open_ports && result.open_ports.length > 0) {
                        var portsHtml = result.open_ports.map(function(p) {
                            var service = p.service ? ' <span style="color: rgba(255,255,255,0.7);">(' + p.service + ')</span>' : '';
                            return '<span style="color: #22c55e;">' + p.port + '</span>' + service;
                        }).join(', ');
                        resultEl.innerHTML = '<span style="color: #22c55e;">&#10003; ' + result.open_ports.length + ' open port(s) found</span><br>' + portsHtml;
                    } else {
                        resultEl.innerHTML = '<span style="color: #f59e0b;">No open ports found</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">Common ports appear to be closed or filtered</span>';
                    }
                }
            })
            .catch(function(error) {
                if (resultEl) {
                    resultEl.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
                }
            });
        },

        /**
         * Get the current endpoint name from the details pane
         */
        getCurrentEndpointName: function() {
            var controlContent = document.getElementById('control-content');
            if (controlContent && controlContent.dataset.endpointName) {
                return controlContent.dataset.endpointName;
            }
            // Fallback to the display span
            var nameDisplay = document.querySelector('#endpoint-name-display span');
            if (nameDisplay) {
                return nameDisplay.textContent.trim();
            }
            return '';
        },

        /**
         * Probe NetBIOS name (Windows/SMB devices)
         */
        probeNetBios: function() {
            var ip = App.NetworkActions.getDeviceIp();
            if (!ip) {
                alert('No device IP available');
                return;
            }

            var resultEl = document.getElementById('probe-netbios-result');
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.innerHTML = '<span style="color: rgba(255,255,255,0.7);">Querying NetBIOS for ' + ip + '...</span>';
            }

            fetch('/api/probe-netbios', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (resultEl) {
                    if (result.netbios_name) {
                        var html = '<span style="color: #22c55e;">&#10003; NetBIOS name: </span>' +
                            '<span style="color: white; font-weight: 500;">' + App.Utils.escapeHtml(result.netbios_name) + '</span>';
                        if (result.group_name) {
                            html += '<br><span style="color: rgba(255,255,255,0.7);">Workgroup: ' + App.Utils.escapeHtml(result.group_name) + '</span>';
                        }
                        if (result.mac) {
                            html += '<br><span style="color: rgba(255,255,255,0.7);">MAC: ' + App.Utils.escapeHtml(result.mac) + '</span>';
                        }
                        resultEl.innerHTML = html;
                    } else {
                        resultEl.innerHTML = '<span style="color: #f59e0b;">No NetBIOS response</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">Device may not support NetBIOS (non-Windows)</span>';
                    }
                }
            })
            .catch(function(error) {
                if (resultEl) {
                    resultEl.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
                }
            });
        },

        /**
         * Apply a discovered hostname as the endpoint name
         */
        applyHostname: function(hostname) {
            var currentName = App.NetworkActions.getCurrentEndpointName();
            if (!currentName) {
                alert('Could not determine current endpoint name');
                return;
            }

            var resultEl = document.getElementById('probe-hostname-result');
            if (resultEl) {
                resultEl.innerHTML = '<span style="color: rgba(255,255,255,0.7);">Applying hostname...</span>';
            }

            fetch('/api/endpoint/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    old_name: currentName,
                    new_name: hostname
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    if (resultEl) {
                        resultEl.innerHTML = '<span style="color: #22c55e;">&#10003; Endpoint renamed to: ' + App.Utils.escapeHtml(hostname) + '</span><br>' +
                            '<span style="color: rgba(255,255,255,0.7);">Refreshing page...</span>';
                    }
                    // Reload to show updated name
                    setTimeout(function() {
                        window.location.href = '/?endpoint=' + encodeURIComponent(hostname);
                    }, 500);
                } else {
                    if (resultEl) {
                        resultEl.innerHTML = '<span style="color: #ef4444;">Failed to rename: ' + (result.message || 'Unknown error') + '</span>';
                    }
                }
            })
            .catch(function(error) {
                if (resultEl) {
                    resultEl.innerHTML = '<span style="color: #ef4444;">Error: ' + error.message + '</span>';
                }
            });
        },

        /**
         * Ping from the table view (quick ping with inline result)
         */
        pingFromTable: function(btn, ip) {
            if (!ip) return;

            var statusEl = btn.querySelector('.ping-status');
            var row = btn.closest('tr');
            var statusIndicator = row ? row.querySelector('.status-indicator') : null;

            btn.classList.remove('success', 'failed');
            btn.classList.add('pinging');
            statusEl.textContent = '...';

            fetch('/api/ping', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                btn.classList.remove('pinging');
                if (result.success) {
                    btn.classList.add('success');
                    var latency = result.latency_ms ? Math.round(result.latency_ms) + 'ms' : '✓';
                    statusEl.textContent = latency;
                    // Update status indicator to online (green)
                    if (statusIndicator) {
                        statusIndicator.classList.remove('offline', 'unreachable');
                        statusIndicator.classList.add('online');
                        statusIndicator.title = 'Online (ping: ' + latency + ')';
                        // Mark as ping-verified so refresh doesn't overwrite
                        statusIndicator.dataset.pingVerified = Date.now();
                    }
                } else {
                    btn.classList.add('failed');
                    statusEl.textContent = '✗';
                    // Update status indicator to unreachable (red)
                    if (statusIndicator) {
                        statusIndicator.classList.remove('online', 'offline');
                        statusIndicator.classList.add('unreachable');
                        statusIndicator.title = 'Unreachable';
                        // Mark as ping-verified so refresh doesn't overwrite
                        statusIndicator.dataset.pingVerified = Date.now();
                    }
                }
                // Clear button status after 5 seconds (but keep indicator)
                setTimeout(function() {
                    btn.classList.remove('success', 'failed');
                    statusEl.textContent = '';
                }, 5000);
            })
            .catch(function() {
                btn.classList.remove('pinging');
                btn.classList.add('failed');
                statusEl.textContent = '✗';
                // Update status indicator to unreachable (red)
                if (statusIndicator) {
                    statusIndicator.classList.remove('online', 'offline');
                    statusIndicator.classList.add('unreachable');
                    statusIndicator.title = 'Unreachable';
                }
                setTimeout(function() {
                    btn.classList.remove('failed');
                    statusEl.textContent = '';
                }, 5000);
            });
        }
    };

    // Expose pingFromTable globally for onclick handlers
    window.pingFromTable = App.NetworkActions.pingFromTable;

})(window.App);
