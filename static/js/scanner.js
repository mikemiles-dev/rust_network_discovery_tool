/**
 * Scanner Module - Network scanning controls
 */
(function(App) {
    'use strict';

    var autoScanIntervalId = null;
    var indicatorPollId = null;
    var currentPollRate = 5000; // Start in slow mode
    var wasRunning = false; // Track scan state transitions to avoid reload loops

    App.Scanner = {
        /**
         * Start network scan with selected scan types
         */
        start: function() {
            var scanTypes = [];
            if (document.getElementById('scan-arp').checked) scanTypes.push('arp');
            if (document.getElementById('scan-icmp').checked) scanTypes.push('icmp');
            if (document.getElementById('scan-port').checked) scanTypes.push('port');
            if (document.getElementById('scan-ssdp').checked) scanTypes.push('ssdp');
            if (document.getElementById('scan-netbios').checked) scanTypes.push('netbios');
            if (document.getElementById('scan-snmp').checked) scanTypes.push('snmp');

            if (scanTypes.length === 0) {
                alert('Please select at least one scan type');
                return;
            }

            // Hide start button, show stop button
            document.getElementById('start-scan-btn').style.display = 'none';
            document.getElementById('stop-scan-btn').style.display = 'block';
            document.getElementById('scan-progress').style.display = 'block';

            fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_types: scanTypes })
            })
            .then(function(response) {
                if (response.ok) {
                    wasRunning = true;
                    // Switch unified poller to fast mode
                    App.Scanner.setPollingRate(500);
                } else {
                    return response.json().then(function(result) {
                        alert('Scan failed: ' + result.message);
                        App.Scanner.resetButton();
                    });
                }
            })
            .catch(function(e) {
                alert('Error starting scan: ' + e);
                App.Scanner.resetButton();
            });
        },

        /**
         * Stop network scan
         */
        stop: function() {
            var stopBtn = document.getElementById('stop-scan-btn');
            stopBtn.textContent = 'Stopping...';
            stopBtn.disabled = true;
            stopBtn.style.opacity = '0.6';

            fetch('/api/scan/stop', { method: 'POST' })
                .catch(function(e) {
                    console.error('Error stopping scan:', e);
                    App.Scanner.resetButton();
                });
        },

        /**
         * Poll scan status and update both scanner tab UI and network tab indicator
         */
        pollStatus: function() {
            fetch('/api/scan/status')
                .then(function(response) {
                    return response.json();
                })
                .then(function(status) {
                    // Update scanner tab progress UI (elements may not exist if not on scanner tab)
                    var progressFill = document.getElementById('scan-progress-fill');
                    var progressText = document.getElementById('scan-progress-text');
                    var phaseEl = document.getElementById('scan-phase');
                    var discoveredEl = document.getElementById('discovered-count');
                    var lastScanEl = document.getElementById('last-scan-time');

                    if (progressFill) progressFill.style.width = status.progress_percent + '%';
                    if (progressText) progressText.textContent = status.progress_percent + '%';
                    if (phaseEl) phaseEl.textContent = status.current_phase || 'Scanning...';
                    if (discoveredEl) discoveredEl.textContent = status.discovered_count;

                    if (status.last_scan_time && lastScanEl) {
                        var date = new Date(status.last_scan_time * 1000);
                        lastScanEl.textContent = date.toLocaleTimeString();
                    }

                    // Update network tab scan indicator
                    var indicator = document.getElementById('scan-indicator');
                    if (indicator) {
                        if (status.running) {
                            indicator.style.display = 'flex';
                            var phase = document.getElementById('scan-indicator-phase');
                            var progress = document.getElementById('scan-indicator-progress');
                            if (phase) phase.textContent = status.current_phase || '...';
                            if (progress) progress.textContent = status.progress_percent + '%';
                        } else {
                            indicator.style.display = 'none';
                        }
                    }

                    if (!status.running) {
                        // Switch to slow mode
                        App.Scanner.setPollingRate(5000);
                        App.Scanner.resetButton();

                        // Only reload once when scan transitions from running to not-running
                        if (wasRunning && status.discovered_count > 0) {
                            wasRunning = false;
                            setTimeout(function() {
                                var url = new URL(window.location.href);
                                url.searchParams.set('tab', 'scanner');
                                window.location.href = url.toString();
                            }, 500);
                        }
                        wasRunning = false;
                    } else {
                        wasRunning = true;
                        if (currentPollRate !== 500) {
                            // Scan started externally (auto-scan), switch to fast mode
                            App.Scanner.setPollingRate(500);
                        }
                    }
                })
                .catch(function(e) {
                    console.error('Error polling scan status:', e);
                });
        },

        /**
         * Change the polling rate of the unified poller
         */
        setPollingRate: function(rateMs) {
            if (currentPollRate === rateMs && indicatorPollId) return;
            currentPollRate = rateMs;
            if (indicatorPollId) {
                clearInterval(indicatorPollId);
            }
            indicatorPollId = setInterval(App.Scanner.pollStatus, rateMs);
        },

        /**
         * Start the unified scan indicator/status poller
         */
        startIndicatorPolling: function() {
            // Initial check
            App.Scanner.pollStatus();
            // Start in slow mode (5s), will switch to fast (500ms) if scan is active
            indicatorPollId = setInterval(App.Scanner.pollStatus, 5000);
        },

        /**
         * Reset scan button to initial state
         */
        resetButton: function() {
            // Reset and show start button
            var startBtn = document.getElementById('start-scan-btn');
            if (startBtn) {
                startBtn.textContent = 'Scan Network';
                startBtn.disabled = false;
                startBtn.style.opacity = '1';
                startBtn.style.display = 'block';
            }

            // Reset and hide stop button
            var stopBtn = document.getElementById('stop-scan-btn');
            if (stopBtn) {
                stopBtn.textContent = 'Stop Scan';
                stopBtn.disabled = false;
                stopBtn.style.opacity = '1';
                stopBtn.style.display = 'none';
            }

            var scanProgress = document.getElementById('scan-progress');
            if (scanProgress) scanProgress.style.display = 'none';
        },

        /**
         * Check scan capabilities on load
         */
        checkCapabilities: function() {
            fetch('/api/scan/capabilities')
                .then(function(response) {
                    return response.json();
                })
                .then(function(caps) {
                    var needsPrivileges = false;

                    // Disable checkboxes for unavailable scan types
                    if (!caps.can_arp) {
                        document.getElementById('scan-arp').disabled = true;
                        document.getElementById('scan-arp').checked = false;
                        document.getElementById('scan-arp').parentElement.style.opacity = '0.5';
                        document.getElementById('scan-arp').parentElement.title = 'Requires root/admin privileges';
                        needsPrivileges = true;
                    }
                    if (!caps.can_icmp) {
                        document.getElementById('scan-icmp').disabled = true;
                        document.getElementById('scan-icmp').checked = false;
                        document.getElementById('scan-icmp').parentElement.style.opacity = '0.5';
                        document.getElementById('scan-icmp').parentElement.title = 'Requires root/admin privileges';
                        needsPrivileges = true;
                    }

                    // Show privilege warning if needed
                    var warning = document.getElementById('privilege-warning');
                    if (warning) {
                        warning.style.display = needsPrivileges ? 'block' : 'none';
                    }
                })
                .catch(function(e) {
                    console.error('Error checking scan capabilities:', e);
                });
        },

        /**
         * Start automatic scanning based on settings
         */
        startAutoScan: function() {
            // Clear any existing auto-scan interval
            if (autoScanIntervalId) {
                clearInterval(autoScanIntervalId);
                autoScanIntervalId = null;
            }

            // Fetch settings to get the auto-scan interval
            fetch('/api/settings')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var settings = data.settings || {};
                    var intervalMinutes = parseInt(settings.auto_scan_interval_minutes, 10) || 0;

                    if (intervalMinutes > 0) {
                        var intervalMs = intervalMinutes * 60 * 1000;
                        console.log('Auto-scan enabled: running every ' + intervalMinutes + ' minutes');

                        autoScanIntervalId = setInterval(function() {
                            // Only start auto-scan if no scan is currently running
                            fetch('/api/scan/status')
                                .then(function(response) { return response.json(); })
                                .then(function(status) {
                                    if (!status.running) {
                                        console.log('Auto-scan triggered');
                                        App.Scanner.runAutoScan();
                                    } else {
                                        console.log('Auto-scan skipped: scan already in progress');
                                    }
                                });
                        }, intervalMs);
                    }
                })
                .catch(function(e) {
                    console.error('Error loading auto-scan settings:', e);
                });
        },

        /**
         * Run an automatic scan with all available scan types
         */
        runAutoScan: function() {
            // Get all enabled scan types
            var scanTypes = [];
            var arpCheck = document.getElementById('scan-arp');
            var icmpCheck = document.getElementById('scan-icmp');
            var portCheck = document.getElementById('scan-port');
            var ssdpCheck = document.getElementById('scan-ssdp');
            var netbiosCheck = document.getElementById('scan-netbios');
            var snmpCheck = document.getElementById('scan-snmp');

            // Use checked state, or default to enabled if not disabled
            if (arpCheck && !arpCheck.disabled) scanTypes.push('arp');
            if (icmpCheck && !icmpCheck.disabled) scanTypes.push('icmp');
            if (portCheck && !portCheck.disabled) scanTypes.push('port');
            if (ssdpCheck && !ssdpCheck.disabled) scanTypes.push('ssdp');
            if (netbiosCheck && !netbiosCheck.disabled) scanTypes.push('netbios');
            if (snmpCheck && !snmpCheck.disabled) scanTypes.push('snmp');

            if (scanTypes.length === 0) {
                console.log('Auto-scan: no scan types available');
                return;
            }

            // Update UI to show scan is running
            var startBtn = document.getElementById('start-scan-btn');
            var stopBtn = document.getElementById('stop-scan-btn');
            var progress = document.getElementById('scan-progress');
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'block';
            if (progress) progress.style.display = 'block';

            fetch('/api/scan/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_types: scanTypes })
            })
            .then(function(response) {
                if (response.ok) {
                    // Switch unified poller to fast mode
                    App.Scanner.setPollingRate(500);
                }
            })
            .catch(function(e) {
                console.error('Auto-scan error:', e);
                App.Scanner.resetButton();
            });
        }
    };

    // Expose functions globally for onclick handlers
    window.startNetworkScan = App.Scanner.start;
    window.stopNetworkScan = App.Scanner.stop;
    window.pollScanStatus = App.Scanner.pollStatus;
    window.checkScanCapabilities = App.Scanner.checkCapabilities;
    window.startAutoScan = App.Scanner.startAutoScan;

    // Start auto-scan timer on page load
    document.addEventListener('DOMContentLoaded', function() {
        App.Scanner.startAutoScan();
    });

})(window.App);
