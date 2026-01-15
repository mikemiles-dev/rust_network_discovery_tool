/**
 * Scanner Module - Network scanning controls
 */
(function(App) {
    'use strict';

    var scanPollInterval = null;

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
                    // Start polling for status
                    scanPollInterval = setInterval(App.Scanner.pollStatus, 500);
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
         * Poll scan status from API
         */
        pollStatus: function() {
            fetch('/api/scan/status')
                .then(function(response) {
                    return response.json();
                })
                .then(function(status) {
                    document.getElementById('scan-progress-fill').style.width = status.progress_percent + '%';
                    document.getElementById('scan-progress-text').textContent = status.progress_percent + '%';
                    document.getElementById('scan-phase').textContent = status.current_phase || 'Scanning...';
                    document.getElementById('discovered-count').textContent = status.discovered_count;

                    if (status.last_scan_time) {
                        var date = new Date(status.last_scan_time * 1000);
                        document.getElementById('last-scan-time').textContent = date.toLocaleTimeString();
                    }

                    if (!status.running) {
                        clearInterval(scanPollInterval);
                        scanPollInterval = null;
                        App.Scanner.resetButton();

                        // Refresh the page to show new endpoints
                        if (status.discovered_count > 0) {
                            setTimeout(function() { location.reload(); }, 500);
                        }
                    }
                })
                .catch(function(e) {
                    console.error('Error polling scan status:', e);
                });
        },

        /**
         * Reset scan button to initial state
         */
        resetButton: function() {
            // Reset and show start button
            var startBtn = document.getElementById('start-scan-btn');
            startBtn.textContent = 'Scan Network';
            startBtn.disabled = false;
            startBtn.style.opacity = '1';
            startBtn.style.display = 'block';

            // Reset and hide stop button
            var stopBtn = document.getElementById('stop-scan-btn');
            stopBtn.textContent = 'Stop Scan';
            stopBtn.disabled = false;
            stopBtn.style.opacity = '1';
            stopBtn.style.display = 'none';

            document.getElementById('scan-progress').style.display = 'none';
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
        }
    };

    // Expose functions globally for onclick handlers
    window.startNetworkScan = App.Scanner.start;
    window.stopNetworkScan = App.Scanner.stop;
    window.pollScanStatus = App.Scanner.pollStatus;
    window.checkScanCapabilities = App.Scanner.checkCapabilities;

})(window.App);
