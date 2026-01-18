/**
 * PCAP Module - PCAP file upload management
 */
(function(App) {
    'use strict';

    // Store upload history in memory
    var uploadHistory = [];

    App.Pcap = {
        /**
         * Initialize the PCAP module
         */
        init: function() {
            var form = document.getElementById('pcap-upload-form');
            if (form) {
                form.addEventListener('submit', App.Pcap.handleUpload);
            }
            // Fetch initial capture status
            App.Pcap.refreshCaptureStatus();
        },

        /**
         * Refresh the capture status from the server
         */
        refreshCaptureStatus: function() {
            fetch('/api/capture/status')
                .then(function(response) { return response.json(); })
                .then(function(result) {
                    App.Pcap.updateCaptureUI(result.paused);
                })
                .catch(function(error) {
                    console.error('Failed to get capture status:', error);
                });
        },

        /**
         * Toggle the capture pause state
         */
        toggleCapture: function() {
            var btn = document.getElementById('capture-toggle-btn');
            if (btn) {
                btn.disabled = true;
            }

            fetch('/api/capture/pause', { method: 'POST' })
                .then(function(response) { return response.json(); })
                .then(function(result) {
                    App.Pcap.updateCaptureUI(result.paused);
                    if (btn) btn.disabled = false;
                })
                .catch(function(error) {
                    console.error('Failed to toggle capture:', error);
                    if (btn) btn.disabled = false;
                });
        },

        /**
         * Update the capture UI based on paused state
         */
        updateCaptureUI: function(isPaused) {
            var indicator = document.getElementById('capture-status-indicator');
            var statusText = document.getElementById('capture-status-text');
            var btn = document.getElementById('capture-toggle-btn');

            if (isPaused) {
                if (indicator) indicator.style.background = '#f59e0b';
                if (statusText) statusText.textContent = 'Paused - live packets ignored';
                if (btn) {
                    btn.textContent = 'Resume Capture';
                    btn.style.background = 'rgba(34, 197, 94, 0.2)';
                    btn.style.borderColor = 'rgba(34, 197, 94, 0.4)';
                    btn.style.color = '#22c55e';
                }
            } else {
                if (indicator) indicator.style.background = '#22c55e';
                if (statusText) statusText.textContent = 'Active - receiving packets';
                if (btn) {
                    btn.textContent = 'Pause Capture';
                    btn.style.background = 'rgba(245, 158, 11, 0.2)';
                    btn.style.borderColor = 'rgba(245, 158, 11, 0.4)';
                    btn.style.color = '#f59e0b';
                }
            }
        },

        /**
         * Handle the PCAP upload form submission
         */
        handleUpload: function(e) {
            e.preventDefault();

            var fileInput = document.getElementById('pcap-file');
            var labelInput = document.getElementById('pcap-label');
            var submitBtn = document.getElementById('pcap-submit-btn');
            var progressDiv = document.getElementById('pcap-progress');
            var progressFill = document.getElementById('pcap-progress-fill');
            var statusSpan = document.getElementById('pcap-status');
            var progressText = document.getElementById('pcap-progress-text');
            var resultDiv = document.getElementById('pcap-result');

            if (!fileInput.files || fileInput.files.length === 0) {
                App.Pcap.showResult(resultDiv, false, 'Please select a file to upload.');
                return;
            }

            var file = fileInput.files[0];
            var label = labelInput.value.trim();

            // Build form data
            var formData = new FormData();
            formData.append('file', file);
            if (label) {
                formData.append('label', label);
            }

            // Show progress, disable button
            submitBtn.disabled = true;
            submitBtn.textContent = 'Uploading...';
            progressDiv.style.display = 'block';
            progressFill.style.width = '0%';
            statusSpan.textContent = 'Uploading...';
            progressText.textContent = '';
            resultDiv.style.display = 'none';

            // Create XMLHttpRequest for progress tracking
            var xhr = new XMLHttpRequest();

            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    var percent = Math.round((e.loaded / e.total) * 50); // Upload is 50% of progress
                    progressFill.style.width = percent + '%';
                    progressText.textContent = percent + '%';
                    if (percent >= 50) {
                        statusSpan.textContent = 'Processing...';
                    }
                }
            });

            xhr.addEventListener('load', function() {
                try {
                    var response = JSON.parse(xhr.responseText);

                    if (xhr.status === 200 && response.success) {
                        progressFill.style.width = '100%';
                        progressText.textContent = '100%';
                        statusSpan.textContent = 'Complete!';

                        // Add to history
                        App.Pcap.addToHistory({
                            filename: response.filename || file.name,
                            label: label || response.filename || file.name,
                            packetCount: response.packet_count || 0,
                            time: new Date().toLocaleTimeString()
                        });

                        App.Pcap.showResult(resultDiv, true, response.message);

                        // Clear form
                        fileInput.value = '';
                        labelInput.value = '';
                    } else {
                        App.Pcap.showResult(resultDiv, false, response.message || 'Upload failed');
                    }
                } catch (e) {
                    App.Pcap.showResult(resultDiv, false, 'Invalid response from server');
                }

                // Reset button
                submitBtn.disabled = false;
                submitBtn.textContent = 'Upload & Process';

                // Hide progress after a moment
                setTimeout(function() {
                    progressDiv.style.display = 'none';
                }, 2000);
            });

            xhr.addEventListener('error', function() {
                App.Pcap.showResult(resultDiv, false, 'Network error occurred');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Upload & Process';
                progressDiv.style.display = 'none';
            });

            xhr.open('POST', '/api/pcap/upload');
            xhr.send(formData);
        },

        /**
         * Display a result message
         */
        showResult: function(resultDiv, success, message) {
            resultDiv.style.display = 'block';
            resultDiv.textContent = message;

            if (success) {
                resultDiv.style.background = 'rgba(16, 185, 129, 0.15)';
                resultDiv.style.border = '1px solid rgba(16, 185, 129, 0.4)';
                resultDiv.style.color = '#10b981';
            } else {
                resultDiv.style.background = 'rgba(239, 68, 68, 0.15)';
                resultDiv.style.border = '1px solid rgba(239, 68, 68, 0.4)';
                resultDiv.style.color = '#f87171';
            }
        },

        /**
         * Add an entry to the upload history
         */
        addToHistory: function(entry) {
            uploadHistory.unshift(entry);

            // Keep only last 10 entries
            if (uploadHistory.length > 10) {
                uploadHistory.pop();
            }

            App.Pcap.renderHistory();
        },

        /**
         * Render the upload history table
         */
        renderHistory: function() {
            var tbody = document.getElementById('pcap-history-body');
            if (!tbody) return;

            if (uploadHistory.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 1rem;">No uploads yet. Upload a PCAP file to get started.</td></tr>';
                return;
            }

            var html = '';
            uploadHistory.forEach(function(entry) {
                html += '<tr>';
                html += '<td>' + App.Utils.escapeHtml(entry.filename) + '</td>';
                html += '<td>' + App.Utils.escapeHtml(entry.label) + '</td>';
                html += '<td>' + entry.packetCount.toLocaleString() + '</td>';
                html += '<td>' + App.Utils.escapeHtml(entry.time) + '</td>';
                html += '</tr>';
            });

            tbody.innerHTML = html;
        }
    };

    // Expose toggle function globally for onclick handler
    App.toggleCaptureState = function() {
        App.Pcap.toggleCapture();
    };

})(window.App);
