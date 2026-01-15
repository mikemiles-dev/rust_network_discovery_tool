/**
 * Classification Module - Device type reclassification and endpoint rename
 */
(function(App) {
    'use strict';

    // These will be set from the template
    var currentEndpointName = null;

    App.Classification = {
        /**
         * Set the current endpoint name (called from template)
         */
        setEndpointName: function(name) {
            currentEndpointName = name;
        },

        /**
         * Toggle device type dropdown
         */
        toggleDeviceTypeDropdown: function(event) {
            if (event) event.stopPropagation();
            var dropdown = document.getElementById('device-type-dropdown');
            var isOpening = !dropdown.classList.contains('open');

            if (isOpening) {
                // Pause auto-refresh while dropdown is open
                if (App.state.refreshIntervalId) {
                    App.state.savedRefreshInterval = document.getElementById('refreshInterval').value;
                    clearInterval(App.state.refreshIntervalId);
                    App.state.refreshIntervalId = null;
                }
            }

            dropdown.classList.toggle('open');
        },

        /**
         * Close dropdown when clicking outside
         */
        setupDropdownClose: function() {
            document.addEventListener('click', function(event) {
                var dropdown = document.getElementById('device-type-dropdown');
                var btn = document.getElementById('device-type-btn');
                if (dropdown && btn && !dropdown.contains(event.target) && !btn.contains(event.target)) {
                    dropdown.classList.remove('open');
                    // Resume auto-refresh if it was paused
                    if (App.state.savedRefreshInterval && App.state.savedRefreshInterval !== '0') {
                        if (App.Refresh) {
                            App.Refresh.updateInterval(App.state.savedRefreshInterval);
                        }
                        App.state.savedRefreshInterval = null;
                    }
                }
            });
        },

        /**
         * Reclassify endpoint device type
         */
        reclassifyEndpoint: function(deviceType) {
            var dropdown = document.getElementById('device-type-dropdown');
            dropdown.classList.remove('open');

            fetch('/api/endpoint/classify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    device_type: deviceType === 'auto' ? null : deviceType
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    window.location.reload();
                } else {
                    alert('Failed to update device type: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to update device type. Please try again.');
            });
        },

        /**
         * Show rename input field
         */
        showRenameInput: function() {
            document.getElementById('endpoint-name-display').style.display = 'none';
            document.getElementById('endpoint-rename-input').style.display = 'block';
            var input = document.getElementById('custom-name-input');
            input.value = currentEndpointName;
            input.focus();
            input.select();
        },

        /**
         * Cancel rename operation
         */
        cancelRename: function() {
            document.getElementById('endpoint-rename-input').style.display = 'none';
            document.getElementById('endpoint-name-display').style.display = 'flex';
        },

        /**
         * Save custom name
         */
        saveCustomName: function() {
            var customName = document.getElementById('custom-name-input').value.trim();

            if (!customName) {
                alert('Please enter a name');
                return;
            }

            fetch('/api/endpoint/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    custom_name: customName
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    window.location.href = '/?node=' + encodeURIComponent(customName);
                } else {
                    alert('Failed to rename endpoint: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to rename endpoint. Please try again.');
            });
        },

        /**
         * Clear custom name and reset to original
         */
        clearCustomName: function() {
            if (!confirm('Reset to original name?')) {
                return;
            }

            fetch('/api/endpoint/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    custom_name: null
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    if (result.original_name) {
                        window.location.href = '/?node=' + encodeURIComponent(result.original_name);
                    } else {
                        window.location.reload();
                    }
                } else {
                    alert('Failed to reset name: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to reset name. Please try again.');
            });
        }
    };

    // Expose functions globally for onclick handlers
    window.toggleDeviceTypeDropdown = App.Classification.toggleDeviceTypeDropdown;
    window.reclassifyEndpoint = App.Classification.reclassifyEndpoint;
    window.showRenameInput = App.Classification.showRenameInput;
    window.cancelRename = App.Classification.cancelRename;
    window.saveCustomName = App.Classification.saveCustomName;
    window.clearCustomName = App.Classification.clearCustomName;

})(window.App);
