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

            if (!currentEndpointName) {
                alert('Error: No endpoint selected');
                return;
            }

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
                    // Update UI in place
                    var typeDisplay = document.getElementById('current-device-type');
                    var typeBtn = document.getElementById('device-type-btn');
                    var indicator = document.getElementById('manual-override-indicator');

                    var typeLabels = {
                        'gateway': '🌐 Gateway',
                        'internet': '🌍 Internet',
                        'printer': '🖨️ Printer',
                        'tv': '📺 TV',
                        'gaming': '🎮 Gaming',
                        'phone': '📱 Phone',
                        'virtualization': '🖥 VM',
                        'soundbar': '🔊 Soundbar',
                        'appliance': '🏠 Appliance',
                        'local': '🖥️ Local',
                        'other': '❓ Other'
                    };

                    if (typeDisplay) {
                        typeDisplay.textContent = typeLabels[deviceType] || '❓ Other';
                    }

                    // Update manual override indicator
                    if (indicator) {
                        indicator.style.display = (deviceType === 'auto') ? 'none' : 'inline';
                    }
                    if (typeBtn) {
                        if (deviceType === 'auto') {
                            typeBtn.classList.remove('manual-override');
                        } else {
                            typeBtn.classList.add('manual-override');
                        }
                    }

                    // Update selected state in dropdown
                    var options = dropdown.querySelectorAll('.device-type-option');
                    options.forEach(function(opt) {
                        opt.classList.remove('selected');
                    });
                    var selectedOpt = dropdown.querySelector('.device-type-option[onclick*="' + deviceType + '"]');
                    if (selectedOpt) {
                        selectedOpt.classList.add('selected');
                    }

                    // Refresh the endpoint table to show updated type
                    if (App.Refresh && App.Refresh.refreshEndpointTable) {
                        App.Refresh.refreshEndpointTable();
                    }
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
            // Pause auto-refresh while rename input is open
            if (App.state.refreshIntervalId) {
                App.state.savedRefreshInterval = document.getElementById('refreshInterval').value;
                clearInterval(App.state.refreshIntervalId);
                App.state.refreshIntervalId = null;
            }
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
            // Resume auto-refresh if it was paused
            if (App.state.savedRefreshInterval && App.state.savedRefreshInterval !== '0') {
                if (App.Refresh) {
                    App.Refresh.updateInterval(App.state.savedRefreshInterval);
                }
                App.state.savedRefreshInterval = null;
            }
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
                    // Preserve existing URL parameters, just update node
                    var url = new URL(window.location.href);
                    url.searchParams.set('node', customName);
                    window.location.href = url.toString();
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
                        // Preserve existing URL parameters, just update node
                        var url = new URL(window.location.href);
                        url.searchParams.set('node', result.original_name);
                        window.location.href = url.toString();
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
        },

        /**
         * Show vendor edit input field
         */
        showVendorEdit: function() {
            // Pause auto-refresh while vendor edit input is open
            if (App.state.refreshIntervalId) {
                App.state.savedRefreshInterval = document.getElementById('refreshInterval').value;
                clearInterval(App.state.refreshIntervalId);
                App.state.refreshIntervalId = null;
            }
            document.getElementById('vendor-edit-input').style.display = 'block';
            var badge = document.getElementById('device-vendor-badge');
            var input = document.getElementById('custom-vendor-input');
            input.value = badge.style.display !== 'none' ? badge.textContent.trim() : '';
            input.focus();
            input.select();
        },

        /**
         * Cancel vendor edit operation
         */
        cancelVendorEdit: function() {
            document.getElementById('vendor-edit-input').style.display = 'none';
            // Resume auto-refresh if it was paused
            if (App.state.savedRefreshInterval && App.state.savedRefreshInterval !== '0') {
                if (App.Refresh) {
                    App.Refresh.updateInterval(App.state.savedRefreshInterval);
                }
                App.state.savedRefreshInterval = null;
            }
        },

        /**
         * Save custom vendor
         */
        saveCustomVendor: function() {
            var customVendor = document.getElementById('custom-vendor-input').value.trim();

            if (!customVendor) {
                alert('Please enter a vendor name');
                return;
            }

            fetch('/api/endpoint/vendor', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    vendor: customVendor
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    // Update UI in place
                    var badge = document.getElementById('device-vendor-badge');
                    var addBtn = document.getElementById('add-vendor-btn');
                    badge.textContent = customVendor;
                    badge.style.display = 'inline';
                    if (addBtn) addBtn.style.display = 'none';
                    document.getElementById('vendor-edit-input').style.display = 'none';
                    // Resume auto-refresh
                    if (App.state.savedRefreshInterval && App.state.savedRefreshInterval !== '0') {
                        if (App.Refresh) {
                            App.Refresh.updateInterval(App.state.savedRefreshInterval);
                        }
                        App.state.savedRefreshInterval = null;
                    }
                } else {
                    alert('Failed to set vendor: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to set vendor. Please try again.');
            });
        },

        /**
         * Clear custom vendor and reset to auto-detected
         */
        clearCustomVendor: function() {
            fetch('/api/endpoint/vendor', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    vendor: 'auto'
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    // Update UI in place - hide badge since we're reverting to auto
                    var badge = document.getElementById('device-vendor-badge');
                    var addBtn = document.getElementById('add-vendor-btn');
                    badge.textContent = '';
                    badge.style.display = 'none';
                    if (addBtn) addBtn.style.display = 'inline';
                    document.getElementById('vendor-edit-input').style.display = 'none';
                } else {
                    alert('Failed to reset vendor: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to reset vendor. Please try again.');
            });
        },

        /**
         * Show model edit input field
         */
        showModelEdit: function() {
            // Pause auto-refresh while model edit input is open
            if (App.state.refreshIntervalId) {
                App.state.savedRefreshInterval = document.getElementById('refreshInterval').value;
                clearInterval(App.state.refreshIntervalId);
                App.state.refreshIntervalId = null;
            }
            document.getElementById('model-edit-input').style.display = 'block';
            var badge = document.getElementById('device-model-badge');
            var input = document.getElementById('custom-model-input');
            input.value = badge.style.display !== 'none' ? badge.textContent.trim() : '';
            input.focus();
            input.select();
        },

        /**
         * Cancel model edit operation
         */
        cancelModelEdit: function() {
            document.getElementById('model-edit-input').style.display = 'none';
            // Resume auto-refresh if it was paused
            if (App.state.savedRefreshInterval && App.state.savedRefreshInterval !== '0') {
                if (App.Refresh) {
                    App.Refresh.updateInterval(App.state.savedRefreshInterval);
                }
                App.state.savedRefreshInterval = null;
            }
        },

        /**
         * Save custom model
         */
        saveCustomModel: function() {
            var customModel = document.getElementById('custom-model-input').value.trim();

            if (!customModel) {
                alert('Please enter a model name');
                return;
            }

            fetch('/api/endpoint/model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    model: customModel
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    // Update UI in place
                    var badge = document.getElementById('device-model-badge');
                    var addBtn = document.getElementById('add-model-btn');
                    var deviceModel = document.getElementById('device-model');
                    badge.textContent = customModel;
                    badge.style.display = 'inline';
                    if (addBtn) addBtn.style.display = 'none';
                    if (deviceModel) deviceModel.textContent = customModel;
                    document.getElementById('model-edit-input').style.display = 'none';
                    // Resume auto-refresh
                    if (App.state.savedRefreshInterval && App.state.savedRefreshInterval !== '0') {
                        if (App.Refresh) {
                            App.Refresh.updateInterval(App.state.savedRefreshInterval);
                        }
                        App.state.savedRefreshInterval = null;
                    }
                } else {
                    alert('Failed to set model: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to set model. Please try again.');
            });
        },

        /**
         * Clear custom model and reset to auto-detected
         */
        clearCustomModel: function() {
            fetch('/api/endpoint/model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    endpoint_name: currentEndpointName,
                    model: 'auto'
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(result) {
                if (result.success) {
                    // Update UI in place - hide badge since we're reverting to auto
                    var badge = document.getElementById('device-model-badge');
                    var addBtn = document.getElementById('add-model-btn');
                    var deviceModel = document.getElementById('device-model');
                    badge.textContent = '';
                    badge.style.display = 'none';
                    if (addBtn) addBtn.style.display = 'inline';
                    if (deviceModel) deviceModel.textContent = '';
                    document.getElementById('model-edit-input').style.display = 'none';
                } else {
                    alert('Failed to reset model: ' + result.message);
                }
            })
            .catch(function(error) {
                alert('Failed to reset model. Please try again.');
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
    window.showVendorEdit = App.Classification.showVendorEdit;
    window.cancelVendorEdit = App.Classification.cancelVendorEdit;
    window.saveCustomVendor = App.Classification.saveCustomVendor;
    window.clearCustomVendor = App.Classification.clearCustomVendor;
    window.showModelEdit = App.Classification.showModelEdit;
    window.cancelModelEdit = App.Classification.cancelModelEdit;
    window.saveCustomModel = App.Classification.saveCustomModel;
    window.clearCustomModel = App.Classification.clearCustomModel;

})(window.App);
