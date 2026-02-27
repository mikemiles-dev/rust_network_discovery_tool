/**
 * Endpoints Actions Module - Merge/delete endpoint operations
 */
(function() {
    'use strict';

    App.Endpoints = App.Endpoints || {};

    // Merge modal state
    var mergeSourceEndpoint = null;
    var mergeTargetEndpoint = null;
    var allEndpoints = [];

    /**
     * Show the merge modal with endpoint list
     */
    App.Endpoints.mergeEndpoint = function(sourceEndpoint) {
        mergeSourceEndpoint = sourceEndpoint;
        mergeTargetEndpoint = null;

        // Update modal header with source name
        document.getElementById('merge-source-name').textContent = sourceEndpoint;

        // Reset UI state
        document.getElementById('merge-search').value = '';
        document.getElementById('merge-confirm-btn').disabled = true;
        document.getElementById('merge-endpoint-list').innerHTML = '<div class="merge-modal-empty">Loading endpoints...</div>';

        // Show modal
        document.getElementById('merge-modal').classList.add('show');

        // Fetch endpoints
        fetch('/api/endpoints/table')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                allEndpoints = (data.endpoints || []).filter(function(ep) {
                    return ep.name.toLowerCase() !== sourceEndpoint.toLowerCase();
                });
                App.Endpoints.renderMergeEndpoints(allEndpoints);
                document.getElementById('merge-search').focus();
            })
            .catch(function(error) {
                document.getElementById('merge-endpoint-list').innerHTML =
                    '<div class="merge-modal-empty">Error loading endpoints</div>';
            });
    };

    /**
     * Render the list of endpoints in the merge modal
     */
    App.Endpoints.renderMergeEndpoints = function(endpoints) {
        var listEl = document.getElementById('merge-endpoint-list');

        if (!endpoints || endpoints.length === 0) {
            listEl.innerHTML = '<div class="merge-modal-empty">No matching endpoints found</div>';
            return;
        }

        var html = endpoints.map(function(ep) {
            var details = [];
            if (ep.vendor) details.push(ep.vendor);
            if (ep.model) details.push(ep.model);
            if (ep.device_type) details.push(ep.device_type);

            var isSelected = mergeTargetEndpoint === ep.name;

            return '<div class="merge-modal-item' + (isSelected ? ' selected' : '') + '" ' +
                   'onclick="App.Endpoints.selectMergeTarget(\'' + ep.name.replace(/'/g, "\\'") + '\')">' +
                   '<div class="merge-modal-item-name">' + App.Endpoints.escapeHtml(ep.name) + '</div>' +
                   (details.length > 0 ?
                       '<div class="merge-modal-item-details">' + App.Endpoints.escapeHtml(details.join(' • ')) + '</div>' : '') +
                   '</div>';
        }).join('');

        listEl.innerHTML = html;
    };

    /**
     * Filter endpoints based on search input
     */
    App.Endpoints.filterMergeEndpoints = function() {
        var search = document.getElementById('merge-search').value.toLowerCase().trim();

        if (!search) {
            App.Endpoints.renderMergeEndpoints(allEndpoints);
            return;
        }

        var filtered = allEndpoints.filter(function(ep) {
            return ep.name.toLowerCase().indexOf(search) !== -1 ||
                   (ep.vendor && ep.vendor.toLowerCase().indexOf(search) !== -1) ||
                   (ep.model && ep.model.toLowerCase().indexOf(search) !== -1) ||
                   (ep.device_type && ep.device_type.toLowerCase().indexOf(search) !== -1);
        });

        App.Endpoints.renderMergeEndpoints(filtered);
    };

    /**
     * Select a target endpoint in the merge modal
     */
    App.Endpoints.selectMergeTarget = function(endpointName) {
        mergeTargetEndpoint = endpointName;
        document.getElementById('merge-confirm-btn').disabled = false;
        App.Endpoints.renderMergeEndpoints(
            document.getElementById('merge-search').value.toLowerCase().trim()
                ? allEndpoints.filter(function(ep) {
                    var search = document.getElementById('merge-search').value.toLowerCase().trim();
                    return ep.name.toLowerCase().indexOf(search) !== -1 ||
                           (ep.vendor && ep.vendor.toLowerCase().indexOf(search) !== -1) ||
                           (ep.model && ep.model.toLowerCase().indexOf(search) !== -1) ||
                           (ep.device_type && ep.device_type.toLowerCase().indexOf(search) !== -1);
                  })
                : allEndpoints
        );
    };

    /**
     * Close the merge modal
     */
    App.Endpoints.closeMergeModal = function() {
        document.getElementById('merge-modal').classList.remove('show');
        mergeSourceEndpoint = null;
        mergeTargetEndpoint = null;
    };

    /**
     * Confirm and execute the merge
     */
    App.Endpoints.confirmMerge = function() {
        if (!mergeSourceEndpoint || !mergeTargetEndpoint) return;

        if (!confirm('Merge "' + mergeSourceEndpoint + '" into "' + mergeTargetEndpoint + '"?\n\nAll communications, attributes, and scan data from "' + mergeSourceEndpoint + '" will be moved to "' + mergeTargetEndpoint + '", and "' + mergeSourceEndpoint + '" will be deleted.')) {
            return;
        }

        App.Endpoints.closeMergeModal();

        fetch('/api/endpoint/merge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: mergeTargetEndpoint,
                source: mergeSourceEndpoint
            })
        })
        .then(function(response) { return response.json(); })
        .then(function(result) {
            if (result.success) {
                alert(result.message);
                var url = new URL(window.location.href);
                url.searchParams.set('node', mergeTargetEndpoint);
                window.location.href = url.toString();
            } else {
                alert('Failed to merge endpoints: ' + result.message);
            }
        })
        .catch(function(error) {
            alert('Error merging endpoints: ' + error);
        });
    };

    /**
     * Escape HTML to prevent XSS
     */
    App.Endpoints.escapeHtml = function(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    /**
     * Delete an endpoint and all associated data
     */
    App.Endpoints.deleteEndpoint = function(endpointName) {
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
    };

    // Merge modal event listeners
    document.addEventListener('DOMContentLoaded', function() {
        // Search input filter
        var mergeSearch = document.getElementById('merge-search');
        if (mergeSearch) {
            mergeSearch.addEventListener('input', App.Endpoints.filterMergeEndpoints);
        }

        // Close modal on overlay click
        var mergeModal = document.getElementById('merge-modal');
        if (mergeModal) {
            mergeModal.addEventListener('click', function(e) {
                if (e.target === mergeModal) {
                    App.Endpoints.closeMergeModal();
                }
            });
        }

        // Close modal on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && mergeModal && mergeModal.classList.contains('show')) {
                App.Endpoints.closeMergeModal();
            }
        });
    });

})();
