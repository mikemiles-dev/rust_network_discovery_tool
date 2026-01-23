/**
 * Theme Module - Light/Dark mode switching
 * Respects browser preference and persists user choice in localStorage
 */
(function(App) {
    'use strict';

    var STORAGE_KEY = 'theme-preference';

    App.Theme = {
        /**
         * Initialize theme based on stored preference or browser default
         */
        init: function() {
            var stored = localStorage.getItem(STORAGE_KEY);

            if (stored) {
                // User has a stored preference
                this.applyTheme(stored);
            } else {
                // Check browser preference
                var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                this.applyTheme(prefersDark ? 'dark' : 'light');
            }

            // Listen for browser preference changes (if user hasn't set a preference)
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
                // Only auto-switch if user hasn't manually set a preference
                if (!localStorage.getItem(STORAGE_KEY)) {
                    App.Theme.applyTheme(e.matches ? 'dark' : 'light');
                    App.Theme.updateButtons();
                }
            });

            // Setup buttons when DOM is ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', function() {
                    App.Theme.setupButtons();
                });
            } else {
                this.setupButtons();
            }
        },

        /**
         * Setup button click handlers and initial state
         */
        setupButtons: function() {
            var self = this;
            var lightBtn = document.getElementById('theme-light-btn');
            var darkBtn = document.getElementById('theme-dark-btn');

            if (lightBtn) {
                lightBtn.addEventListener('click', function() {
                    self.set('light');
                });
            }

            if (darkBtn) {
                darkBtn.addEventListener('click', function() {
                    self.set('dark');
                });
            }

            this.updateButtons();
        },

        /**
         * Apply theme to document
         * @param {string} theme - 'light' or 'dark'
         */
        applyTheme: function(theme) {
            if (theme === 'light') {
                document.documentElement.setAttribute('data-theme', 'light');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
        },

        /**
         * Set theme (user action) - saves to localStorage
         * @param {string} theme - 'light' or 'dark'
         */
        set: function(theme) {
            this.applyTheme(theme);
            localStorage.setItem(STORAGE_KEY, theme);
            this.updateButtons();
        },

        /**
         * Toggle between light and dark themes
         */
        toggle: function() {
            var current = this.getTheme();
            this.set(current === 'light' ? 'dark' : 'light');
        },

        /**
         * Get current theme
         * @returns {string} 'light' or 'dark'
         */
        getTheme: function() {
            return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
        },

        /**
         * Update button active states
         */
        updateButtons: function() {
            var current = this.getTheme();
            var lightBtn = document.getElementById('theme-light-btn');
            var darkBtn = document.getElementById('theme-dark-btn');

            if (lightBtn) {
                if (current === 'light') {
                    lightBtn.classList.add('active');
                } else {
                    lightBtn.classList.remove('active');
                }
            }
            if (darkBtn) {
                if (current === 'dark') {
                    darkBtn.classList.add('active');
                } else {
                    darkBtn.classList.remove('active');
                }
            }
        }
    };

    // Initialize theme immediately to prevent flash
    App.Theme.init();

})(window.App || (window.App = {}));
