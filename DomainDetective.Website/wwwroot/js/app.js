(function () {
    'use strict';

    var themes = ['dark', 'light'];

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    window.domainDetectiveTools = {
        initTheme: function () {
            var current = localStorage.getItem('dd-theme') || 'dark';
            applyTheme(current);
        },
        toggleTheme: function () {
            var current = localStorage.getItem('dd-theme') || 'dark';
            var idx = themes.indexOf(current);
            var next = themes[(idx + 1) % themes.length];
            localStorage.setItem('dd-theme', next);
            applyTheme(next);
        }
    };
})();
