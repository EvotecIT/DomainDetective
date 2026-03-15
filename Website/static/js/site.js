/* DomainDetective - Site JavaScript */

(function () {
    'use strict';

    // Theme toggle (3-way: dark -> light -> auto)
    var themeBtn = document.querySelector('.theme-cycle-btn');
    if (themeBtn) {
        var themes = ['dark', 'light'];
        var current = localStorage.getItem('dd-theme') || 'dark';
        document.documentElement.setAttribute('data-theme', current);

        themeBtn.addEventListener('click', function () {
            var idx = themes.indexOf(current);
            current = themes[(idx + 1) % themes.length];
            document.documentElement.setAttribute('data-theme', current);
            localStorage.setItem('dd-theme', current);
        });
    }

    // Mobile nav toggle
    var navToggle = document.querySelector('.dd-nav-toggle');
    var nav = document.querySelector('.dd-nav');
    if (navToggle && nav) {
        navToggle.addEventListener('click', function () {
            nav.classList.toggle('open');
        });
    }
})();
