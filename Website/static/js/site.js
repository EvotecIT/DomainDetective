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
            var isOpen = nav.classList.toggle('open');
            navToggle.setAttribute('aria-expanded', isOpen);
        });
    }

    var navDropdowns = document.querySelectorAll('.dd-nav-dropdown');
    if (navDropdowns.length > 0) {
        var closeDropdown = function (dropdown) {
            var trigger = dropdown.querySelector('.dd-nav-dropdown-trigger');
            dropdown.classList.remove('open');
            if (trigger) {
                trigger.setAttribute('aria-expanded', 'false');
            }
        };

        var closeOtherDropdowns = function (currentDropdown) {
            navDropdowns.forEach(function (dropdown) {
                if (dropdown !== currentDropdown) {
                    closeDropdown(dropdown);
                }
            });
        };

        navDropdowns.forEach(function (dropdown) {
            var trigger = dropdown.querySelector('.dd-nav-dropdown-trigger');
            if (!trigger) {
                return;
            }

            trigger.addEventListener('click', function (event) {
                event.preventDefault();
                var willOpen = !dropdown.classList.contains('open');
                closeOtherDropdowns(dropdown);
                dropdown.classList.toggle('open', willOpen);
                trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            });
        });

        document.addEventListener('click', function (event) {
            navDropdowns.forEach(function (dropdown) {
                if (!dropdown.contains(event.target)) {
                    closeDropdown(dropdown);
                }
            });
        });

        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') {
                navDropdowns.forEach(function (dropdown) {
                    closeDropdown(dropdown);
                });
            }
        });
    }

    var docsToggle = document.querySelector('.docs-sidebar-toggle');
    var docsSidebar = document.querySelector('.docs-sidebar');
    var docsOverlay = document.querySelector('.docs-sidebar-overlay');
    if (docsToggle && docsSidebar && docsOverlay) {
        var setDocsSidebar = function (isOpen) {
            docsSidebar.classList.toggle('open', isOpen);
            docsOverlay.classList.toggle('open', isOpen);
            docsToggle.setAttribute('aria-expanded', isOpen);
        };

        docsToggle.addEventListener('click', function () {
            setDocsSidebar(!docsSidebar.classList.contains('open'));
        });

        docsOverlay.addEventListener('click', function () {
            setDocsSidebar(false);
        });
    }

    // Code example tabs
    var tabBar = document.querySelector('.code-tab-bar');
    if (tabBar) {
        var tabs = tabBar.querySelectorAll('.code-tab-btn');
        var panels = tabBar.parentElement.querySelectorAll('.code-panel');

        tabs.forEach(function (tab) {
            tab.addEventListener('click', function () {
                var target = tab.getAttribute('data-tab');

                tabs.forEach(function (t) { t.classList.remove('active'); });
                panels.forEach(function (p) { p.classList.remove('active'); });

                tab.classList.add('active');
                var panel = tabBar.parentElement.querySelector('.code-panel[data-panel="' + target + '"]');
                if (panel) panel.classList.add('active');
            });
        });
    }

    // Copy button for install commands
    document.querySelectorAll('.hero-copy-btn, .hero-copy').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var text = btn.getAttribute('data-copy') || btn.previousElementSibling.textContent.trim();
            navigator.clipboard.writeText(text).then(function () {
                var orig = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(function () { btn.textContent = orig; }, 1500);
            });
        });
    });
})();
