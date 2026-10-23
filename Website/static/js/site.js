/* DomainDetective site behaviour: theme, navigation, tabs, copy buttons and lazy syntax highlighting.
   Everything here is progressive: without JavaScript the navigation panels open on hover/focus,
   every link still works and code stays readable. */

(function () {
    'use strict';

    var root = document.documentElement;

    function readTheme() {
        try {
            return localStorage.getItem('dd-theme') === 'light' ? 'light' : 'dark';
        } catch (error) {
            return 'dark';
        }
    }

    function applyTheme(theme) {
        var next = theme === 'light' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        root.style.colorScheme = next;
        var meta = document.querySelector('meta[name="theme-color"]');
        if (meta) {
            meta.setAttribute('content', next === 'light' ? '#f4f6f8' : '#07090d');
        }
        return next;
    }

    function persistTheme(theme) {
        try {
            localStorage.setItem('dd-theme', theme);
        } catch (error) {
            /* Storage can be unavailable in private windows; the toggle still works for this page. */
        }
    }

    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }

        return new Promise(function (resolve, reject) {
            try {
                var area = document.createElement('textarea');
                area.value = text;
                area.setAttribute('readonly', '');
                area.style.position = 'fixed';
                area.style.opacity = '0';
                document.body.appendChild(area);
                area.select();
                var ok = document.execCommand('copy');
                document.body.removeChild(area);
                if (ok) {
                    resolve();
                } else {
                    reject(new Error('Copy command was not successful.'));
                }
            } catch (error) {
                reject(error);
            }
        });
    }

    function flashCopied(button, label) {
        // Keep the button's own nodes (icon and text) and put them back, rather than re-parsing stored HTML.
        if (button.dataset.flashing === 'true') {
            return;
        }
        button.dataset.flashing = 'true';
        var original = Array.prototype.slice.call(button.childNodes);
        button.classList.add('is-copied', 'copied');
        button.textContent = label;
        window.setTimeout(function () {
            button.classList.remove('is-copied', 'copied');
            button.textContent = '';
            original.forEach(function (node) { button.appendChild(node); });
            button.dataset.flashing = 'false';
        }, 1500);
    }

    function loadScript(src) {
        return new Promise(function (resolve) {
            var existing = document.querySelector('script[data-dynamic-src="' + src + '"]');
            if (existing) {
                if (existing.getAttribute('data-loaded') === 'true') {
                    resolve(true);
                    return;
                }
                existing.addEventListener('load', function () { resolve(true); }, { once: true });
                existing.addEventListener('error', function () { resolve(false); }, { once: true });
                return;
            }

            var script = document.createElement('script');
            script.src = src;
            script.async = true;
            script.setAttribute('data-dynamic-src', src);
            script.addEventListener('load', function () {
                script.setAttribute('data-loaded', 'true');
                resolve(true);
            }, { once: true });
            script.addEventListener('error', function () { resolve(false); }, { once: true });
            document.head.appendChild(script);
        });
    }

    applyTheme(readTheme());
    window.Prism = window.Prism || {};
    window.Prism.manual = true;

    /* ---------------------------------------------------------------- syntax highlighting */

    var prismPromise = null;

    function hasCode(scope) {
        return !!(scope || document).querySelector('pre code[class*="language-"]');
    }

    function ensurePrism() {
        if (window.Prism && window.Prism.plugins && window.Prism.plugins.autoloader) {
            return Promise.resolve(true);
        }
        if (!prismPromise) {
            prismPromise = loadScript('/assets/prism/prism-core.min.js')
                .then(function (ok) { return ok ? loadScript('/assets/prism/prism-autoloader.min.js') : false; })
                .catch(function () { return false; });
        }
        return prismPromise;
    }

    function highlight(scope) {
        var target = scope || document;
        if (!hasCode(target)) {
            return;
        }
        ensurePrism().then(function (ok) {
            if (!ok || !window.Prism) {
                return;
            }
            if (window.Prism.plugins && window.Prism.plugins.autoloader) {
                window.Prism.plugins.autoloader.languages_path = '/assets/prism/components/';
            }
            if (typeof window.Prism.highlightAllUnder === 'function') {
                window.Prism.highlightAllUnder(target);
            }
        });
    }

    window.DomainDetectiveSite = { highlight: highlight, copyText: copyText };

    /* ---------------------------------------------------------------- navigation */

    function initNavigation() {
        var header = document.querySelector('[data-dd-header], .dd-header');
        var toggle = document.querySelector('.dd-nav-toggle');
        var nav = document.querySelector('.dd-nav');
        var groups = Array.prototype.slice.call(document.querySelectorAll('[data-dd-navgroup], .dd-nav-dropdown, .nav-dropdown'));
        var desktop = window.matchMedia('(min-width: 961px)');

        function setMobile(open) {
            if (!nav || !toggle) {
                return;
            }
            nav.classList.toggle('is-open', open);
            if (header) {
                header.classList.toggle('is-open', open);
            }
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            document.body.classList.toggle('dd-nav-open', open);
        }

        function triggerOf(group) {
            return group.querySelector('.dd-navgroup__trigger, .dd-nav-dropdown-trigger, .nav-dropdown-trigger');
        }

        function setGroup(group, open) {
            group.classList.toggle('is-open', open);
            var trigger = triggerOf(group);
            if (trigger) {
                trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
            }
        }

        function closeAll(except) {
            groups.forEach(function (group) {
                if (group !== except) {
                    setGroup(group, false);
                }
            });
        }

        if (toggle && nav) {
            toggle.addEventListener('click', function () {
                setMobile(!nav.classList.contains('is-open'));
            });
        }

        groups.forEach(function (group) {
            var trigger = triggerOf(group);
            var closeTimer = null;
            if (!trigger) {
                return;
            }

            trigger.addEventListener('click', function (event) {
                /* The flat API reference markup uses a link as trigger; on desktop it keeps navigating. */
                if (trigger.tagName === 'A' && desktop.matches) {
                    return;
                }
                event.preventDefault();
                var open = !group.classList.contains('is-open');
                closeAll(group);
                setGroup(group, open);
            });

            group.addEventListener('mouseenter', function () {
                if (!desktop.matches) {
                    return;
                }
                window.clearTimeout(closeTimer);
                closeAll(group);
                setGroup(group, true);
            });

            group.addEventListener('mouseleave', function () {
                if (!desktop.matches) {
                    return;
                }
                closeTimer = window.setTimeout(function () { setGroup(group, false); }, 160);
            });
        });

        document.addEventListener('click', function (event) {
            groups.forEach(function (group) {
                if (!group.contains(event.target)) {
                    setGroup(group, false);
                }
            });
        });

        document.addEventListener('keydown', function (event) {
            if (event.key !== 'Escape') {
                return;
            }
            var openGroup = groups.filter(function (group) { return group.classList.contains('is-open'); })[0];
            closeAll();
            if (openGroup) {
                var trigger = triggerOf(openGroup);
                if (trigger) {
                    trigger.focus();
                }
            } else if (nav && nav.classList.contains('is-open')) {
                setMobile(false);
                toggle.focus();
            }
        });

        if (nav) {
            nav.addEventListener('click', function (event) {
                var link = event.target.closest('a[href]');
                if (link && !desktop.matches) {
                    setMobile(false);
                }
            });
        }

        desktop.addEventListener('change', function () {
            setMobile(false);
            closeAll();
        });
    }

    /* ---------------------------------------------------------------- docs sidebar */

    function initDocsSidebar() {
        var toggle = document.querySelector('.docs-sidebar-toggle');
        var sidebar = document.querySelector('.docs-sidebar');
        var overlay = document.querySelector('.docs-sidebar-overlay');
        if (!toggle || !sidebar) {
            return;
        }

        function set(open) {
            sidebar.classList.toggle('open', open);
            if (overlay) {
                overlay.classList.toggle('open', open);
            }
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        }

        toggle.addEventListener('click', function () { set(!sidebar.classList.contains('open')); });
        if (overlay) {
            overlay.addEventListener('click', function () { set(false); });
        }
    }

    /* ---------------------------------------------------------------- tabs */

    function initTabs() {
        document.querySelectorAll('[data-dd-tabs]').forEach(function (container) {
            var tabs = Array.prototype.slice.call(container.querySelectorAll('[role="tab"]'));
            var panels = Array.prototype.slice.call(container.querySelectorAll('[role="tabpanel"]'));

            function select(tab, focus) {
                tabs.forEach(function (item) {
                    var selected = item === tab;
                    item.setAttribute('aria-selected', selected ? 'true' : 'false');
                    item.tabIndex = selected ? 0 : -1;
                });
                panels.forEach(function (panel) {
                    panel.hidden = panel.id !== tab.getAttribute('aria-controls');
                    if (!panel.hidden) {
                        highlight(panel);
                    }
                });
                if (focus) {
                    tab.focus();
                }
            }

            tabs.forEach(function (tab, index) {
                tab.addEventListener('click', function () { select(tab, false); });
                tab.addEventListener('keydown', function (event) {
                    var next = null;
                    if (event.key === 'ArrowRight') { next = tabs[(index + 1) % tabs.length]; }
                    if (event.key === 'ArrowLeft') { next = tabs[(index - 1 + tabs.length) % tabs.length]; }
                    if (event.key === 'Home') { next = tabs[0]; }
                    if (event.key === 'End') { next = tabs[tabs.length - 1]; }
                    if (next) {
                        event.preventDefault();
                        select(next, true);
                    }
                });
            });
        });

        /* Older Markdown content still uses .code-tabs markup. */
        document.querySelectorAll('.code-tabs').forEach(function (container) {
            var tabs = container.querySelectorAll('.code-tab-btn');
            var panels = container.querySelectorAll('.code-panel');
            tabs.forEach(function (tab) {
                tab.addEventListener('click', function () {
                    tabs.forEach(function (item) { item.classList.remove('active'); });
                    panels.forEach(function (panel) { panel.classList.remove('active'); });
                    tab.classList.add('active');
                    var panel = container.querySelector('.code-panel[data-panel="' + tab.getAttribute('data-tab') + '"]');
                    if (panel) {
                        panel.classList.add('active');
                        highlight(panel);
                    }
                });
            });
        });
    }

    /* ---------------------------------------------------------------- copy */

    function initCopy() {
        document.addEventListener('click', function (event) {
            var button = event.target.closest('[data-copy]');
            if (!button) {
                return;
            }
            copyText(button.getAttribute('data-copy') || '')
                .then(function () { flashCopied(button, 'Copied'); })
                .catch(function () { flashCopied(button, 'Copy failed'); });
        });

        document.querySelectorAll('.dd-prose pre, .docs-article-body pre, .dd-article-body pre').forEach(function (pre) {
            if (pre.closest('.dd-codeblock') || pre.closest('.dd-window')) {
                return;
            }
            var wrap = document.createElement('div');
            wrap.className = 'dd-codeblock';
            pre.parentNode.insertBefore(wrap, pre);
            wrap.appendChild(pre);
            var button = document.createElement('button');
            button.type = 'button';
            button.className = 'copy-code-btn';
            button.textContent = 'Copy';
            button.setAttribute('aria-label', 'Copy code');
            button.addEventListener('click', function () {
                copyText(pre.innerText.replace(/\n$/, ''))
                    .then(function () { flashCopied(button, 'Copied'); })
                    .catch(function () { flashCopied(button, 'Copy failed'); });
            });
            wrap.appendChild(button);
        });
    }

    /* ---------------------------------------------------------------- theme */

    function initTheme() {
        document.querySelectorAll('.theme-cycle-btn').forEach(function (button) {
            if (button.dataset.themeBound === 'true') {
                return;
            }
            button.dataset.themeBound = 'true';
            button.addEventListener('click', function () {
                var next = (root.getAttribute('data-theme') || 'dark') === 'dark' ? 'light' : 'dark';
                applyTheme(next);
                persistTheme(next);
            });
        });
    }

    function init() {
        initTheme();
        initNavigation();
        initDocsSidebar();
        initTabs();
        initCopy();
        highlight(document);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
