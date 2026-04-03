/* DomainDetective - Site JavaScript */

(function () {
    'use strict';

    function getStoredTheme() {
        try {
            return localStorage.getItem('dd-theme') || 'dark';
        } catch (error) {
            return 'dark';
        }
    }

    function applyTheme(theme) {
        var nextTheme = theme === 'light' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        document.documentElement.style.colorScheme = nextTheme;
        return nextTheme;
    }

    function persistTheme(theme) {
        try {
            localStorage.setItem('dd-theme', theme);
        } catch (error) {
            /* Ignore storage failures. */
        }
    }

    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }

        return new Promise(function (resolve, reject) {
            try {
                var textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.setAttribute('readonly', '');
                textArea.style.position = 'fixed';
                textArea.style.opacity = '0';
                document.body.appendChild(textArea);
                textArea.select();
                textArea.setSelectionRange(0, textArea.value.length);

                if (document.execCommand('copy')) {
                    document.body.removeChild(textArea);
                    resolve();
                    return;
                }

                document.body.removeChild(textArea);
                reject(new Error('Copy command was not successful.'));
            } catch (error) {
                reject(error);
            }
        });
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
            script.defer = true;
            script.setAttribute('data-dynamic-src', src);
            script.addEventListener('load', function () {
                script.setAttribute('data-loaded', 'true');
                resolve(true);
            }, { once: true });
            script.addEventListener('error', function () {
                resolve(false);
            }, { once: true });
            document.head.appendChild(script);
        });
    }

    applyTheme(getStoredTheme());
    window.Prism = window.Prism || {};
    window.Prism.manual = true;

    document.addEventListener('DOMContentLoaded', function () {
        var prismLoadPromise = null;

        function hasCodeBlocks(scope) {
            var root = scope || document;
            return !!root.querySelector('pre code[class*="language-"]');
        }

        function highlightCodeBlocks(scope) {
            if (!window.Prism || !hasCodeBlocks(scope)) {
                return;
            }

            if (window.Prism.plugins && window.Prism.plugins.autoloader) {
                window.Prism.plugins.autoloader.languages_path = '/assets/prism/components/';
            }

            if (scope && typeof window.Prism.highlightAllUnder === 'function') {
                window.Prism.highlightAllUnder(scope);
                return;
            }

            if (typeof window.Prism.highlightAll === 'function') {
                window.Prism.highlightAll();
            }
        }

        function ensurePrismLoaded() {
            if (!hasCodeBlocks(document)) {
                return Promise.resolve(false);
            }

            if (window.Prism && window.Prism.plugins && window.Prism.plugins.autoloader) {
                return Promise.resolve(true);
            }

            if (prismLoadPromise) {
                return prismLoadPromise;
            }

            prismLoadPromise = loadScript('/assets/prism/prism-core.min.js')
                .then(function (coreLoaded) {
                    if (!coreLoaded) {
                        return false;
                    }

                    return loadScript('/assets/prism/prism-autoloader.min.js');
                })
                .then(function (autoloadLoaded) {
                    return !!autoloadLoaded;
                })
                .catch(function () {
                    return false;
                });

            return prismLoadPromise;
        }

        function highlightCodeBlocksWhenReady(scope, attemptsLeft) {
            if (!hasCodeBlocks(scope || document)) {
                return;
            }

            if (window.Prism && (typeof window.Prism.highlightAllUnder === 'function' || typeof window.Prism.highlightAll === 'function')) {
                highlightCodeBlocks(scope || document);
                return;
            }

            if ((attemptsLeft || 0) <= 0) {
                ensurePrismLoaded().then(function (loaded) {
                    if (loaded) {
                        highlightCodeBlocks(scope || document);
                    }
                });
                return;
            }

            window.setTimeout(function () {
                highlightCodeBlocksWhenReady(scope || document, attemptsLeft - 1);
            }, 60);
        }

        // Theme toggle
        document.querySelectorAll('.theme-cycle-btn').forEach(function (button) {
            button.addEventListener('click', function () {
                var currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
                var nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
                applyTheme(nextTheme);
                persistTheme(nextTheme);
            });
        });

        // Mobile nav toggle
        var navToggle = document.querySelector('.dd-nav-toggle');
        var nav = document.querySelector('.dd-nav');
        if (navToggle && nav) {
            var setNavState = function (isOpen) {
                nav.classList.toggle('open', isOpen);
                navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
                document.body.classList.toggle('nav-open', isOpen);
            };

            navToggle.addEventListener('click', function () {
                setNavState(!nav.classList.contains('open'));
            });

            nav.querySelectorAll('a').forEach(function (link) {
                link.addEventListener('click', function () {
                    setNavState(false);
                });
            });
        }

        // Header dropdowns
        var navDropdowns = document.querySelectorAll('.dd-nav-dropdown, .nav-dropdown');
        if (navDropdowns.length > 0) {
            var closeDropdown = function (dropdown) {
                var trigger = dropdown.querySelector('.dd-nav-dropdown-trigger, .nav-dropdown-trigger, .nav-dropdown-trigger-button');
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
                var trigger = dropdown.querySelector('.dd-nav-dropdown-trigger, .nav-dropdown-trigger, .nav-dropdown-trigger-button');
                if (!trigger) {
                    return;
                }

                trigger.addEventListener('click', function (event) {
                    if (trigger.tagName === 'BUTTON') {
                        event.preventDefault();
                    }

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

        // Docs sidebar toggle
        var docsToggle = document.querySelector('.docs-sidebar-toggle');
        var docsSidebar = document.querySelector('.docs-sidebar');
        var docsOverlay = document.querySelector('.docs-sidebar-overlay');
        if (docsToggle && docsSidebar && docsOverlay) {
            var setDocsSidebar = function (isOpen) {
                docsSidebar.classList.toggle('open', isOpen);
                docsOverlay.classList.toggle('open', isOpen);
                docsToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
            };

            docsToggle.addEventListener('click', function () {
                setDocsSidebar(!docsSidebar.classList.contains('open'));
            });

            docsOverlay.addEventListener('click', function () {
                setDocsSidebar(false);
            });
        }

        // Code example tabs
        document.querySelectorAll('.code-tabs').forEach(function (tabContainer) {
            var tabs = tabContainer.querySelectorAll('.code-tab-btn');
            var panels = tabContainer.querySelectorAll('.code-panel');

            tabs.forEach(function (tab) {
                tab.addEventListener('click', function () {
                    var target = tab.getAttribute('data-tab');

                    tabs.forEach(function (item) {
                        item.classList.remove('active');
                    });

                    panels.forEach(function (panel) {
                        panel.classList.remove('active');
                    });

                    tab.classList.add('active');
                    var panel = tabContainer.querySelector('.code-panel[data-panel="' + target + '"]');
                    if (panel) {
                        panel.classList.add('active');
                        highlightCodeBlocksWhenReady(panel, 12);
                    }
                });
            });
        });

        // Copy buttons
        document.querySelectorAll('[data-copy]').forEach(function (button) {
            button.addEventListener('click', function () {
                var text = button.getAttribute('data-copy') || '';
                var originalHtml = button.innerHTML;

                copyText(text).then(function () {
                    button.textContent = 'Copied';
                    window.setTimeout(function () {
                        button.innerHTML = originalHtml;
                    }, 1400);
                }).catch(function () {
                    button.textContent = 'Copy failed';
                    window.setTimeout(function () {
                        button.innerHTML = originalHtml;
                    }, 1400);
                });
            });
        });

        highlightCodeBlocksWhenReady(document, 12);
        window.addEventListener('load', function () {
            highlightCodeBlocksWhenReady(document, 6);
        });
        window.addEventListener('pageshow', function () {
            highlightCodeBlocksWhenReady(document, 6);
        });
    });
})();
