(function () {
    'use strict';

    var themes = ['dark', 'light'];
    var recentRunsKey = 'dd-tool-recent-runs';
    var prismLoadPromise = null;

    window.Prism = window.Prism || {};
    window.Prism.manual = true;

    function applyTheme(theme) {
        var nextTheme = theme === 'light' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        document.documentElement.style.colorScheme = nextTheme;
    }

    function loadRecentRunsState() {
        try {
            var raw = localStorage.getItem(recentRunsKey);
            if (!raw) {
                return {};
            }

            var parsed = JSON.parse(raw);
            return parsed && typeof parsed === 'object' ? parsed : {};
        } catch (error) {
            return {};
        }
    }

    function saveRecentRunsState(state) {
        try {
            localStorage.setItem(recentRunsKey, JSON.stringify(state));
        } catch (error) {
            // Ignore quota and storage errors.
        }
    }

    function hasCodeBlocks(scope) {
        var root = scope || document;
        return !!(root && root.querySelector && root.querySelector('pre code[class*="language-"]'));
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

    function ensurePrismLoaded(scope) {
        if (!hasCodeBlocks(scope)) {
            return Promise.resolve(false);
        }

        if (window.Prism && window.Prism.plugins && window.Prism.plugins.autoloader) {
            return Promise.resolve(true);
        }

        if (prismLoadPromise) {
            return prismLoadPromise;
        }

        prismLoadPromise = loadScript('assets/prism/prism-core.min.js')
            .then(function (coreLoaded) {
                if (!coreLoaded) {
                    return false;
                }

                return loadScript('assets/prism/prism-autoloader.min.js');
            })
            .then(function (autoloadLoaded) {
                return !!autoloadLoaded;
            })
            .catch(function () {
                return false;
            });

        return prismLoadPromise;
    }

    function highlightCodeBlocks(scope) {
        var root = scope || document;
        if (!hasCodeBlocks(root)) {
            return Promise.resolve(false);
        }

        return ensurePrismLoaded(root).then(function (loaded) {
            if (!loaded || !window.Prism) {
                return false;
            }

            if (window.Prism.plugins && window.Prism.plugins.autoloader) {
                window.Prism.plugins.autoloader.languages_path = 'assets/prism/components/';
            }

            if (root && typeof window.Prism.highlightAllUnder === 'function') {
                window.Prism.highlightAllUnder(root);
                return true;
            }

            if (typeof window.Prism.highlightAll === 'function') {
                window.Prism.highlightAll();
                return true;
            }

            return false;
        });
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
        },
        copyText: async function (text) {
            if (!text) {
                return false;
            }

            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(text);
                    return true;
                }
            } catch (error) {
                // Fall back to document.execCommand below.
            }

            try {
                var element = document.createElement('textarea');
                element.value = text;
                element.setAttribute('readonly', 'readonly');
                element.style.position = 'fixed';
                element.style.opacity = '0';
                element.style.pointerEvents = 'none';
                document.body.appendChild(element);
                element.focus();
                element.select();
                var copied = document.execCommand('copy');
                document.body.removeChild(element);
                return copied;
            } catch (error) {
                return false;
            }
        },
        loadRecentRuns: function (toolSlug) {
            if (!toolSlug) {
                return [];
            }

            var state = loadRecentRunsState();
            return Array.isArray(state[toolSlug]) ? state[toolSlug] : [];
        },
        saveRecentRun: function (toolSlug, item) {
            if (!toolSlug || !item || !item.domain) {
                return [];
            }

            var state = loadRecentRunsState();
            var current = Array.isArray(state[toolSlug]) ? state[toolSlug] : [];
            var normalized = {
                domain: item.domain,
                dnsHost: item.dnsHost || null,
                secondaryInput: item.secondaryInput || null,
                dnsResolver: item.dnsResolver || null,
                savedAtUtc: item.savedAtUtc || new Date().toISOString()
            };
            var deduped = current.filter(function (entry) {
                if (!entry || !entry.domain) {
                    return false;
                }

                return !(entry.domain.toLowerCase() === normalized.domain.toLowerCase()
                    && (entry.dnsHost || '') === (normalized.dnsHost || '')
                    && (entry.secondaryInput || '') === (normalized.secondaryInput || '')
                    && (entry.dnsResolver || '') === (normalized.dnsResolver || ''));
            });

            deduped.unshift(normalized);
            state[toolSlug] = deduped.slice(0, 6);
            saveRecentRunsState(state);
            return state[toolSlug];
        },
        scrollToElement: function (id) {
            if (!id) {
                return false;
            }

            var element = document.getElementById(id);
            if (!element) {
                return false;
            }

            var header = document.querySelector('.dd-header');
            var headerHeight = header ? header.getBoundingClientRect().height : 0;
            var extraOffset = 20;
            var top = window.scrollY + element.getBoundingClientRect().top - headerHeight - extraOffset;
            window.scrollTo({
                top: Math.max(top, 0),
                behavior: 'smooth'
            });

            return true;
        },
        highlightCodeBlocks: function (scope) {
            return highlightCodeBlocks(scope);
        }
    };
})();
