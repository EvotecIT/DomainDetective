/* DomainDetective browser tools: hub filtering and the tool-page boot sequence.

   Tool pages are complete static HTML. This script starts the DomainDetective engine (Blazor WebAssembly)
   straight away, shows its download progress, and makes the static form useful before the engine is ready:
   a submit runs the DNS quick scan from quickscan.js, records the domain in ?q=, and the engine picks that
   up and runs the full analysis as soon as it mounts. */

(function () {
    'use strict';

    /* ---------------------------------------------------------------- hub */

    function initHub() {
        var form = document.querySelector('[data-dd-hub-search]');
        if (!form) {
            return;
        }
        var input = form.querySelector('input');
        var groups = Array.prototype.slice.call(document.querySelectorAll('[data-dd-hub-group]'));
        var empty = document.querySelector('[data-dd-hub-empty]');

        function apply() {
            var terms = (input.value || '').toLowerCase().trim().split(/\s+/).filter(Boolean);
            var visible = 0;
            groups.forEach(function (group) {
                var shown = 0;
                group.querySelectorAll('[data-dd-hub-tool]').forEach(function (item) {
                    var haystack = item.getAttribute('data-search') || '';
                    var match = terms.every(function (term) { return haystack.indexOf(term) >= 0; });
                    item.hidden = !match;
                    if (match) {
                        shown++;
                    }
                });
                group.hidden = shown === 0;
                visible += shown;
            });
            if (empty) {
                empty.hidden = visible !== 0;
            }
        }

        input.addEventListener('input', apply);
        document.addEventListener('keydown', function (event) {
            var target = event.target;
            var typing = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable);
            if (event.key === '/' && !typing) {
                event.preventDefault();
                input.focus();
            }
        });
        if (input.value) {
            apply();
        }
    }

    /* ---------------------------------------------------------------- tool page */

    var QUICK_CHECKS = {
        spf: ['spf'], dkim: ['spf', 'dmarc'], dmarc: ['dmarc'], mx: ['mx'], 'mta-sts': ['mta-sts', 'mx'],
        'tls-rpt': ['tls-rpt'], bimi: ['dmarc'], dnssec: ['dnssec'], caa: ['caa'], 'cert-check': ['caa'],
        'dns-lookup': ['mx', 'spf', 'caa', 'dnssec'], ns: ['dnssec'], soa: ['dnssec'], 'dns-propagation': ['mx', 'dnssec']
    };

    function initTool() {
        var root = document.querySelector('[data-dd-tool-root]');
        if (!root) {
            return;
        }
        var slug = root.getAttribute('data-tool');
        var form = root.querySelector('[data-dd-tool-form]');
        var boot = root.querySelector('[data-dd-boot]');
        var bootText = root.querySelector('[data-dd-boot-text]');
        var quick = root.querySelector('[data-dd-quick]');
        var started = Date.now();
        var ready = false;

        function setBootText(text) {
            if (bootText) {
                bootText.textContent = text;
            }
        }

        /* Blazor publishes its download progress as CSS variables on the document element. */
        var progressTimer = window.setInterval(function () {
            if (ready || !boot) {
                window.clearInterval(progressTimer);
                return;
            }
            var value = getComputedStyle(document.documentElement).getPropertyValue('--blazor-load-percentage').trim();
            var percent = parseFloat(value) || 0;
            boot.style.setProperty('--dd-boot', Math.max(4, Math.min(100, percent)) + '%');
            if (percent > 0 && percent < 100) {
                setBootText('Loading the DomainDetective engine… ' + Math.round(percent) + '%');
            } else if (percent >= 100) {
                setBootText('Starting the DomainDetective engine…');
            }
        }, 150);

        function currentQuery() {
            try {
                return new URLSearchParams(window.location.search).get('q') || '';
            } catch (error) {
                return '';
            }
        }

        function setQuery(domain) {
            try {
                var url = new URL(window.location.href);
                url.searchParams.set('q', domain);
                window.history.replaceState(window.history.state, '', url.toString());
            } catch (error) {
                /* Older browsers keep the plain form submit as a fallback. */
            }
        }

        function runQuick(domain) {
            if (!quick || !window.DomainDetectiveQuickScan) {
                return;
            }
            var wanted = QUICK_CHECKS[slug];
            quick.hidden = false;
            quick.setAttribute('aria-busy', 'true');
            quick.innerHTML = '<div class="dd-quick__head"><strong>First look at ' + escapeHtml(domain) + '</strong><span>Asking DNS…</span></div>';
            window.DomainDetectiveQuickScan.scan(domain).then(function (report) {
                if (ready) {
                    return;
                }
                var results = wanted ? report.results.filter(function (item) { return wanted.indexOf(item.id) >= 0; }) : report.results;
                var list = document.createElement('ul');
                list.className = 'dd-quick__rows';
                window.DomainDetectiveQuickScan.render(list, { results: results });
                quick.innerHTML = '<div class="dd-quick__head"><strong>First look at ' + escapeHtml(domain) + '</strong><span>Live from DNS in ' + report.elapsedMs + ' ms</span></div>';
                quick.appendChild(list);
                var note = document.createElement('p');
                note.className = 'dd-quick__note';
                note.textContent = 'The full DomainDetective analysis replaces this as soon as the engine finishes loading.';
                quick.appendChild(note);
            }).catch(function () {
                quick.innerHTML = '<div class="dd-quick__head"><strong>First look at ' + escapeHtml(domain) + '</strong><span>DNS lookup failed</span></div>';
            }).finally(function () {
                quick.removeAttribute('aria-busy');
            });
        }

        function submitEarly(domain) {
            setQuery(domain);
            runQuick(domain);
            setBootText('Your check starts automatically when the engine is ready…');
        }

        if (form) {
            var input = form.querySelector('input[name="q"]');
            var initial = currentQuery();
            if (input && initial) {
                input.value = initial;
                runQuick(initial);
            }
            form.addEventListener('submit', function (event) {
                event.preventDefault();
                var normalize = window.DomainDetectiveQuickScan && window.DomainDetectiveQuickScan.normalizeDomain;
                var domain = normalize ? normalize(input.value) : (input.value || '').trim();
                if (!domain) {
                    input.setCustomValidity('Enter a domain such as example.com');
                    input.reportValidity();
                    input.addEventListener('input', function () { input.setCustomValidity(''); }, { once: true });
                    return;
                }
                submitEarly(domain);
            });
            root.addEventListener('click', function (event) {
                var chip = event.target.closest('[data-dd-example]');
                if (!chip || ready) {
                    return;
                }
                event.preventDefault();
                var domain = chip.getAttribute('data-dd-example');
                if (input) {
                    input.value = domain;
                }
                submitEarly(domain);
            });
        }

        function markReady() {
            ready = true;
            document.documentElement.classList.add('dd-engine-ready');
            window.clearInterval(progressTimer);
        }

        function fail() {
            window.clearInterval(progressTimer);
            if (boot) {
                boot.classList.add('is-failed');
            }
            setBootText('The browser engine could not load. The quick DNS look above still works, and every check runs from PowerShell or the CLI below.');
        }

        function start() {
            if (!window.Blazor || typeof window.Blazor.start !== 'function') {
                fail();
                return;
            }
            window.Blazor.start().then(function () {
                markReady();
                if (window.performance && performance.mark) {
                    performance.mark('dd-engine-ready');
                }
                root.setAttribute('data-engine-ms', String(Date.now() - started));
            }).catch(fail);
        }

        var script = document.querySelector('script[data-dd-blazor]');
        if (window.Blazor) {
            start();
        } else if (script) {
            script.addEventListener('load', start, { once: true });
            script.addEventListener('error', fail, { once: true });
        }
    }

    function escapeHtml(value) {
        return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function init() {
        initHub();
        initTool();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
