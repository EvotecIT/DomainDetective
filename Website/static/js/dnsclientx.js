/* DnsClientX landing page: a small live resolver in the hero.
   It asks a public DNS-over-HTTPS resolver from the browser (through quickscan.js) and shows the DnsClientX C# and
   PowerShell that ask the same question. Nothing is sent anywhere except the chosen resolver. */

(function () {
    'use strict';

    var ENDPOINT = { cloudflare: 'Cloudflare', google: 'Google' };
    var TYPE_CODES = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48, TLSA: 52, HTTPS: 65, CAA: 257 };

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function codeFor(lang, name, type, provider) {
        if (lang === 'ps') {
            return 'Resolve-Dns -Name ' + name + ' -Type ' + type + ' -DnsProvider ' + ENDPOINT[provider];
        }
        return 'var response = await ClientX.QueryDns("' + name + '", DnsRecordType.' + type + ', DnsEndpoint.' + ENDPOINT[provider] + ');';
    }

    function init() {
        var root = document.querySelector('[data-dx-console]');
        if (!root || !window.DomainDetectiveQuickScan) {
            return;
        }
        var form = root.querySelector('[data-dx-form]');
        var answers = root.querySelector('[data-dx-answers]');
        var status = root.querySelector('[data-dx-status]');
        var code = root.querySelector('[data-dx-code]');
        var tabs = Array.prototype.slice.call(root.querySelectorAll('[data-dx-lang]'));
        var lang = 'cs';
        var token = 0;

        function current() {
            var name = window.DomainDetectiveQuickScan.normalizeDomain(form.elements.name.value) || form.elements.name.value.trim();
            return { name: name, type: form.elements.type.value, provider: form.elements.provider.value };
        }

        function updateCode() {
            var q = current();
            code.textContent = codeFor(lang, q.name || 'example.com', q.type, q.provider);
        }

        function resolve() {
            var q = current();
            if (!q.name || !window.DomainDetectiveQuickScan.normalizeDomain(q.name)) {
                form.elements.name.setCustomValidity('Enter a DNS name such as example.com');
                form.elements.name.reportValidity();
                return;
            }
            var run = ++token;
            var started = performance.now();
            root.setAttribute('aria-busy', 'true');
            status.textContent = 'Asking ' + ENDPOINT[q.provider] + '…';
            updateCode();
            // quickscan.js tries Cloudflare first and falls back to Google; ask the chosen one first.
            var query = q.provider === 'google'
                ? fetch('https://dns.google/resolve?name=' + encodeURIComponent(q.name) + '&type=' + encodeURIComponent(q.type), { credentials: 'omit', referrerPolicy: 'no-referrer' }).then(function (r) { return r.json(); })
                : window.DomainDetectiveQuickScan.query(q.name, q.type);
            query.then(function (response) {
                if (run !== token) {
                    return;
                }
                var ms = Math.round(performance.now() - started);
                var wanted = TYPE_CODES[q.type];
                var rows = (response.Answer || []);
                var matching = rows.filter(function (row) { return row.type === wanted; });
                var shown = matching.length ? matching : rows;
                if (!shown.length) {
                    var message = response.Status === 3 ? 'NXDOMAIN, the name does not exist' : 'No ' + q.type + ' records (NOERROR)';
                    answers.innerHTML = '<li class="dx-console__empty">' + escapeHtml(message) + '</li>';
                } else {
                    answers.innerHTML = shown.slice(0, 8).map(function (row) {
                        return '<li><span class="dx-console__name">' + escapeHtml(String(row.name).replace(/\.$/, '')) + '</span>' +
                            '<span class="dx-console__ttl">' + escapeHtml(row.TTL) + 's</span>' +
                            '<span class="dx-console__data">' + escapeHtml(row.data) + '</span></li>';
                    }).join('') + (shown.length > 8 ? '<li class="dx-console__empty">' + (shown.length - 8) + ' more records</li>' : '');
                }
                status.textContent = (response.AD ? 'DNSSEC validated · ' : '') + ms + ' ms via ' + ENDPOINT[q.provider];
            }).catch(function () {
                if (run === token) {
                    answers.innerHTML = '<li class="dx-console__empty">The resolver did not answer. Try again.</li>';
                    status.textContent = 'Lookup failed';
                }
            }).finally(function () {
                if (run === token) {
                    root.removeAttribute('aria-busy');
                }
            });
        }

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            resolve();
        });
        form.elements.name.addEventListener('input', function () {
            form.elements.name.setCustomValidity('');
            updateCode();
        });
        form.elements.type.addEventListener('change', resolve);
        form.elements.provider.addEventListener('change', resolve);
        tabs.forEach(function (tab) {
            tab.addEventListener('click', function () {
                lang = tab.getAttribute('data-dx-lang');
                tabs.forEach(function (other) { other.setAttribute('aria-selected', other === tab ? 'true' : 'false'); });
                updateCode();
            });
        });

        updateCode();
        if ('requestIdleCallback' in window) {
            window.requestIdleCallback(resolve, { timeout: 1500 });
        } else {
            window.setTimeout(resolve, 400);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
