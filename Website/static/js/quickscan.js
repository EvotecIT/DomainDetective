/* DomainDetective quick scan.
   A small DNS-over-HTTPS pass that answers "what does this domain publish?" in well under a second,
   before the full DomainDetective engine (WebAssembly) has finished loading. It reads public records only,
   runs entirely in the browser and never sends the domain anywhere except the chosen DoH resolver.
   The full analysis in the tools remains the source of truth; this is the first look. */

(function () {
    'use strict';

    var RESOLVERS = [
        { url: 'https://cloudflare-dns.com/dns-query', headers: { Accept: 'application/dns-json' } },
        { url: 'https://dns.google/resolve', headers: {} }
    ];

    var TYPE = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };

    function normalizeDomain(value) {
        var text = String(value || '').trim().toLowerCase();
        text = text.replace(/^[a-z]+:\/\//, '').replace(/^\*\./, '');
        text = text.split(/[\/?#\s]/)[0];
        if (text.indexOf('@') >= 0) {
            text = text.split('@').pop();
        }
        text = text.replace(/\.$/, '');
        if (!/^(?=.{1,253}$)([a-z0-9-_]{1,63}\.)+[a-z0-9-]{2,63}$/.test(text) && !/^xn--/.test(text)) {
            return null;
        }
        return text;
    }

    function query(name, type, options) {
        var dnssec = options && options.dnssec;
        var attempt = function (index) {
            var resolver = RESOLVERS[index];
            var url = resolver.url + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type) + (dnssec ? '&do=1' : '');
            var controller = typeof AbortController === 'function' ? new AbortController() : null;
            var timer = controller ? window.setTimeout(function () { controller.abort(); }, 4500) : null;
            return fetch(url, { headers: resolver.headers, signal: controller ? controller.signal : undefined, credentials: 'omit', referrerPolicy: 'no-referrer' })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error('HTTP ' + response.status);
                    }
                    return response.json();
                })
                .finally(function () {
                    if (timer) {
                        window.clearTimeout(timer);
                    }
                })
                .catch(function (error) {
                    if (index + 1 < RESOLVERS.length) {
                        return attempt(index + 1);
                    }
                    throw error;
                });
        };
        return attempt(0);
    }

    function answers(response, type) {
        var code = TYPE[type];
        return ((response && response.Answer) || [])
            .filter(function (record) { return record.type === code; })
            .map(function (record) { return record.data; });
    }

    function txt(data) {
        /* DoH JSON returns TXT data as one or more quoted strings; join them back into one value. */
        var parts = String(data).match(/"((?:[^"\\]|\\.)*)"/g);
        if (!parts) {
            return String(data);
        }
        return parts.map(function (part) { return part.slice(1, -1).replace(/\\"/g, '"'); }).join('');
    }

    function tag(value, name) {
        var match = new RegExp('(?:^|;)\\s*' + name + '\\s*=\\s*([^;]+)', 'i').exec(value);
        return match ? match[1].trim() : null;
    }

    function caa(data) {
        var text = String(data).trim();
        /* RFC 3597 generic form: \# <length> <hex bytes> */
        var generic = /^\\#\s+\d+\s+([0-9a-f\s]+)$/i.exec(text);
        if (generic) {
            var bytes = generic[1].replace(/\s+/g, '').match(/../g) || [];
            var codes = bytes.map(function (pair) { return parseInt(pair, 16); });
            var tagLength = codes[1] || 0;
            var tagName = String.fromCharCode.apply(null, codes.slice(2, 2 + tagLength));
            var tagValue = String.fromCharCode.apply(null, codes.slice(2 + tagLength));
            return { tag: tagName.toLowerCase(), value: tagValue };
        }
        var match = /^\d+\s+([a-z0-9]+)\s+"?(.*?)"?$/i.exec(text);
        return match ? { tag: match[1].toLowerCase(), value: match[2] } : null;
    }

    function providerFor(host) {
        var h = host.toLowerCase();
        if (/\.mail\.protection\.outlook\.com\.?$/.test(h)) { return 'Microsoft 365'; }
        if (/(aspmx\.l\.google\.com|googlemail\.com|\.google\.com)\.?$/.test(h)) { return 'Google Workspace'; }
        if (/(pphosted\.com|ppe-hosted\.com)\.?$/.test(h)) { return 'Proofpoint'; }
        if (/mimecast\.com\.?$/.test(h)) { return 'Mimecast'; }
        if (/zoho\.(com|eu)\.?$/.test(h)) { return 'Zoho Mail'; }
        if (/(protonmail\.ch|proton\.me)\.?$/.test(h)) { return 'Proton Mail'; }
        if (/(messagingengine\.com|fastmail)\.?/.test(h)) { return 'Fastmail'; }
        if (/amazonaws\.com\.?$/.test(h)) { return 'Amazon SES'; }
        return null;
    }

    function check(id, label, run) {
        return run().then(function (result) {
            result.id = id;
            result.label = label;
            return result;
        }).catch(function () {
            return { id: id, label: label, status: 'info', value: 'Lookup failed', detail: 'The resolver did not answer in time.' };
        });
    }

    function scan(domain) {
        var started = (window.performance && performance.now) ? performance.now() : Date.now();
        var checks = [
            check('spf', 'SPF', function () {
                return query(domain, 'TXT').then(function (response) {
                    var records = answers(response, 'TXT').map(txt).filter(function (value) { return /^v=spf1(\s|$)/i.test(value); });
                    if (records.length === 0) {
                        return { status: 'fail', value: 'Not published', detail: 'Anyone can send mail as this domain.' };
                    }
                    if (records.length > 1) {
                        return { status: 'fail', value: records.length + ' records', detail: 'Multiple SPF records cause a permanent error.' };
                    }
                    var record = records[0];
                    var all = /([-~?+])?all\b/i.exec(record);
                    var lookups = (record.match(/\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/gi) || []).length;
                    var qualifier = all ? (all[1] || '+') : null;
                    var budget = lookups + ' of 10 direct lookups';
                    if (qualifier === '-') { return { status: 'pass', value: 'Enforced (-all)', detail: budget, record: record }; }
                    if (qualifier === '~') { return { status: 'warn', value: 'Soft fail (~all)', detail: budget, record: record }; }
                    if (/redirect=/i.test(record)) { return { status: 'info', value: 'Redirected', detail: tag(record.replace(/\s+/g, ';'), 'redirect') || budget, record: record }; }
                    return { status: 'fail', value: qualifier ? 'Permissive (' + qualifier + 'all)' : 'No all mechanism', detail: budget, record: record };
                });
            }),
            check('dmarc', 'DMARC', function () {
                return query('_dmarc.' + domain, 'TXT').then(function (response) {
                    var records = answers(response, 'TXT').map(txt).filter(function (value) { return /^v=DMARC1/i.test(value); });
                    if (records.length === 0) {
                        return { status: 'fail', value: 'Not published', detail: 'Receivers get no policy for spoofed mail.' };
                    }
                    var policy = (tag(records[0], 'p') || '').toLowerCase();
                    var pct = tag(records[0], 'pct');
                    var rua = tag(records[0], 'rua');
                    var detail = (rua ? 'Aggregate reports on' : 'No aggregate reports') + (pct && pct !== '100' ? ' · pct=' + pct : '');
                    if (policy === 'reject') { return { status: 'pass', value: 'p=reject', detail: detail, record: records[0] }; }
                    if (policy === 'quarantine') { return { status: 'pass', value: 'p=quarantine', detail: detail, record: records[0] }; }
                    return { status: 'warn', value: 'p=' + (policy || 'missing'), detail: 'Monitoring only. Spoofed mail is still delivered.', record: records[0] };
                });
            }),
            check('mx', 'MX', function () {
                return query(domain, 'MX').then(function (response) {
                    var hosts = answers(response, 'MX').map(function (value) {
                        var parts = String(value).split(/\s+/);
                        return { pref: parseInt(parts[0], 10), host: (parts[1] || '').replace(/\.$/, '') };
                    }).sort(function (a, b) { return a.pref - b.pref; });
                    if (hosts.length === 0) {
                        return { status: 'info', value: 'No MX', detail: 'This domain does not receive mail.' };
                    }
                    if (hosts.length === 1 && (hosts[0].host === '' || hosts[0].host === '.')) {
                        return { status: 'info', value: 'Null MX', detail: 'Mail explicitly refused (RFC 7505).' };
                    }
                    var provider = null;
                    hosts.some(function (item) { provider = providerFor(item.host); return !!provider; });
                    return { status: 'pass', value: provider || (hosts.length + ' host' + (hosts.length > 1 ? 's' : '')), detail: hosts[0].host };
                });
            }),
            check('dnssec', 'DNSSEC', function () {
                return query(domain, 'A', { dnssec: true }).then(function (response) {
                    if (response && response.AD === true) {
                        return { status: 'pass', value: 'Signed and validated', detail: 'Resolver set the AD flag.' };
                    }
                    return { status: 'warn', value: 'Not signed', detail: 'Answers can be forged in transit.' };
                });
            }),
            check('caa', 'CAA', function () {
                return query(domain, 'CAA').then(function (response) {
                    var records = answers(response, 'CAA');
                    if (records.length === 0) {
                        return { status: 'warn', value: 'Not published', detail: 'Any certificate authority may issue.' };
                    }
                    var parsed = records.map(caa).filter(Boolean);
                    var issueTags = parsed.filter(function (item) { return item.tag === 'issue' || item.tag === 'issuewild'; });
                    if (issueTags.length === 0) {
                        return { status: 'warn', value: 'No issuer restriction', detail: 'CAA exists but has no issue tag.' };
                    }
                    var issuers = issueTags.map(function (item) { return item.value.split(';')[0].trim(); })
                        .filter(function (value, index, all) { return all.indexOf(value) === index; });
                    var named = issuers.filter(Boolean);
                    if (named.length === 0) {
                        return { status: 'pass', value: 'Issuance forbidden', detail: 'No certificate authority may issue.' };
                    }
                    return { status: 'pass', value: named.length + ' issuer' + (named.length === 1 ? '' : 's'), detail: named.slice(0, 3).join(', ') };
                });
            }),
            check('mta-sts', 'MTA-STS', function () {
                return query('_mta-sts.' + domain, 'TXT').then(function (response) {
                    var records = answers(response, 'TXT').map(txt).filter(function (value) { return /^v=STSv1/i.test(value); });
                    if (records.length === 0) {
                        return { status: 'warn', value: 'Not published', detail: 'Inbound TLS can be downgraded.' };
                    }
                    return { status: 'pass', value: 'Published', detail: 'id=' + (tag(records[0], 'id') || '?') };
                });
            }),
            check('tls-rpt', 'TLS-RPT', function () {
                return query('_smtp._tls.' + domain, 'TXT').then(function (response) {
                    var records = answers(response, 'TXT').map(txt).filter(function (value) { return /^v=TLSRPTv1/i.test(value); });
                    if (records.length === 0) {
                        return { status: 'info', value: 'Not published', detail: 'No reports about failed TLS delivery.' };
                    }
                    return { status: 'pass', value: 'Reporting on', detail: (tag(records[0], 'rua') || '').replace(/^mailto:/, '') };
                });
            })
        ];

        return Promise.all(checks).then(function (results) {
            var ended = (window.performance && performance.now) ? performance.now() : Date.now();
            var summary = { pass: 0, warn: 0, fail: 0, info: 0 };
            results.forEach(function (item) { summary[item.status] = (summary[item.status] || 0) + 1; });
            return { domain: domain, results: results, summary: summary, elapsedMs: Math.round(ended - started) };
        });
    }

    /* ---------------------------------------------------------------- rendering into a case file */

    var ICONS = {
        pass: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.5 6.5 11.5 12.5 4.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        warn: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 4.2v4.6M8 11.6v.2" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
        fail: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4.5 4.5l7 7M11.5 4.5l-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        info: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 7.2v4.6M8 4.4v.2" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>'
    };
    var WORDS = { pass: 'Pass', warn: 'Review', fail: 'Fail', info: 'Info' };

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function renderRows(container, report) {
        container.innerHTML = report.results.map(function (item) {
            return '<li class="dd-case__row" data-status="' + item.status + '">' +
                '<span class="dd-case__name">' + escapeHtml(item.label) + '</span>' +
                '<span class="dd-case__value"><strong>' + escapeHtml(item.value) + '</strong><small>' + escapeHtml(item.detail || '') + '</small></span>' +
                '<span class="dd-verdict dd-verdict--' + item.status + '">' + ICONS[item.status] + WORDS[item.status] + '</span>' +
                '</li>';
        }).join('');
    }

    function bindCaseFile(caseFile) {
        var form = document.querySelector(caseFile.getAttribute('data-dd-form') || '[data-dd-quickscan-form]');
        var rows = caseFile.querySelector('[data-dd-case-rows]');
        var domainLabel = caseFile.querySelector('[data-dd-case-domain]');
        var status = caseFile.querySelector('[data-dd-case-status]');
        var score = caseFile.querySelector('[data-dd-case-score]');
        var fullLink = caseFile.querySelector('[data-dd-case-full]');
        var live = caseFile.querySelector('[data-dd-case-live]');
        var token = 0;

        function run(domain, focusResult) {
            var current = ++token;
            caseFile.setAttribute('aria-busy', 'true');
            caseFile.classList.add('is-scanning');
            if (domainLabel) { domainLabel.textContent = domain; }
            if (status) { status.textContent = 'Asking DNS…'; }
            if (fullLink) { fullLink.href = '/tools/domain-overview/?q=' + encodeURIComponent(domain); }
            return scan(domain).then(function (report) {
                if (current !== token) {
                    return;
                }
                renderRows(rows, report);
                if (score) {
                    score.innerHTML =
                        '<span class="dd-case__count dd-case__count--pass"><b>' + report.summary.pass + '</b> passed</span>' +
                        '<span class="dd-case__count dd-case__count--warn"><b>' + report.summary.warn + '</b> to review</span>' +
                        '<span class="dd-case__count dd-case__count--fail"><b>' + report.summary.fail + '</b> failing</span>';
                }
                if (status) { status.textContent = 'Live from DNS in ' + report.elapsedMs + ' ms'; }
                if (live) { live.textContent = 'Quick scan of ' + domain + ': ' + report.summary.pass + ' passed, ' + report.summary.warn + ' to review, ' + report.summary.fail + ' failing.'; }
                caseFile.setAttribute('data-state', 'live');
                if (focusResult && rows) {
                    rows.setAttribute('tabindex', '-1');
                    rows.focus({ preventScroll: true });
                }
            }).catch(function () {
                if (status && current === token) { status.textContent = 'DNS lookup failed. Try again.'; }
            }).finally(function () {
                if (current === token) {
                    caseFile.removeAttribute('aria-busy');
                    caseFile.classList.remove('is-scanning');
                }
            });
        }

        function setLabel(attribute) {
            var submit = form && form.querySelector('[type="submit"]');
            var text = submit && submit.querySelector('[data-dd-label]');
            if (text && submit.getAttribute(attribute)) {
                text.textContent = submit.getAttribute(attribute);
            }
        }

        if (form) {
            form.addEventListener('submit', function (event) {
                var input = form.querySelector('input[name="q"], input[type="text"], input[type="search"]');
                var domain = normalizeDomain(input && input.value);
                if (!domain) {
                    if (input) {
                        input.setCustomValidity('Enter a domain such as example.com');
                        input.reportValidity();
                        input.addEventListener('input', function () { input.setCustomValidity(''); }, { once: true });
                    }
                    event.preventDefault();
                    return;
                }
                /* First submit shows the quick scan in place; the "full report" link carries on to the tools. */
                if (form.getAttribute('data-dd-submitted') !== domain) {
                    event.preventDefault();
                    form.setAttribute('data-dd-submitted', domain);
                    run(domain, true);
                    setLabel('data-full-label');
                }
            });
            var field = form.querySelector('input[name="q"]');
            if (field) {
                field.addEventListener('input', function () {
                    form.removeAttribute('data-dd-submitted');
                    setLabel('data-label');
                });
            }
        }

        var initial = caseFile.getAttribute('data-dd-domain');
        if (initial) {
            var start = function () { run(initial, false); };
            if ('requestIdleCallback' in window) {
                window.requestIdleCallback(start, { timeout: 1500 });
            } else {
                window.setTimeout(start, 400);
            }
        }
    }

    window.DomainDetectiveQuickScan = { scan: scan, normalizeDomain: normalizeDomain, query: query, render: renderRows };

    function init() {
        document.querySelectorAll('[data-dd-casefile]').forEach(bindCaseFile);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
