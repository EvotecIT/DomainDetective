(function () {
    'use strict';

    var controllers = new WeakMap();

    var recordTypeMap = {
        0: 'Reserved',
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        43: 'DS',
        46: 'RRSIG',
        47: 'NSEC',
        48: 'DNSKEY',
        50: 'NSEC3',
        52: 'TLSA',
        64: 'SVCB',
        65: 'HTTPS',
        99: 'SPF',
        257: 'CAA'
    };

    var rcodeMap = {
        0: 'NOERROR',
        1: 'FORMERR',
        2: 'SERVFAIL',
        3: 'NXDOMAIN',
        4: 'NOTIMP',
        5: 'REFUSED'
    };

    var providers = {
        google: {
            label: 'Google Public DNS',
            endpoint: 'DnsEndpoint.Google',
            powershellProvider: 'Google',
            baseUrl: 'https://dns.google/resolve',
            headers: {},
            supportsEcs: true
        },
        cloudflare: {
            label: 'Cloudflare DNS JSON',
            endpoint: 'DnsEndpoint.Cloudflare',
            powershellProvider: 'Cloudflare',
            baseUrl: 'https://cloudflare-dns.com/dns-query',
            headers: { Accept: 'application/dns-json' },
            supportsEcs: false
        }
    };

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function getTypeLabel(type) {
        if (typeof type === 'number' && recordTypeMap[type]) {
            return recordTypeMap[type];
        }

        return String(type == null ? '' : type);
    }

    function buildSummaryCard(label, value, meta) {
        return '<article class="tool-summary-card raw-dns-query-summary-card">' +
            '<span class="tool-summary-label">' + escapeHtml(label) + '</span>' +
            '<strong class="tool-summary-value">' + escapeHtml(value) + '</strong>' +
            '<p class="tool-summary-note">' + escapeHtml(meta) + '</p>' +
            '</article>';
    }

    function renderSummary(state, payload, provider, summaryElement) {
        var answers = payload.Answer || [];
        var authority = payload.Authority || [];
        var additional = payload.Additional || [];
        var flags = [
            payload.AD ? 'AD' : null,
            payload.CD ? 'CD' : null,
            payload.RA ? 'RA' : null,
            payload.RD ? 'RD' : null
        ].filter(Boolean);

        summaryElement.innerHTML = [
            buildSummaryCard('Status', rcodeMap[payload.Status] || String(payload.Status == null ? 'n/a' : payload.Status), provider.label),
            buildSummaryCard('Answers', String(answers.length), authority.length + ' authority'),
            buildSummaryCard('Additional', String(additional.length), payload.Comment || 'No comment'),
            buildSummaryCard('Question', state.type, state.name)
        ].join('');

        if (flags.length > 0) {
            summaryElement.insertAdjacentHTML(
                'beforeend',
                '<article class="tool-summary-card raw-dns-query-summary-card">' +
                    '<span class="tool-summary-label">Flags</span>' +
                    '<strong class="tool-summary-value">DNS</strong>' +
                    '<div class="tool-chip-list raw-dns-query-flags">' +
                        flags.map(function (flag) { return '<span class="tool-chip">' + escapeHtml(flag) + '</span>'; }).join('') +
                    '</div>' +
                '</article>'
            );
        }
    }

    function renderSections(payload, recordsElement) {
        var sections = [
            { title: 'Question', rows: payload.Question || [], empty: 'No question section returned.' },
            { title: 'Answer', rows: payload.Answer || [], empty: 'No answer records returned.' },
            { title: 'Authority', rows: payload.Authority || [], empty: 'No authority records returned.' },
            { title: 'Additional', rows: payload.Additional || [], empty: 'No additional records returned.' }
        ];

        recordsElement.innerHTML = sections.map(function (section) {
            if (!section.rows.length) {
                return '<section class="result-card raw-dns-query-section">' +
                    '<h2 class="raw-dns-query-section-title">' + escapeHtml(section.title) + '</h2>' +
                    '<div class="raw-dns-query-empty">' + escapeHtml(section.empty) + '</div>' +
                    '</section>';
            }

            var isQuestionSection = section.title === 'Question';
            var headerHtml = isQuestionSection
                ? '<thead><tr><th>Name</th><th>Type</th></tr></thead>'
                : '<thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Data</th></tr></thead>';

            var rowsHtml = section.rows.map(function (row) {
                if (isQuestionSection) {
                    return '<tr>' +
                        '<td><code>' + escapeHtml(row.name || row.Name || '') + '</code></td>' +
                        '<td>' + escapeHtml(getTypeLabel(row.type || row.Type || '')) + '</td>' +
                        '</tr>';
                }

                return '<tr>' +
                    '<td><code>' + escapeHtml(row.name || row.Name || '') + '</code></td>' +
                    '<td>' + escapeHtml(getTypeLabel(row.type || row.Type || '')) + '</td>' +
                    '<td>' + escapeHtml(row.TTL == null ? (row.ttl == null ? '' : row.ttl) : row.TTL) + '</td>' +
                    '<td><code>' + escapeHtml(row.data || row.Data || '') + '</code></td>' +
                    '</tr>';
            }).join('');

            return '<section class="result-card raw-dns-query-section">' +
                '<h2 class="raw-dns-query-section-title">' + escapeHtml(section.title) + '</h2>' +
                '<div class="raw-dns-query-table-scroll"><table class="result-table raw-dns-query-table">' +
                headerHtml +
                '<tbody>' + rowsHtml + '</tbody></table></div>' +
                '</section>';
        }).join('');
    }

    function buildCSharpSnippet(state) {
        var provider = providers[state.providerId] || providers.google;
        var requestDnsSec = state.showDnssec;
        var validateDnsSec = state.showDnssec && !state.disableValidation;

        if (state.ecs) {
            return [
                'using DnsClientX;',
                '',
                'using var client = new ClientXBuilder()',
                '    .WithEndpoint(' + provider.endpoint + ')',
                '    .WithEdnsOptions(new EdnsOptions {',
                '        EnableEdns = true,',
                '        Subnet = new EdnsClientSubnetOption("' + state.ecs + '")',
                '    })',
                '    .Build();',
                '',
                'DnsResponse response = await client.Resolve("' + state.name + '", DnsRecordType.' + state.type + ',',
                '    requestDnsSec: ' + String(requestDnsSec).toLowerCase() + ',',
                '    validateDnsSec: ' + String(validateDnsSec).toLowerCase() + ');',
                '',
                'foreach (var answer in response.Answers) {',
                '    Console.WriteLine($"{answer.Type}: {answer.Data}");',
                '}'
            ].join('\n');
        }

        return [
            'using DnsClientX;',
            '',
            'using var client = new ClientX(' + provider.endpoint + ');',
            'DnsResponse response = await client.Resolve("' + state.name + '", DnsRecordType.' + state.type + ',',
            '    requestDnsSec: ' + String(requestDnsSec).toLowerCase() + ',',
            '    validateDnsSec: ' + String(validateDnsSec).toLowerCase() + ');',
            '',
            'foreach (var answer in response.Answers) {',
            '    Console.WriteLine($"{answer.Type}: {answer.Data}");',
            '}'
        ].join('\n');
    }

    function buildPowerShellSnippet(state) {
        var provider = providers[state.providerId] || providers.google;
        var argumentsList = [
            "-Name '" + state.name + "'",
            '-Type ' + state.type,
            '-DnsProvider ' + provider.powershellProvider
        ];

        if (state.showDnssec) {
            argumentsList.push('-RequestDnsSec');
        }

        if (state.showDnssec && !state.disableValidation) {
            argumentsList.push('-ValidateDnsSec');
        }

        var lines = [
            '$response = Resolve-Dns ' + argumentsList.join(' '),
            '$response | Format-Table'
        ];

        if (state.ecs) {
            lines.unshift('# EDNS client subnet is currently shown in the browser preview and the C# builder example.');
        }

        return lines.join('\n');
    }

    function setCopyButtonState(button, copied) {
        if (button._rawDnsCopyTimer) {
            clearTimeout(button._rawDnsCopyTimer);
            button._rawDnsCopyTimer = null;
        }

        button.textContent = copied ? 'Copied' : 'Copy';
        if (copied) {
            button._rawDnsCopyTimer = window.setTimeout(function () {
                button.textContent = 'Copy';
            }, 1400);
        }
    }

    function updateProviderNote(state, noteElement) {
        var provider = providers[state.providerId] || providers.google;
        if (provider.supportsEcs) {
            noteElement.textContent = 'Leave EDNS client subnet empty unless you want to simulate answers for a specific client network. Google preview supports EDNS client subnet and DNSSEC detail flags in the browser. The generated snippets show the closest DnsClientX equivalent.';
        } else {
            noteElement.textContent = 'Leave EDNS client subnet empty unless you want to simulate answers for a specific client network. Cloudflare preview ignores EDNS client subnet. The generated DnsClientX examples still show the selected record type and DNSSEC intent.';
        }
    }

    function initRawDnsQueryTool(root) {
        if (!root || typeof root.querySelector !== 'function') {
            return false;
        }

        if (controllers.has(root)) {
            return true;
        }

        var elements = {
            form: root.querySelector('.js-dns-query-form'),
            nameInput: root.querySelector('.js-dns-name'),
            typeInput: root.querySelector('.js-dns-type'),
            providerInput: root.querySelector('.js-dns-provider'),
            ecsInput: root.querySelector('.js-dns-ecs'),
            disableValidationInput: root.querySelector('.js-dns-disable-validation'),
            showDnssecInput: root.querySelector('.js-dns-show-dnssec'),
            directLink: root.querySelector('.js-dns-direct-link'),
            note: root.querySelector('.js-dns-note'),
            status: root.querySelector('.js-dns-status'),
            summary: root.querySelector('.js-dns-summary'),
            records: root.querySelector('.js-dns-records'),
            csharpCode: root.querySelector('.js-dns-csharp-code'),
            powershellCode: root.querySelector('.js-dns-powershell-code'),
            jsonCode: root.querySelector('.js-dns-json-code'),
            resolveButton: root.querySelector('.js-dns-query-form button[type="submit"]')
        };

        if (!elements.form || !elements.nameInput || !elements.typeInput || !elements.providerInput || !elements.ecsInput || !elements.disableValidationInput || !elements.showDnssecInput || !elements.directLink || !elements.note || !elements.status || !elements.summary || !elements.records || !elements.csharpCode || !elements.powershellCode || !elements.jsonCode || !elements.resolveButton) {
            return false;
        }

        function readStateFromUrl() {
            var url = new URL(window.location.href);
            var providerId = url.searchParams.get('provider');
            var type = url.searchParams.get('type');

            if (url.searchParams.has('name')) {
                elements.nameInput.value = url.searchParams.get('name') || '';
            }

            if (type && Array.from(elements.typeInput.options).some(function (option) { return option.value === type; })) {
                elements.typeInput.value = type;
            }

            if (providerId && providers[providerId]) {
                elements.providerInput.value = providerId;
            }

            if (url.searchParams.has('ecs')) {
                elements.ecsInput.value = url.searchParams.get('ecs') || '';
            }

            elements.disableValidationInput.checked = url.searchParams.get('disableValidation') === '1';
            elements.showDnssecInput.checked = url.searchParams.get('showDnssec') === '1';
        }

        function getState() {
            return {
                name: elements.nameInput.value.trim(),
                type: elements.typeInput.value,
                providerId: elements.providerInput.value,
                ecs: elements.ecsInput.value.trim(),
                disableValidation: elements.disableValidationInput.checked,
                showDnssec: elements.showDnssecInput.checked
            };
        }

        function writeStateToUrl(state) {
            var url = new URL(window.location.href);

            if (state.name) {
                url.searchParams.set('name', state.name);
            } else {
                url.searchParams.delete('name');
            }

            url.searchParams.set('type', state.type);
            url.searchParams.set('provider', state.providerId);

            if (state.ecs) {
                url.searchParams.set('ecs', state.ecs);
            } else {
                url.searchParams.delete('ecs');
            }

            if (state.disableValidation) {
                url.searchParams.set('disableValidation', '1');
            } else {
                url.searchParams.delete('disableValidation');
            }

            if (state.showDnssec) {
                url.searchParams.set('showDnssec', '1');
            } else {
                url.searchParams.delete('showDnssec');
            }

            window.history.replaceState({}, '', url.toString());
        }

        function buildRequest(state) {
            var provider = providers[state.providerId] || providers.google;
            var url = new URL(provider.baseUrl);

            url.searchParams.set('name', state.name);
            url.searchParams.set('type', state.type);

            if (state.disableValidation) {
                url.searchParams.set('cd', '1');
            }

            if (state.showDnssec) {
                url.searchParams.set('do', '1');
            }

            if (state.ecs && provider.supportsEcs) {
                url.searchParams.set('edns_client_subnet', state.ecs);
            }

            return { provider: provider, url: url };
        }

        async function highlight(rootElement) {
            if (window.domainDetectiveTools && typeof window.domainDetectiveTools.highlightCodeBlocks === 'function') {
                await window.domainDetectiveTools.highlightCodeBlocks(rootElement);
            }
        }

        async function copyText(text) {
            if (window.domainDetectiveTools && typeof window.domainDetectiveTools.copyText === 'function') {
                return window.domainDetectiveTools.copyText(text);
            }

            return false;
        }

        function updateCodeBlocks(state) {
            elements.csharpCode.textContent = buildCSharpSnippet(state);
            elements.powershellCode.textContent = buildPowerShellSnippet(state);
        }

        async function resolveDns(state) {
            if (!state.name) {
                elements.status.dataset.state = 'error';
                elements.status.textContent = 'Enter a DNS name before resolving.';
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                return;
            }

            writeStateToUrl(state);
            updateProviderNote(state, elements.note);
            elements.status.dataset.state = 'loading';
            elements.status.textContent = 'Resolving ' + state.name + ' ' + state.type + '...';
            elements.resolveButton.disabled = true;

            var request = buildRequest(state);
            elements.directLink.href = request.url.toString();
            elements.directLink.textContent = 'Open ' + request.provider.label;
            updateCodeBlocks(state);
            elements.jsonCode.textContent = '';
            await highlight(root);

            try {
                var response = await fetch(request.url.toString(), {
                    headers: request.provider.headers
                });

                if (!response.ok) {
                    throw new Error('Resolver returned HTTP ' + response.status + '.');
                }

                var payload = await response.json();
                elements.status.dataset.state = 'success';
                elements.status.textContent = 'Resolved via ' + request.provider.label + '.';

                renderSummary(state, payload, request.provider, elements.summary);
                renderSections(payload, elements.records);
                elements.jsonCode.textContent = JSON.stringify(payload, null, 2);
                await highlight(root);
            } catch (error) {
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                elements.status.dataset.state = 'error';
                elements.status.textContent = error instanceof Error ? error.message : 'Failed to resolve DNS.';
            } finally {
                elements.resolveButton.disabled = false;
            }
        }

        function handleSubmit(event) {
            event.preventDefault();
            void resolveDns(getState());
        }

        function handleProviderChange() {
            updateProviderNote(getState(), elements.note);
        }

        function handleRootClick(event) {
            var button = event.target && event.target.closest ? event.target.closest('.js-dns-copy-btn') : null;
            if (!button || !root.contains(button)) {
                return;
            }

            var targetSelector = button.getAttribute('data-copy-target');
            if (!targetSelector) {
                return;
            }

            var target = root.querySelector(targetSelector);
            if (!target) {
                return;
            }

            void copyText(target.textContent || '').then(function (copied) {
                setCopyButtonState(button, copied);
            });
        }

        elements.form.addEventListener('submit', handleSubmit);
        elements.providerInput.addEventListener('change', handleProviderChange);
        root.addEventListener('click', handleRootClick);

        readStateFromUrl();
        updateProviderNote(getState(), elements.note);
        void resolveDns(getState());

        controllers.set(root, {
            form: elements.form,
            providerInput: elements.providerInput,
            handleSubmit: handleSubmit,
            handleProviderChange: handleProviderChange,
            handleRootClick: handleRootClick
        });

        return true;
    }

    function disposeRawDnsQueryTool(root) {
        if (!root) {
            return false;
        }

        var controller = controllers.get(root);
        if (!controller) {
            return false;
        }

        controller.form.removeEventListener('submit', controller.handleSubmit);
        controller.providerInput.removeEventListener('change', controller.handleProviderChange);
        root.removeEventListener('click', controller.handleRootClick);
        controllers.delete(root);
        return true;
    }

    window.domainDetectiveTools = window.domainDetectiveTools || {};
    window.domainDetectiveTools.initRawDnsQueryTool = initRawDnsQueryTool;
    window.domainDetectiveTools.disposeRawDnsQueryTool = disposeRawDnsQueryTool;
})();
