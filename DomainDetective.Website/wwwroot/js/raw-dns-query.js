(function () {
    'use strict';

    var controllers = new WeakMap();
    var webMcpToolName = 'query_dns_records';
    var activeWebMcpController = null;
    var webMcpRegistered = false;
    var webMcpRegistrationController = null;
    var allowedToolRecordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'CAA', 'SRV', 'PTR', 'SOA', 'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'TLSA', 'HTTPS', 'SVCB'];
    var nonPublicDnsSuffixes = [
        'localhost', 'localdomain', 'local', 'home.arpa', 'internal', 'intranet', 'lan', 'home', 'corp', 'private',
        'test', 'invalid', 'example', 'onion'
    ];

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
            supportsEcs: true,
            supportsDirectLink: true
        },
        cloudflare: {
            label: 'Cloudflare DNS JSON',
            endpoint: 'DnsEndpoint.Cloudflare',
            powershellProvider: 'Cloudflare',
            baseUrl: 'https://cloudflare-dns.com/dns-query',
            headers: { Accept: 'application/dns-json' },
            supportsEcs: false,
            supportsDirectLink: false
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

    function getEffectiveName(name) {
        return name ? name : 'example.com';
    }

    function normalizePublicDnsName(value) {
        var name = String(value == null ? '' : value).trim().toLowerCase().replace(/\.$/, '');
        if (name.length < 3 || name.length > 253 || name.indexOf('.') < 1 || /^[0-9.]+$/.test(name)) {
            return null;
        }
        var labels = name.split('.');
        if (labels.some(function (label) {
            return label.length < 1 || label.length > 63 || !/^_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
        })) {
            return null;
        }
        if (isNonPublicDnsName(name)) {
            return null;
        }
        return name;
    }

    function isNonPublicDnsName(name) {
        if (nonPublicDnsSuffixes.some(function (suffix) {
            return name === suffix || name.endsWith('.' + suffix);
        })) {
            return true;
        }

        if (name.endsWith('.in-addr.arpa')) {
            var reverseV4 = name.slice(0, -'.in-addr.arpa'.length).split('.');
            if (reverseV4.length >= 1 && reverseV4.length <= 4 && reverseV4.every(function (part) { return /^\d{1,3}$/.test(part) && Number(part) <= 255; })) {
                var octets = reverseV4.reverse().map(Number);
                return octets[0] === 0 || octets[0] === 10 || octets[0] === 127 || octets[0] >= 224 ||
                    (octets.length >= 2 && octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
                    (octets.length >= 2 && octets[0] === 169 && octets[1] === 254) ||
                    (octets.length >= 2 && octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
                    (octets.length >= 2 && octets[0] === 192 && octets[1] === 168) ||
                    (octets.length >= 2 && octets[0] === 198 && (octets[1] === 18 || octets[1] === 19));
            }
        }

        if (name.endsWith('.ip6.arpa')) {
            var reverseV6 = name.slice(0, -'.ip6.arpa'.length).split('.');
            if (reverseV6.length >= 1 && reverseV6.length <= 32 && reverseV6.every(function (part) { return /^[0-9a-f]$/.test(part); })) {
                var addressPrefix = reverseV6.reverse().join('');
                return /^(?:fc|fd)/.test(addressPrefix) ||
                    /^fe[89ab]/.test(addressPrefix) ||
                    (addressPrefix.length === 32 && /^0{31}[01]$/.test(addressPrefix));
            }
        }

        return false;
    }

    function trimToolText(value, maximum) {
        var text = String(value == null ? '' : value).replace(/\s+/g, ' ').trim();
        return text.length <= maximum ? text : text.slice(0, maximum - 1) + '…';
    }

    function buildWebMcpResult(state, payload, provider) {
        var answers = (payload.Answer || []).map(function (row) {
            return {
                name: trimToolText(row.name || row.Name || '', 120),
                type: trimToolText(getTypeLabel(row.type || row.Type || ''), 12),
                ttl: Number(row.TTL == null ? (row.ttl == null ? 0 : row.ttl) : row.TTL),
                data: trimToolText(row.data || row.Data || '', 240)
            };
        });
        var result = {
            success: true,
            name: state.name,
            type: state.type,
            provider: provider.label,
            status: rcodeMap[payload.Status] || String(payload.Status == null ? 'UNKNOWN' : payload.Status),
            totalAnswers: answers.length,
            answers: answers.slice(0, 10),
            outputTruncated: answers.length > 10
        };
        while (result.answers.length > 0 && JSON.stringify(result).length > 1500) {
            result.answers.pop();
            result.outputTruncated = true;
        }
        return result;
    }

    async function registerWebMcpTool(controller) {
        activeWebMcpController = controller;
        if (webMcpRegistered || !document.modelContext || typeof document.modelContext.registerTool !== 'function') {
            return;
        }
        try {
            webMcpRegistrationController = new AbortController();
            await document.modelContext.registerTool({
                name: webMcpToolName,
                description: 'Resolve one bounded public DNS record query and leave the result visible in the DomainDetective playground.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        name: { type: 'string', minLength: 3, maxLength: 253, description: 'Public DNS name, for example example.com.' },
                        type: { type: 'string', enum: allowedToolRecordTypes, default: 'A' }
                    },
                    required: ['name'],
                    additionalProperties: false
                },
                annotations: {
                    readOnlyHint: true,
                    destructiveHint: false,
                    idempotentHint: true,
                    openWorldHint: true,
                    untrustedContentHint: true
                },
                execute: async function (input, context) {
                    if (!activeWebMcpController) {
                        throw new Error('The Raw DNS Query playground is no longer available on this page.');
                    }
                    return activeWebMcpController.resolveFromWebMcp(input || {}, context && context.signal);
                }
            }, { signal: webMcpRegistrationController.signal });
            webMcpRegistered = true;
            document.body.setAttribute('data-webmcp-status', 'registered');
        } catch (_) {
            webMcpRegistrationController && webMcpRegistrationController.abort();
            webMcpRegistrationController = null;
            document.body.setAttribute('data-webmcp-status', 'failed');
        }
    }

    async function unregisterWebMcpTool(controller) {
        if (activeWebMcpController !== controller) {
            return;
        }
        activeWebMcpController = null;
        webMcpRegistrationController && webMcpRegistrationController.abort();
        webMcpRegistrationController = null;
        webMcpRegistered = false;
        document.body.setAttribute('data-webmcp-status', 'disposed');
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
            buildSummaryCard('Question', state.type, getEffectiveName(state.name))
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
        var resolveArguments = [];
        var dnsName = getEffectiveName(state.name);

        if (requestDnsSec) {
            resolveArguments.push('requestDnsSec: true');
            resolveArguments.push('validateDnsSec: ' + String(validateDnsSec).toLowerCase());
        }

        var resolveInvocation = 'DnsResponse response = await client.Resolve("' + dnsName + '", DnsRecordType.' + state.type;
        if (resolveArguments.length > 0) {
            resolveInvocation += ',\n    ' + resolveArguments.join(',\n    ');
        }

        resolveInvocation += ');';

        if (state.ecs && provider.supportsEcs) {
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
                resolveInvocation,
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
            resolveInvocation,
            '',
            'foreach (var answer in response.Answers) {',
            '    Console.WriteLine($"{answer.Type}: {answer.Data}");',
            '}'
        ].join('\n');
    }

    function buildPowerShellSnippet(state) {
        var provider = providers[state.providerId] || providers.google;
        var dnsName = getEffectiveName(state.name);
        var argumentsList = [
            "-Name '" + dnsName + "'",
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

        return lines.join('\n');
    }

    function updateCodeNotes(state, elements) {
        var provider = providers[state.providerId] || providers.google;

        if (state.ecs && provider.supportsEcs) {
            elements.csharpNote.hidden = false;
            elements.csharpNote.textContent = 'The .NET example switches to ClientXBuilder because EDNS client subnet is configured through EdnsOptions.';
            elements.powershellNote.hidden = false;
            elements.powershellNote.textContent = 'Resolve-Dns does not currently expose EDNS client subnet directly. The PowerShell snippet shows the closest available query, while the C# snippet shows the full ECS-aware setup.';
            return;
        }

        if (state.ecs && !provider.supportsEcs) {
            elements.csharpNote.hidden = false;
            elements.csharpNote.textContent = provider.label + ' ignores EDNS client subnet in the browser preview, so the generated snippets stay aligned with that resolver behavior.';
            elements.powershellNote.hidden = true;
            elements.powershellNote.textContent = '';
            return;
        }

        elements.csharpNote.hidden = true;
        elements.csharpNote.textContent = '';
        elements.powershellNote.hidden = true;
        elements.powershellNote.textContent = '';
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

    function syncDnssecControls(elements) {
        var dnssecEnabled = elements.showDnssecInput.checked;

        if (!dnssecEnabled) {
            elements.disableValidationInput.checked = false;
        }

        elements.disableValidationInput.disabled = !dnssecEnabled;
        elements.disableValidationInput.setAttribute('aria-disabled', dnssecEnabled ? 'false' : 'true');
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
            csharpNote: root.querySelector('.js-dns-csharp-note'),
            powershellCode: root.querySelector('.js-dns-powershell-code'),
            powershellNote: root.querySelector('.js-dns-powershell-note'),
            jsonCode: root.querySelector('.js-dns-json-code'),
            resolveButton: root.querySelector('.js-dns-query-form button[type="submit"]')
        };

        if (!elements.form || !elements.nameInput || !elements.typeInput || !elements.providerInput || !elements.ecsInput || !elements.disableValidationInput || !elements.showDnssecInput || !elements.directLink || !elements.note || !elements.status || !elements.summary || !elements.records || !elements.csharpCode || !elements.csharpNote || !elements.powershellCode || !elements.powershellNote || !elements.jsonCode || !elements.resolveButton) {
            return false;
        }

        var activeAbortController = null;
        var nextRequestSequence = 0;
        var latestRequestSequence = 0;

        function isValidEcsSubnet(value) {
            if (!value) {
                return true;
            }

            var match = /^(\d{1,3})(?:\.(\d{1,3})){3}\/(\d{1,2})$/.exec(value);
            if (!match) {
                return false;
            }

            var parts = value.split('/');
            var octets = parts[0].split('.');
            var prefixLength = Number(parts[1]);
            if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) {
                return false;
            }

            return octets.every(function (part) {
                var octet = Number(part);
                return Number.isInteger(octet) && octet >= 0 && octet <= 255;
            });
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
            syncDnssecControls(elements);
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
            var effectiveName = getEffectiveName(state.name);

            url.searchParams.set('name', effectiveName);
            url.searchParams.set('type', state.type);

            if (state.showDnssec && state.disableValidation) {
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

        function updatePreviewArtifacts(state) {
            var request = buildRequest(state);
            if (request.provider.supportsDirectLink) {
                elements.directLink.href = request.url.toString();
                elements.directLink.target = '_blank';
                elements.directLink.rel = 'noopener';
                elements.directLink.removeAttribute('aria-disabled');
                elements.directLink.removeAttribute('tabindex');
                elements.directLink.classList.remove('is-disabled');
                elements.directLink.textContent = 'Open ' + request.provider.label;
                elements.directLink.title = '';
            } else {
                elements.directLink.removeAttribute('href');
                elements.directLink.removeAttribute('target');
                elements.directLink.removeAttribute('rel');
                elements.directLink.setAttribute('aria-disabled', 'true');
                elements.directLink.setAttribute('tabindex', '-1');
                elements.directLink.classList.add('is-disabled');
                elements.directLink.textContent = 'Direct JSON link unavailable';
                elements.directLink.title = 'Cloudflare preview requires an Accept header, so use the in-page resolver preview instead.';
            }

            updateProviderNote(state, elements.note);
            updateCodeBlocks(state);
            return request;
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
            updateCodeNotes(state, elements);
        }

        async function refreshPreviewState() {
            var state = getState();
            updatePreviewArtifacts(state);
            await highlight(root);
        }

        function cancelActiveRequest() {
            if (!activeAbortController) {
                return;
            }

            activeAbortController.abort();
            activeAbortController = null;
        }

        function invalidateActiveRequest() {
            latestRequestSequence = ++nextRequestSequence;
            cancelActiveRequest();
            elements.resolveButton.disabled = false;
        }

        function supersededResult(state) {
            return {
                success: false,
                name: state.name,
                type: state.type,
                message: 'DNS query was superseded by a newer request.'
            };
        }

        async function resolveDns(state, externalSignal) {
            if (!state.name) {
                invalidateActiveRequest();
                elements.status.dataset.state = 'error';
                elements.status.textContent = 'Enter a DNS name before resolving.';
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                return { success: false, message: 'Enter a DNS name before resolving.' };
            }

            if (!isValidEcsSubnet(state.ecs)) {
                invalidateActiveRequest();
                elements.status.dataset.state = 'error';
                elements.status.textContent = 'Use EDNS client subnet in IPv4 CIDR form, for example 203.0.113.0/24.';
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                return { success: false, message: 'Use EDNS client subnet in IPv4 CIDR form, for example 203.0.113.0/24.' };
            }

            if (externalSignal && externalSignal.aborted) {
                invalidateActiveRequest();
                elements.status.dataset.state = 'error';
                elements.status.textContent = 'DNS query was cancelled.';
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                return { success: false, name: state.name, type: state.type, message: elements.status.textContent };
            }

            writeStateToUrl(state);
            elements.status.dataset.state = 'loading';
            elements.status.textContent = 'Resolving ' + state.name + ' ' + state.type + '...';
            elements.resolveButton.disabled = true;

            var request = updatePreviewArtifacts(state);
            var requestSequence = ++nextRequestSequence;
            latestRequestSequence = requestSequence;
            cancelActiveRequest();
            var requestAbortController = new AbortController();
            var externallyAborted = false;
            var handleExternalAbort = function () {
                externallyAborted = true;
                requestAbortController.abort();
            };
            activeAbortController = requestAbortController;
            if (externalSignal) {
                externalSignal.addEventListener('abort', handleExternalAbort, { once: true });
            }
            elements.jsonCode.textContent = '';
            await highlight(root);

            try {
                var response = await fetch(request.url.toString(), {
                    headers: request.provider.headers,
                    signal: requestAbortController.signal
                });

                if (requestSequence !== latestRequestSequence) {
                    return supersededResult(state);
                }

                if (!response.ok) {
                    throw new Error('Resolver returned HTTP ' + response.status + '.');
                }

                var payload = await response.json();
                if (requestSequence !== latestRequestSequence) {
                    return supersededResult(state);
                }

                elements.status.dataset.state = 'success';
                elements.status.textContent = 'Resolved via ' + request.provider.label + '.';

                renderSummary(state, payload, request.provider, elements.summary);
                renderSections(payload, elements.records);
                elements.jsonCode.textContent = JSON.stringify(payload, null, 2);
                await highlight(root);
                return buildWebMcpResult(state, payload, request.provider);
            } catch (error) {
                if (requestSequence !== latestRequestSequence) {
                    return supersededResult(state);
                }

                if (error && error.name === 'AbortError' && !externallyAborted) {
                    return {
                        success: false,
                        name: state.name,
                        type: state.type,
                        message: 'DNS query was cancelled.'
                    };
                }

                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                elements.status.dataset.state = 'error';
                elements.status.textContent = externallyAborted
                    ? 'DNS query was cancelled.'
                    : (error instanceof Error ? error.message : 'Failed to resolve DNS.');
                return {
                    success: false,
                    name: state.name,
                    type: state.type,
                    message: trimToolText(elements.status.textContent, 300)
                };
            } finally {
                if (externalSignal) {
                    externalSignal.removeEventListener('abort', handleExternalAbort);
                }
                if (requestSequence === latestRequestSequence) {
                    elements.resolveButton.disabled = false;
                    activeAbortController = null;
                }
            }
        }

        function handleSubmit(event) {
            event.preventDefault();
            void resolveDns(getState());
        }

        async function resolveFromWebMcp(input, signal) {
            var normalizedName = normalizePublicDnsName(input.name);
            var requestedType = String(input.type || 'A').toUpperCase();
            if (!normalizedName) {
                invalidateActiveRequest();
                elements.status.dataset.state = 'error';
                elements.status.textContent = 'Enter a normalized public DNS name such as example.com.';
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                return { success: false, message: elements.status.textContent };
            }
            if (allowedToolRecordTypes.indexOf(requestedType) < 0) {
                invalidateActiveRequest();
                elements.status.dataset.state = 'error';
                elements.status.textContent = 'Choose one of the record types exposed by the Raw DNS Query playground.';
                elements.summary.innerHTML = '';
                elements.records.innerHTML = '';
                elements.jsonCode.textContent = '';
                return { success: false, name: normalizedName, message: elements.status.textContent };
            }

            elements.nameInput.value = normalizedName;
            elements.typeInput.value = requestedType;
            elements.providerInput.value = 'google';
            elements.ecsInput.value = '';
            elements.disableValidationInput.checked = false;
            elements.showDnssecInput.checked = false;
            syncDnssecControls(elements);
            return resolveDns(getState(), signal);
        }

        function handleProviderChange() {
            void refreshPreviewState();
        }

        function handleStateInput() {
            syncDnssecControls(elements);
            void refreshPreviewState();
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
        elements.nameInput.addEventListener('input', handleStateInput);
        elements.typeInput.addEventListener('change', handleStateInput);
        elements.ecsInput.addEventListener('input', handleStateInput);
        elements.disableValidationInput.addEventListener('change', handleStateInput);
        elements.showDnssecInput.addEventListener('change', handleStateInput);
        root.addEventListener('click', handleRootClick);

        readStateFromUrl();
        void refreshPreviewState();

        var initialState = getState();
        if (initialState.name) {
            void resolveDns(initialState);
        }

        var controller = {
            form: elements.form,
            providerInput: elements.providerInput,
            nameInput: elements.nameInput,
            typeInput: elements.typeInput,
            ecsInput: elements.ecsInput,
            disableValidationInput: elements.disableValidationInput,
            showDnssecInput: elements.showDnssecInput,
            handleSubmit: handleSubmit,
            handleProviderChange: handleProviderChange,
            handleStateInput: handleStateInput,
            handleRootClick: handleRootClick,
            cancelActiveRequest: invalidateActiveRequest,
            resolveFromWebMcp: resolveFromWebMcp
        };
        controllers.set(root, controller);
        void registerWebMcpTool(controller);

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
        controller.nameInput.removeEventListener('input', controller.handleStateInput);
        controller.typeInput.removeEventListener('change', controller.handleStateInput);
        controller.ecsInput.removeEventListener('input', controller.handleStateInput);
        controller.disableValidationInput.removeEventListener('change', controller.handleStateInput);
        controller.showDnssecInput.removeEventListener('change', controller.handleStateInput);
        root.removeEventListener('click', controller.handleRootClick);
        controller.cancelActiveRequest();
        void unregisterWebMcpTool(controller);
        controllers.delete(root);
        return true;
    }

    window.domainDetectiveTools = window.domainDetectiveTools || {};
    window.domainDetectiveTools.initRawDnsQueryTool = initRawDnsQueryTool;
    window.domainDetectiveTools.disposeRawDnsQueryTool = disposeRawDnsQueryTool;
})();
