import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

// Run the shipped browser scripts with DNS/HTTP responses supplied at the network boundary.
function load(fetch, elements = {}) {
    const listeners = [];
    const document = {
        readyState: 'loading',
        addEventListener: (event, callback) => { if (event === 'DOMContentLoaded') listeners.push(callback); },
        querySelectorAll: () => [],
        querySelector: selector => elements[selector] || null
    };
    const context = vm.createContext({ document, fetch, URLSearchParams, performance, AbortController,
        setTimeout, clearTimeout });
    context.window = context;
    for (const name of ['quickscan.js', 'dnsclientx.js', 'tools.js']) {
        const path = new URL('../static/js/' + name, import.meta.url);
        vm.runInContext(readFileSync(path, 'utf8'), context, { filename: name });
    }
    context.start = () => listeners.forEach(callback => callback());
    return context;
}

const response = data => ({ ok: true, json: async () => data });
function scanWith(records) {
    const context = load(async url => {
        const query = new URL(url).searchParams;
        const type = query.get('type');
        const name = query.get('name');
        const data = records(name, type);
        return response({ Status: 0, Answer: data || [] });
    });
    return context.DomainDetectiveQuickScan.scan('example.com');
}

test('DNS failures and truncated or malformed answers never become absence or success verdicts', async () => {
    for (const payload of [{ Status: 2 }, { Status: 5 }, { Status: 0, TC: true }, {}]) {
        const context = load(async () => response(payload));
        const report = await context.DomainDetectiveQuickScan.scan('example.com');
        assert.ok(report.results.every(r => r.status === 'info' && r.value === 'Lookup failed'));
    }
});

test('a failed resolver falls back, while an explicitly selected provider remains selected', async () => {
    const requested = [];
    const context = load(async url => {
        requested.push(new URL(url).host);
        return response({ Status: new URL(url).host === 'dns.google' ? 0 : 2 });
    });
    assert.equal((await context.DomainDetectiveQuickScan.query('example.com', 'A')).Status, 0);
    assert.deepEqual(requested, ['cloudflare-dns.com', 'dns.google']);
    requested.length = 0;
    await assert.rejects(context.DomainDetectiveQuickScan.query('example.com', 'A', { provider: 'cloudflare' }));
    assert.deepEqual(requested, ['cloudflare-dns.com']);
});

test('authoritative negative responses remain distinct from resolver failures', async () => {
    const context = load(async () => response({ Status: 3 }));
    assert.equal((await context.DomainDetectiveQuickScan.query('absent.example.com', 'TXT')).Status, 3);
});

test('SPF hostname labels are not mechanisms and redirect cannot override an all mechanism', async () => {
    for (const [policy, expected] of [
        ['v=spf1 include:_spf.all-inkl.com -all', 'Enforced (-all)'],
        ['v=spf1 include:all.example.com ~all', 'Soft fail (~all)'],
        ['v=spf1 include:mx.a.example.com ?all redirect=example.net', 'Permissive (?all)'],
        ['v=spf1 redirect=example.net', 'Redirected']
    ]) {
        const report = await scanWith((name, type) => name === 'example.com' && type === 'TXT'
            ? [{ type: 16, data: '"' + policy + '"' }] : []);
        const spf = report.results.find(r => r.id === 'spf');
        assert.equal(spf.value, expected);
        if (policy.includes('include:')) assert.equal(spf.detail, '1 of 10 direct lookups');
    }
});

test('multiple DMARC policy records cannot receive an enforcement pass', async () => {
    const report = await scanWith((name, type) => name === '_dmarc.example.com' && type === 'TXT'
        ? ['reject', 'none'].map(p => ({ type: 16, data: '"v=DMARC1; p=' + p + '"' })) : []);
    const dmarc = report.results.find(r => r.id === 'dmarc');
    assert.equal(dmarc.status, 'fail');
    assert.equal(dmarc.value, '2 records');
});

test('CAA preview reports exact-name evidence without claiming certificate authorization', async () => {
    for (const records of [[], [{ type: 257, data: '0 issuewild ";"' }], [{ type: 257, data: '0 issue "ca.example"' }]]) {
        const report = await scanWith((name, type) => type === 'CAA' ? records : []);
        assert.equal(report.results.find(r => r.id === 'caa').status, 'info');
    }
});

test('an unset AD flag does not establish an unsigned zone', async () => {
    const report = await scanWith(() => []);
    assert.equal(report.results.find(r => r.id === 'dnssec').status, 'info');
    assert.equal(report.results.find(r => r.id === 'mx').status, 'info');
    assert.equal(report.results.find(r => r.id === 'dmarc').status, 'info');
});

test('the landing console never displays resolver failure as NOERROR for either provider', async () => {
    for (const provider of ['cloudflare', 'google']) {
        const answers = {};
        const status = {};
        const field = value => ({ value, addEventListener() {}, setCustomValidity() {} });
        const form = { elements: { name: field('example.com'), type: field('A'), provider: field(provider) }, addEventListener() {} };
        const elements = { '[data-dx-form]': form, '[data-dx-answers]': answers, '[data-dx-status]': status, '[data-dx-code]': {} };
        const root = { querySelector: selector => elements[selector], querySelectorAll: () => [], setAttribute() {}, removeAttribute() {} };
        const context = load(async () => response({ Status: 2 }), { '[data-dx-console]': root });
        context.requestIdleCallback = callback => callback();
        context.start();
        await new Promise(setImmediate);
        assert.equal(status.textContent, 'Lookup failed');
        assert.doesNotMatch(answers.innerHTML, /NOERROR/);
    }
});

test('legacy hub domain links reach the static overview without loading Blazor', () => {
    const form = { querySelector: () => ({ value: '', addEventListener() {} }) };
    const context = load(async () => response({ Status: 0 }), { '[data-dd-hub-search]': form });
    let destination;
    context.location = { search: '?domain=www.example.com', replace: url => { destination = url; } };
    context.start();
    assert.equal(destination, '/tools/domain-overview/?q=www.example.com');
});
