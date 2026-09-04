async (page) => {
  const consoleErrors = [];
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', error => consoleErrors.push(error.message));

  await page.addInitScript(() => {
    const tools = Object.create(null);
    Object.defineProperty(window, '__domainDetectiveWebMcpTools', { value: tools, configurable: true });
    Object.defineProperty(document, 'modelContext', {
      configurable: true,
      value: {
        registerTool: async (tool, options) => {
          tools[tool.name] = tool;
          options?.signal?.addEventListener('abort', () => { delete tools[tool.name]; }, { once: true });
        }
      }
    });
  });
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForFunction(() => Boolean(window.__domainDetectiveWebMcpTools?.query_dns_records), null, { timeout: 60000 });

  const result = await page.evaluate(async () => {
    const tool = window.__domainDetectiveWebMcpTools.query_dns_records;
    const valid = await tool.execute({ name: 'example.com.', type: 'A' }, { signal: new AbortController().signal });
    await new Promise(resolve => setTimeout(resolve, 250));
    const visible = {
      name: document.querySelector('.js-dns-name')?.value || '',
      type: document.querySelector('.js-dns-type')?.value || '',
      provider: document.querySelector('.js-dns-provider')?.value || '',
      status: document.querySelector('.js-dns-status')?.textContent || '',
      records: document.querySelector('.js-dns-records')?.textContent || ''
    };
    const invalid = await tool.execute({ name: 'localhost', type: 'A' });
    await new Promise(resolve => setTimeout(resolve, 100));
    const invalidVisibleStatus = document.querySelector('.js-dns-status')?.textContent || '';
    const invalidVisibleRecords = document.querySelector('.js-dns-records')?.textContent || '';
    const unsupported = await tool.execute({ name: 'example.com', type: 'BOGUS' });
    const unsupportedVisibleRecords = document.querySelector('.js-dns-records')?.textContent || '';
    const cancelledSignal = new AbortController();
    cancelledSignal.abort();
    const cancelled = await tool.execute({ name: 'example.com', type: 'A' }, { signal: cancelledSignal.signal });
    const cancelledVisibleStatus = document.querySelector('.js-dns-status')?.textContent || '';
    const specialUse = [];
    for (const name of [
      'printer.local',
      'host.localhost',
      'service.home.arpa',
      'example.test',
      '10.in-addr.arpa',
      '0.10.in-addr.arpa',
      '1.0.0.10.in-addr.arpa',
      '8.e.f.ip6.arpa',
      'c.f.ip6.arpa'
    ]) {
      specialUse.push({ name, output: await tool.execute({ name, type: 'A' }) });
    }

    const originalFetch = window.fetch;
    let markFetchStarted;
    const fetchStarted = new Promise(resolve => { markFetchStarted = resolve; });
    window.fetch = (url, options) => {
      if (!String(url).startsWith('https://dns.google/resolve')) return originalFetch(url, options);
      return new Promise((_resolve, reject) => {
        markFetchStarted();
        options?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
      });
    };
    const pending = tool.execute({ name: 'openai.com', type: 'A' });
    await fetchStarted;
    const raceInvalid = await tool.execute({ name: 'printer.local', type: 'A' });
    const superseded = await pending;

    let markManualFetchStarted;
    const manualFetchStarted = new Promise(resolve => { markManualFetchStarted = resolve; });
    markFetchStarted = markManualFetchStarted;
    const manuallyCancelledPending = tool.execute({ name: 'openai.com', type: 'A' });
    await manualFetchStarted;
    document.querySelector('.js-dns-name').value = '';
    document.querySelector('.js-dns-query-form').requestSubmit();
    const manuallySuperseded = await manuallyCancelledPending;
    window.fetch = originalFetch;
    const raceVisible = {
      status: document.querySelector('.js-dns-status')?.textContent || '',
      records: document.querySelector('.js-dns-records')?.textContent || ''
    };

    let root = document.querySelector('.js-dns-query-form');
    let disposed = false;
    while (root && !disposed) {
      disposed = window.domainDetectiveTools.disposeRawDnsQueryTool(root);
      if (!disposed) root = root.parentElement;
    }
    await Promise.resolve();
    const removedAfterDispose = !window.__domainDetectiveWebMcpTools.query_dns_records;
    const initialized = Boolean(root && window.domainDetectiveTools.initRawDnsQueryTool(root));
    await Promise.resolve();
    const restoredAfterInit = Boolean(window.__domainDetectiveWebMcpTools.query_dns_records);
    return {
      registeredTools: Object.keys(window.__domainDetectiveWebMcpTools).sort(),
      schema: tool.inputSchema,
      annotations: tool.annotations,
      valid,
      validOutputCharacters: JSON.stringify(valid).length,
      visible,
      invalid,
      invalidVisibleStatus,
      invalidVisibleRecords,
      unsupported,
      unsupportedVisibleRecords,
      cancelled,
      cancelledVisibleStatus,
      specialUse,
      raceInvalid,
      superseded,
      raceVisible,
      manuallySuperseded,
      lifecycle: { disposed, removedAfterDispose, initialized, restoredAfterInit }
    };
  });

  return JSON.stringify({ ...result, consoleErrors });
}
