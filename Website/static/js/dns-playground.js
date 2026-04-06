(function () {
  var form = document.getElementById("dns-playground-form");
  if (!form) {
    return;
  }

  var root = document.querySelector(".dns-playground");
  var nameInput = document.getElementById("dns-name");
  var typeInput = document.getElementById("dns-type");
  var providerInput = document.getElementById("dns-provider");
  var ecsInput = document.getElementById("dns-ecs");
  var disableValidationInput = document.getElementById("dns-disable-validation");
  var showDnssecInput = document.getElementById("dns-show-dnssec");
  var directLink = document.getElementById("dns-direct-link");
  var note = document.getElementById("dns-playground-note");
  var status = document.getElementById("dns-playground-status");
  var summary = document.getElementById("dns-playground-summary");
  var records = document.getElementById("dns-playground-records");
  var csharpCode = document.getElementById("dns-csharp-code");
  var powershellCode = document.getElementById("dns-powershell-code");
  var jsonCode = document.getElementById("dns-json-code");

  var recordTypeMap = {
    0: "Reserved",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    257: "CAA"
  };

  var rcodeMap = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED"
  };

  var providers = {
    google: {
      label: "Google Public DNS",
      endpoint: "DnsEndpoint.Google",
      powershellProvider: "Google",
      baseUrl: "https://dns.google/resolve",
      headers: {},
      supportsEcs: true
    },
    cloudflare: {
      label: "Cloudflare DNS JSON",
      endpoint: "DnsEndpoint.Cloudflare",
      powershellProvider: "Cloudflare",
      baseUrl: "https://cloudflare-dns.com/dns-query",
      headers: { Accept: "application/dns-json" },
      supportsEcs: false
    }
  };

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function getTypeLabel(type) {
    if (typeof type === "number" && recordTypeMap[type]) {
      return recordTypeMap[type];
    }

    return String(type ?? "");
  }

  function readStateFromUrl() {
    const url = new URL(window.location.href);
    const providerId = url.searchParams.get("provider");
    const type = url.searchParams.get("type");

    if (url.searchParams.has("name")) {
      nameInput.value = url.searchParams.get("name") || "";
    }

    if (type && Array.from(typeInput.options).some(function (option) { return option.value === type; })) {
      typeInput.value = type;
    }

    if (providerId && providers[providerId]) {
      providerInput.value = providerId;
    }

    if (url.searchParams.has("ecs")) {
      ecsInput.value = url.searchParams.get("ecs") || "";
    }

    disableValidationInput.checked = url.searchParams.get("disableValidation") === "1";
    showDnssecInput.checked = url.searchParams.get("showDnssec") === "1";
  }

  function getState() {
    return {
      name: nameInput.value.trim(),
      type: typeInput.value,
      providerId: providerInput.value,
      ecs: ecsInput.value.trim(),
      disableValidation: disableValidationInput.checked,
      showDnssec: showDnssecInput.checked
    };
  }

  function writeStateToUrl(state) {
    const url = new URL(window.location.href);

    if (state.name) {
      url.searchParams.set("name", state.name);
    } else {
      url.searchParams.delete("name");
    }

    url.searchParams.set("type", state.type);
    url.searchParams.set("provider", state.providerId);

    if (state.ecs) {
      url.searchParams.set("ecs", state.ecs);
    } else {
      url.searchParams.delete("ecs");
    }

    if (state.disableValidation) {
      url.searchParams.set("disableValidation", "1");
    } else {
      url.searchParams.delete("disableValidation");
    }

    if (state.showDnssec) {
      url.searchParams.set("showDnssec", "1");
    } else {
      url.searchParams.delete("showDnssec");
    }

    window.history.replaceState({}, "", url.toString());
  }

  function buildRequest(state) {
    const provider = providers[state.providerId] || providers.google;
    const url = new URL(provider.baseUrl);

    url.searchParams.set("name", state.name);
    url.searchParams.set("type", state.type);

    if (state.disableValidation) {
      url.searchParams.set("cd", "1");
    }

    if (state.showDnssec) {
      url.searchParams.set("do", "1");
    }

    if (state.ecs && provider.supportsEcs) {
      url.searchParams.set("edns_client_subnet", state.ecs);
    }

    return { provider, url };
  }

  function updateProviderNote(state) {
    const provider = providers[state.providerId] || providers.google;
    if (provider.supportsEcs) {
      note.textContent = "Leave EDNS client subnet empty unless you want to simulate answers for a specific client network. Google preview supports EDNS client subnet and DNSSEC detail flags in the browser. The generated snippets show the closest DnsClientX equivalent.";
    } else {
      note.textContent = "Leave EDNS client subnet empty unless you want to simulate answers for a specific client network. Cloudflare preview ignores EDNS client subnet. The generated DnsClientX examples still show the selected record type and DNSSEC intent.";
    }
  }

  function summaryCard(label, value, meta) {
    return '<article class="dns-playground__summary-card">' +
      '<span class="dns-playground__summary-label">' + escapeHtml(label) + "</span>" +
      '<span class="dns-playground__summary-value">' + escapeHtml(value) + "</span>" +
      '<span class="dns-playground__summary-meta">' + escapeHtml(meta) + "</span>" +
      "</article>";
  }

  function renderSummary(state, payload, provider) {
    const answers = payload.Answer || [];
    const authority = payload.Authority || [];
    const additional = payload.Additional || [];
    const flags = [
      payload.AD ? "AD" : null,
      payload.CD ? "CD" : null,
      payload.RA ? "RA" : null,
      payload.RD ? "RD" : null
    ].filter(Boolean);

    summary.innerHTML = [
      summaryCard("Status", rcodeMap[payload.Status] || String(payload.Status ?? "n/a"), provider.label),
      summaryCard("Answers", String(answers.length), authority.length + " authority"),
      summaryCard("Additional", String(additional.length), payload.Comment || "No comment"),
      summaryCard("Question", state.type, state.name)
    ].join("");

    if (flags.length > 0) {
      summary.insertAdjacentHTML(
        "beforeend",
        '<div class="dns-playground__summary-card"><span class="dns-playground__summary-label">Flags</span><span class="dns-playground__summary-value">DNS</span><div class="dns-playground__flags">' +
          flags.map(function (flag) { return '<span class="dns-playground__flag">' + escapeHtml(flag) + "</span>"; }).join("") +
          "</div></div>"
      );
    }
  }

  function renderRecordTables(payload) {
    const sections = [
      { title: "Question", rows: payload.Question || [], empty: "No question section returned." },
      { title: "Answer", rows: payload.Answer || [], empty: "No answer records returned." },
      { title: "Authority", rows: payload.Authority || [], empty: "No authority records returned." },
      { title: "Additional", rows: payload.Additional || [], empty: "No additional records returned." }
    ];

    records.innerHTML = sections.map(function (section) {
      if (!section.rows.length) {
        return '<section class="dns-playground__table-wrap"><h3 class="dns-playground__table-title">' + escapeHtml(section.title) + '</h3><div class="dns-playground__empty">' + escapeHtml(section.empty) + "</div></section>";
      }

      const isQuestionSection = section.title === "Question";
      const headerHtml = isQuestionSection
        ? "<thead><tr><th>Name</th><th>Type</th></tr></thead>"
        : "<thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Data</th></tr></thead>";

      const rowsHtml = section.rows.map(function (row) {
        if (isQuestionSection) {
          return "<tr>" +
            "<td><code>" + escapeHtml(row.name || row.Name || "") + "</code></td>" +
            "<td>" + escapeHtml(getTypeLabel(row.type || row.Type || "")) + "</td>" +
            "</tr>";
        }

        return "<tr>" +
          "<td><code>" + escapeHtml(row.name || row.Name || "") + "</code></td>" +
          "<td>" + escapeHtml(getTypeLabel(row.type || row.Type || "")) + "</td>" +
          "<td>" + escapeHtml(row.TTL ?? row.ttl ?? "") + "</td>" +
          "<td><code>" + escapeHtml(row.data || row.Data || "") + "</code></td>" +
          "</tr>";
      }).join("");

      return '<section class="dns-playground__table-wrap">' +
        '<h3 class="dns-playground__table-title">' + escapeHtml(section.title) + "</h3>" +
        '<div class="dns-playground__table-scroll"><table class="dns-playground__table">' +
        headerHtml +
        "<tbody>" + rowsHtml + "</tbody></table></div></section>";
    }).join("");
  }

  function buildCsharpSnippet(state) {
    const provider = providers[state.providerId] || providers.google;
    const requestDnsSec = state.showDnssec;
    const validateDnsSec = state.showDnssec && !state.disableValidation;

    if (state.ecs) {
      return [
        "using DnsClientX;",
        "",
        "using var client = new ClientXBuilder()",
        "    .WithEndpoint(" + provider.endpoint + ")",
        "    .WithEdnsOptions(new EdnsOptions {",
        "        EnableEdns = true,",
        '        Subnet = new EdnsClientSubnetOption("' + state.ecs + '")',
        "    })",
        "    .Build();",
        "",
        'DnsResponse response = await client.Resolve("' + state.name + '", DnsRecordType.' + state.type + ",",
        "    requestDnsSec: " + String(requestDnsSec).toLowerCase() + ",",
        "    validateDnsSec: " + String(validateDnsSec).toLowerCase() + ");",
        "",
        "foreach (var answer in response.Answers) {",
        '    Console.WriteLine($"{answer.Type}: {answer.Data}");',
        "}"
      ].join("\n");
    }

    return [
      "using DnsClientX;",
      "",
      "using var client = new ClientX(" + provider.endpoint + ");",
      'DnsResponse response = await client.Resolve("' + state.name + '", DnsRecordType.' + state.type + ",",
      "    requestDnsSec: " + String(requestDnsSec).toLowerCase() + ",",
      "    validateDnsSec: " + String(validateDnsSec).toLowerCase() + ");",
      "",
      "foreach (var answer in response.Answers) {",
      '    Console.WriteLine($"{answer.Type}: {answer.Data}");',
      "}"
    ].join("\n");
  }

  function buildPowerShellSnippet(state) {
    const provider = providers[state.providerId] || providers.google;
    const argumentsList = [
      "-Name '" + state.name + "'",
      "-Type " + state.type,
      "-DnsProvider " + provider.powershellProvider
    ];

    if (state.showDnssec) {
      argumentsList.push("-RequestDnsSec");
    }

    if (state.showDnssec && !state.disableValidation) {
      argumentsList.push("-ValidateDnsSec");
    }

    const lines = [
      "$response = Resolve-Dns " + argumentsList.join(" "),
      "$response | Format-Table"
    ];

    if (state.ecs) {
      lines.unshift("# EDNS client subnet is currently shown in the browser preview and the C# builder example.");
    }

    return lines.join("\n");
  }

  function highlightBlocks() {
    if (window.Prism && typeof window.Prism.highlightAllUnder === "function" && root) {
      window.Prism.highlightAllUnder(root);
    }
  }

  async function resolveDns(state) {
    if (!state.name) {
      status.dataset.state = "error";
      status.textContent = "Enter a DNS name before resolving.";
      return;
    }

    writeStateToUrl(state);
    updateProviderNote(state);
    status.dataset.state = "loading";
    status.textContent = "Resolving " + state.name + " " + state.type + "...";

    const request = buildRequest(state);
    directLink.href = request.url.toString();
    directLink.textContent = "Open " + request.provider.label + " JSON";

    csharpCode.textContent = buildCsharpSnippet(state);
    powershellCode.textContent = buildPowerShellSnippet(state);
    jsonCode.textContent = "";
    highlightBlocks();

    try {
      const response = await fetch(request.url.toString(), {
        headers: request.provider.headers
      });

      if (!response.ok) {
        throw new Error("Resolver returned HTTP " + response.status + ".");
      }

      const payload = await response.json();
      status.dataset.state = "success";
      status.textContent = "Resolved via " + request.provider.label + ".";

      renderSummary(state, payload, request.provider);
      renderRecordTables(payload);
      jsonCode.textContent = JSON.stringify(payload, null, 2);
      highlightBlocks();
    } catch (error) {
      summary.innerHTML = "";
      records.innerHTML = "";
      jsonCode.textContent = "";
      status.dataset.state = "error";
      status.textContent = error instanceof Error ? error.message : "Failed to resolve DNS.";
    }
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    resolveDns(getState());
  });

  providerInput.addEventListener("change", function () {
    updateProviderNote(getState());
  });

  readStateFromUrl();
  updateProviderNote(getState());
  resolveDns(getState());
})();
