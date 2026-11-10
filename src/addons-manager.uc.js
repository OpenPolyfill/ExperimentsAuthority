/* Native about:addons page for the Experiments Authority trust policy. */
(async () => {
  if (location.href !== "about:addons") return;

  await Promise.all([
    import("chrome://global/content/elements/moz-box-group.mjs"),
    import("chrome://global/content/elements/moz-box-item.mjs"),
    import("chrome://global/content/elements/moz-card.mjs"),
    import("chrome://global/content/elements/moz-fieldset.mjs"),
    import("chrome://global/content/elements/moz-button-group.mjs"),
    import("chrome://global/content/elements/moz-input-text.mjs"),
    import("chrome://global/content/elements/moz-input-search.mjs"),
    import("chrome://global/content/elements/moz-textarea.mjs"),
    import("chrome://global/content/elements/moz-toggle.mjs"),
    import("chrome://global/content/elements/moz-message-bar.mjs"),
  ]);

  const DB_NAME = "experiments-authority";
  const POLICY_CHANGED_TOPIC = "experiments-authority:policy-changed";
  const { IndexedDB } = ChromeUtils.importESModule(
    "resource://gre/modules/IndexedDB.sys.mjs"
  );
  const { AddonManager } = ChromeUtils.importESModule(
    "resource://gre/modules/AddonManager.sys.mjs"
  );
  const { ExtensionData } = ChromeUtils.importESModule(
    "resource://gre/modules/Extension.sys.mjs"
  );
  const VIEW = "experiments-authority";
  const VIEW_ID = `addons://${VIEW}/`;
  const TITLE = "Experiments";
  const controller = window.gViewController;
  const categories = document.querySelector("categories-box");
  if (!controller || !categories) return;

  window.__eaAddonsCleanup?.();

  function validRecord(value) {
    return value && typeof value === "object" && !Array.isArray(value);
  }

  function emptyPolicy() {
    return {
      keys: Object.create(null),
      addons: Object.create(null),
      providers: Object.create(null),
    };
  }

  const db = await IndexedDB.openForPrincipal(
    Services.scriptSecurityManager.getSystemPrincipal(),
    DB_NAME,
    { version: 2 },
    database => {
      if (database.objectStoreNames.contains("grants")) {
        database.deleteObjectStore("grants");
      }
      for (const [name, keyPath] of [
        ["certificates", "name"], ["privileges", "addonId"], ["providers", "api"],
      ]) {
        if (!database.objectStoreNames.contains(name)) {
          database.createObjectStore(name, { keyPath });
        }
      }
    }
  );

  async function readPolicy() {
    const transaction = db.transaction(["certificates", "privileges", "providers"], "readonly");
    const [certificates, privileges, providers] = await Promise.all([
      transaction.objectStore("certificates").getAll(),
      transaction.objectStore("privileges").getAll(),
      transaction.objectStore("providers").getAll(),
    ]);
    await transaction.promiseComplete();
    const policy = emptyPolicy();
    for (const { name, pem } of certificates) policy.keys[name] = pem;
    for (const { addonId, enabled } of privileges) {
      policy.addons[addonId] = enabled;
    }
    for (const { api, addonId } of providers) policy.providers[api] = addonId;
    if (!validRecord(policy.keys) || !validRecord(policy.addons) ||
        !validRecord(policy.providers)) {
      throw new Error("Invalid policy database");
    }
    for (const [name, value] of Object.entries(policy.keys)) {
      if (!name || !validCertificate(value)) throw new Error(`Invalid CA certificate: ${name}`);
    }
    for (const [id, enabled] of Object.entries(policy.addons)) {
      if (!id || typeof enabled !== "boolean") {
        throw new Error(`Invalid privilege state for ${id}`);
      }
    }
    for (const [api, addonId] of Object.entries(policy.providers)) {
      if (!/^\w+$/.test(api) || typeof addonId !== "string" || !addonId.trim()) {
        throw new Error(`Invalid provider mapping: ${api}`);
      }
    }
    return policy;
  }

  function validCertificate(pem) {
    if (typeof pem !== "string") return false;
    const match = /^-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*$/.exec(pem);
    if (!match) return false;
    try {
      const bytes = atob(match[1].replace(/\s/g, ""));
      return bytes.length > 128 && bytes.charCodeAt(0) === 0x30;
    } catch {
      return false;
    }
  }

  function certificateDescription(pem) {
    try {
      const base64 = pem.match(/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----/)[1]
        .replace(/\s/g, "");
      const certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
      const cert = certDB.constructX509FromBase64(base64);
      const subject = cert.commonName || cert.subjectName;
      const issuer = cert.issuerCommonName || cert.issuerName;
      const expires = cert.validity.notAfterLocalTime;
      return `CN: ${subject} · Issuer: ${issuer} · Expires: ${expires}`;
    } catch (error) {
      console.warn("[Experiments Authority] Cannot inspect CA certificate", error);
      return "Cannot read X.509 certificate details";
    }
  }

  function caSource(input) {
    const value = input.trim();
    const repository = /^([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/.exec(value);
    if (repository) return { kind: "repo", owner: repository[1], repo: repository[2] };

    let url;
    try {
      url = new URL(value);
    } catch {
      throw new Error("Enter owner/repo, a GitHub repository URL, or an HTTPS CA certificate URL.");
    }
    if (url.protocol !== "https:" || url.username || url.password) {
      throw new Error("CA sources must use HTTPS without embedded credentials.");
    }

    if (url.hostname === "github.com") {
      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length < 2) throw new Error("Invalid GitHub repository URL.");
      const [owner, originalRepo, operation] = parts;
      if (!/^[A-Za-z0-9-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(originalRepo)) {
        throw new Error("Invalid GitHub repository name.");
      }
      const repo = originalRepo.replace(/\.git$/, "");
      if (operation === "blob" || operation === "raw") {
        if (parts.length < 5) throw new Error("GitHub file URL must include a ref and file path.");
        return {
          kind: "file",
          url: `https://raw.githubusercontent.com/${owner}/${repo}/${parts.slice(3).join("/")}`,
          name: `${owner}/${repo}`,
        };
      }
      if (operation === "releases" && parts[3] === "download" && parts.length >= 6) {
        return { kind: "file", url: url.href, name: `${owner}/${repo}` };
      }
      if (!operation || operation === "tree") return { kind: "repo", owner, repo };
      throw new Error("Use the repository root URL or a direct certificate file URL.");
    }
    return { kind: "file", url: url.href, name: url.hostname };
  }

  async function sourceText(url, limit = 128 * 1024, allow404 = false) {
    const response = await fetch(url, { credentials: "omit", cache: "no-store" });
    if (allow404 && response.status === 404) return null;
    if (!response.ok) throw new Error(`Cannot fetch CA source (HTTP ${response.status}).`);
    if (!response.url.startsWith("https://")) throw new Error("CA source redirected to an insecure URL.");
    if (Number(response.headers.get("content-length")) > limit) {
      throw new Error("CA source exceeds the size limit.");
    }

    const reader = response.body?.getReader();
    if (!reader) {
      const text = await response.text();
      if (new TextEncoder().encode(text).length > limit) throw new Error("CA source exceeds the size limit.");
      return text;
    }
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error("CA source exceeds the size limit.");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function certificatePath(path) {
    return typeof path === "string" && path.length > 0 &&
      !path.startsWith("/") && !path.includes("\\") && !path.includes("?") &&
      !path.includes("#") && path.split("/").every(part => part && part !== "." && part !== "..");
  }

  async function resolveCA(input) {
    const source = caSource(input);
    let url = source.url;
    let name = source.name;

    if (source.kind === "repo") {
      const { owner, repo } = source;
      const info = JSON.parse(await sourceText(`https://api.github.com/repos/${owner}/${repo}`));
      const branch = info.default_branch;
      if (typeof branch !== "string" || !branch) throw new Error("GitHub did not report a default branch.");
      const base = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/`;
      const index = await sourceText(`${base}manifest.json`, 128 * 1024, true);
      let path;
      if (index !== null) {
        const manifest = JSON.parse(index);
        path = manifest?.signing?.ca_certificate;
        if (path !== undefined && !certificatePath(path)) {
          throw new Error("xpi-manifest declares an invalid CA certificate path.");
        }
      }
      if (!path) {
        const listing = await sourceText(
          `https://api.github.com/repos/${owner}/${repo}/contents/certificates?ref=${encodeURIComponent(branch)}`,
          128 * 1024, true
        );
        const files = listing === null ? [] : JSON.parse(listing);
        const candidates = Array.isArray(files) ? files.filter(file =>
          file.type === "file" && /\.(?:pem|crt|cer)$/i.test(file.name) && certificatePath(file.path)) : [];
        if (candidates.length !== 1) {
          throw new Error(candidates.length
            ? "Multiple CA certificates found; use a direct certificate URL."
            : "No CA certificate declared in manifest.json or found in certificates/.");
        }
        path = candidates[0].path;
      }
      url = `${base}${path.split("/").map(encodeURIComponent).join("/")}`;
      name = `${owner}/${repo}`;
    }

    const pem = (await sourceText(url)).trim();
    if (!validCertificate(pem)) throw new Error("The resolved file is not one PEM-encoded X.509 certificate.");
    const encoded = pem.match(/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----/)[1];
    const der = Uint8Array.from(atob(encoded.replace(/\s/g, "")), char => char.charCodeAt(0));
    const digest = await crypto.subtle.digest("SHA-256", der);
    const fingerprint = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0"))
      .join(":").toUpperCase();
    return { pem, name, url, fingerprint };
  }

  async function savePolicy(policy) {
    const transaction = db.transaction(["certificates", "privileges", "providers"], "readwrite");
    const certificates = transaction.objectStore("certificates");
    const privileges = transaction.objectStore("privileges");
    const providers = transaction.objectStore("providers");
    const requests = [certificates.clear(), privileges.clear(), providers.clear()];
    for (const [name, pem] of Object.entries(policy.keys)) {
      requests.push(certificates.put({ name, pem }));
    }
    for (const [addonId, enabled] of Object.entries(policy.addons)) {
      requests.push(privileges.put({ addonId, enabled }));
    }
    for (const [api, addonId] of Object.entries(policy.providers)) {
      requests.push(providers.put({ api, addonId }));
    }
    await Promise.all([...requests, transaction.promiseComplete()]);
    Services.obs.notifyObservers(null, POLICY_CHANGED_TOPIC);
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function button(label, action, primary = false) {
    const element = node("moz-button");
    element.label = label;
    if (primary) element.setAttribute("type", "primary");
    element.addEventListener("click", action);
    return element;
  }

  function iconButton(label, icon, action) {
    const element = node("moz-button");
    element.type = "icon ghost";
    element.iconSrc = `chrome://global/skin/icons/${icon}.svg`;
    element.ariaLabel = label;
    element.setAttribute("aria-label", label);
    element.title = label;
    element.addEventListener("click", action);
    return element;
  }

  function field(label, value = "", multiline = false) {
    const input = node(multiline ? "moz-textarea" : "moz-input-text");
    input.label = label;
    input.value = value;
    input.setAttribute("inputlayout", "block");
    if (multiline) input.rows = 6;
    return { wrapper: input, input };
  }

  function renderView() {
    const root = node("div", "experiments-authority-page");
    root.innerHTML = `
      <style>
        .experiments-authority-add-action { display: flex; justify-content: flex-end; }
        .experiments-authority-scroll-list { --box-group-max-height: 500px; }
        .experiments-authority-dialog {
          appearance: none;
          box-sizing: border-box;
          border: 1px solid transparent;
          border-radius: var(--border-radius-medium);
          box-shadow: var(--popup-box-shadow);
          background-color: var(--background-color-box);
          color: var(--text-color);
          padding: 0;
          width: min(588px, calc(100vw - 48px));
          max-height: calc(100vh - 48px);
          overflow: auto;
        }
        .experiments-authority-dialog::backdrop { background-color: var(--background-color-overlay); }
        .experiments-authority-dialog-titlebar {
          display: grid;
          grid-template-columns: 1fr auto 1fr;
          align-items: center;
          padding: 0.4em 0.2em;
          border-bottom: 1px solid var(--border-color);
        }
        .experiments-authority-dialog-title {
          grid-column: 2;
          font-weight: var(--font-weight-heading);
          text-align: center;
          user-select: none;
        }
        .experiments-authority-dialog-close {
          grid-column: 3;
          justify-self: end;
          margin-inline-end: var(--space-xsmall);
        }
        .experiments-authority-dialog-form { padding: var(--space-xlarge); }
        .experiments-authority-dialog-actions {
          gap: var(--space-medium);
          margin-block-start: var(--space-xlarge);
        }
      </style>
    `;
    root.append(node("p", "",
      "Manage trusted XPI signers, privileged experiment add-ons, and API providers."));

    const status = node("moz-message-bar");
    status.type = "error";
    status.setAttribute("role", "status");
    status.hidden = true;
    let policy = emptyPolicy();

    function section(title, description, add) {
      const card = node("moz-card");
      const fields = node("moz-fieldset");
      fields.label = title;
      fields.description = description;
      fields.headingLevel = 3;
      if (add) {
        const actionRow = node("div", "experiments-authority-add-action");
        actionRow.append(add);
        fields.append(actionRow);
      }
      card.append(fields);
      const container = node("section", "section");
      container.append(card);
      root.append(container);
      return fields;
    }

    function openDialog(title, build, apply, readOnly = false) {
      const dialog = node("dialog", "experiments-authority-dialog");
      dialog.setAttribute("aria-label", title);
      const titlebar = node("header", "experiments-authority-dialog-titlebar");
      titlebar.append(node("span", "experiments-authority-dialog-title", title));
      const close = iconButton("Close", "close", () => dialog.close());
      close.size = "small";
      close.classList.add("experiments-authority-dialog-close");
      titlebar.append(close);
      dialog.append(titlebar);
      const form = node("form", "experiments-authority-dialog-form");
      form.noValidate = true;
      const inputs = node("moz-fieldset");
      const controls = build(inputs);
      form.append(inputs);
      const error = node("moz-message-bar");
      error.type = "error";
      error.hidden = true;
      form.append(error);
      const actions = node("moz-button-group", "experiments-authority-dialog-actions");
      actions.append(button(readOnly ? "Close" : "Cancel", () => dialog.close()));
      let saving = false;
      const commit = async () => {
        if (saving) return;
        try {
          saving = true;
          apply(controls);
          await savePolicy(policy);
          dialog.close();
          await refresh();
        } catch (cause) {
          error.message = cause.message;
          error.hidden = false;
          await refresh();
        } finally {
          saving = false;
        }
      };
      if (!readOnly) actions.append(button("Save", commit, true));
      form.append(actions);
      form.addEventListener("submit", event => {
        event.preventDefault();
        if (!readOnly) commit();
      });
      dialog.append(form);
      dialog.addEventListener("close", () => dialog.remove(), { once: true });
      root.append(dialog);
      dialog.showModal();
      form.querySelector("moz-input-text")?.focus();
    }

    const addKey = button("Add CA", () => keyDialog(null));
    addKey.iconSrc = "chrome://global/skin/icons/plus.svg";
    const keysSection = section("Trusted certificate authorities",
      "Named PEM-encoded X.509 CA certificates.", addKey);
    const keysList = node("moz-box-group", "experiments-authority-scroll-list");
    keysList.setAttribute("type", "list");
    keysSection.append(keysList);

    async function removeKey(name) {
      delete policy.keys[name];
      await savePolicy(policy);
      await refresh();
    }

    const addonSection = section("Experiments Addon",
      "Installed experiment API providers signed by a trusted CA. Toggle privileged access per add-on.");
    const addonList = node("moz-box-group", "experiments-authority-scroll-list");
    addonList.setAttribute("type", "list");
    addonSection.append(addonList);
    root.append(status);

    async function writePrivilege(id, enabled) {
      const transaction = db.transaction("privileges", "readwrite");
      await Promise.all([
        transaction.objectStore("privileges").put({ addonId: id, enabled }),
        transaction.promiseComplete(),
      ]);
      Services.obs.notifyObservers(null, POLICY_CHANGED_TOPIC);
    }

    const addProvider = button("Add provider", () => providerDialog(null));
    addProvider.iconSrc = "chrome://global/skin/icons/plus.svg";
    const providersSection = section("Experiment API providers",
      "Map an experiment API name to the add-on ID that provides it.", addProvider);
    const filter = node("moz-input-search", "experiments-authority-filter");
    filter.setAttribute("inputlayout", "block");
    filter.placeholder = "Find experiment APIs";
    filter.ariaLabel = "Find experiment APIs";
    providersSection.append(filter);
    const providersTable = node("moz-box-group", "experiments-authority-scroll-list");
    providersTable.setAttribute("type", "list");
    providersSection.append(providersTable);

    async function removeProvider(api) {
      delete policy.providers[api];
      await savePolicy(policy);
      await refresh();
    }

    function providerDialog(previousApi) {
      openDialog(previousApi ? "Edit experiment provider" : "Add experiment provider", form => {
        const api = field("Experiment API name", previousApi || "");
        const id = field("Provider add-on ID", previousApi ? policy.providers[previousApi] : "");
        form.append(api.wrapper, id.wrapper);
        return { api: api.input, id: id.input };
      }, ({ api, id }) => {
        const nextApi = api.value.trim().replace(/^experiments\./, "");
        const addonId = id.value.trim();
        if (!/^\w+$/.test(nextApi)) throw new Error("Enter a valid experiment API name.");
        if (!addonId) throw new Error("Enter a provider add-on ID.");
        if (nextApi !== previousApi && Object.hasOwn(policy.providers, nextApi)) {
          throw new Error("This experiment API already has a provider.");
        }
        if (previousApi && nextApi !== previousApi) delete policy.providers[previousApi];
        policy.providers[nextApi] = addonId;
      });
    }

    function keyDialog(previousName) {
      openDialog(previousName ? "Edit CA certificate" : "Add CA certificate", form => {
        const name = field("CA name", previousName || "");
        const source = field("GitHub repository or CA certificate URL");
        source.input.placeholder = "owner/repo or https://.../ca.pem";
        const value = field("CA certificate (PEM)", previousName ? policy.keys[previousName] : "", true);
        const result = node("moz-message-bar");
        result.hidden = true;
        const sourceActions = node("div", "experiments-authority-add-action");
        let resolvedSource = "";
        const resolve = button("Resolve CA", async event => {
          event.preventDefault();
          resolve.disabled = true;
          result.hidden = true;
          try {
            const input = source.input.value.trim();
            const certificate = await resolveCA(input);
            value.input.value = certificate.pem;
            if (!name.input.value.trim()) name.input.value = certificate.name;
            resolvedSource = input;
            result.type = "info";
            result.message = `Resolved ${certificate.url}\nSHA-256: ${certificate.fingerprint}`;
          } catch (error) {
            resolvedSource = "";
            result.type = "error";
            result.message = error.message;
          } finally {
            resolve.disabled = false;
            result.hidden = false;
          }
        });
        source.input.addEventListener("input", () => { resolvedSource = ""; result.hidden = true; });
        value.input.addEventListener("input", () => { resolvedSource = ""; result.hidden = true; });
        sourceActions.append(resolve);
        form.append(name.wrapper, source.wrapper, sourceActions, result, value.wrapper);
        return { name: name.input, value: value.input, source: source.input,
          isResolved: () => resolvedSource === source.input.value.trim() };
      }, ({ name, value, source, isResolved }) => {
        const nextName = name.value.trim();
        const key = value.value.trim();
        if (source.value.trim() && !isResolved()) {
          throw new Error("Resolve the CA source before saving.");
        }
        if (!nextName) throw new Error("Enter a key name.");
        if (nextName !== previousName && Object.hasOwn(policy.keys, nextName)) {
          throw new Error("A key with this name already exists.");
        }
        if (!validCertificate(key)) throw new Error("Expected one PEM-encoded X.509 CA certificate.");
        const entries = Object.entries(policy.keys).map(([current, publicKey]) =>
          [current === previousName ? nextName : current, current === previousName ? key : publicKey]);
        if (!previousName) entries.push([nextName, key]);
        policy.keys = Object.fromEntries(entries);
      });
    }

    function mozillaCADialog() {
      openDialog("Mozilla CA", form => {
        const name = field("CA name", "Mozilla");
        const authority = field("Certificate authority", "Firefox built-in XPI signing trust");
        for (const input of [name.input, authority.input]) {
          input.readOnly = true;
          input.setAttribute("readonly", "");
        }
        form.append(name.wrapper, authority.wrapper);
      }, null, true);
    }

    function populate(group, entries, type) {
      group.replaceChildren();
      if (type === "key") {
        const row = node("moz-box-item");
        row.label = "Mozilla";
        row.description = "Firefox built-in XPI signing trust";
        const edit = iconButton("Edit Mozilla", "edit-outline", mozillaCADialog);
        edit.slot = "actions";
        row.append(edit);
        group.append(row);
      }
      if (!entries.length) {
        if (type === "key") return;
        const row = node("moz-box-item", "experiments-authority-empty");
        row.label = "No entries configured.";
        group.append(row);
        return;
      }
      for (const [name, value] of entries) {
        const row = node("moz-box-item");
        row.label = name;
        row.description = type === "key" ? certificateDescription(value) : value;
        const edit = iconButton(`Edit ${name}`, "edit-outline", () =>
          type === "key" ? keyDialog(name) : providerDialog(name));
        const remove = iconButton(`Remove ${name}`, "delete", () =>
          type === "key" ? removeKey(name) : removeProvider(name));
        edit.slot = "actions";
        remove.slot = "actions";
        row.append(edit, remove);
        group.append(row);
      }
    }

    async function populateExperiments() {
      const rows = [];
      for (const addon of await AddonManager.getAllAddons()) {
        const internal = addon.__AddonInternal__;
        if (internal?.type !== "extension" || !internal.eaVerified) continue;
        try {
          const uri = typeof internal.rootURI === "string"
            ? Services.io.newURI(internal.rootURI) : internal.rootURI;
          const data = new ExtensionData(uri);
          await data.initializeAddonTypeAndID();
          if (!data.rawManifest?.experiment_apis ||
              !Object.keys(data.rawManifest.experiment_apis).length) continue;
          rows.push(addon);
        } catch (error) {
          console.warn(`[Experiments Authority] Cannot inspect ${addon.id}`, error);
        }
      }
      addonList.replaceChildren();
      if (!rows.length) {
        const empty = node("moz-box-item");
        empty.label = "No installed experiment add-ons signed by trusted CAs.";
        addonList.append(empty);
        return;
      }
      for (const addon of rows) {
        const row = node("moz-box-item");
        row.label = addon.name || addon.id;
        row.description = addon.id;
        const toggle = node("moz-toggle");
        toggle.slot = "actions";
        toggle.ariaLabel = `Privileged access for ${addon.name || addon.id}`;
        toggle.pressed = policy.addons[addon.id] !== false;
        toggle.addEventListener("toggle", async () => {
          toggle.disabled = true;
          try {
            await writePrivilege(addon.id, toggle.pressed);
            await refresh();
          } catch (error) {
            toggle.pressed = !toggle.pressed;
            status.message = `Cannot change privileged access: ${error.message}`;
            status.hidden = false;
          } finally {
            toggle.disabled = false;
          }
        });
        row.append(toggle);
        addonList.append(row);
      }
    }

    function populateProviders(search) {
      providersTable.replaceChildren();
      const entries = Object.entries(policy.providers).filter(([api, addonId]) =>
        api.toLowerCase().includes(search) || addonId.toLowerCase().includes(search));
      if (!entries.length) {
        const empty = node("moz-box-item", "experiments-authority-empty");
        empty.label = "No entries configured.";
        providersTable.append(empty);
        return;
      }
      for (const [api, addonId] of entries) {
        const row = node("moz-box-item", "experiments-authority-provider-row");
        row.label = api;
        row.description = addonId;
        const edit = iconButton(`Edit ${api}`, "edit-outline", () => providerDialog(api));
        const remove = iconButton(`Remove ${api}`, "delete", () => void removeProvider(api));
        edit.slot = "actions";
        remove.slot = "actions";
        row.append(edit, remove);
        providersTable.append(row);
      }
    }

    async function refresh() {
      let valid = true;
      try {
        policy = await readPolicy();
        status.hidden = true;
      } catch (error) {
        valid = false;
        policy = emptyPolicy();
        status.message = `Cannot read experiment policy: ${error.message}.`;
        status.hidden = false;
      }
      populate(keysList, Object.entries(policy.keys), "key");
      await populateExperiments();
      populateProviders(filter.value.trim().toLowerCase());
      addKey.disabled = !valid;
      addProvider.disabled = !valid;
    }

    filter.addEventListener("MozInputSearch:search", () => {
      populateProviders(filter.value.trim().toLowerCase());
    });
    root.eaRefresh = refresh;
    void refresh();
    const heading = document.querySelector("#page-header .header-name");
    if (heading) {
      heading.removeAttribute("data-l10n-id");
      heading.textContent = TITLE;
    }
    return root;
  }

  if (controller.views[VIEW]) controller.views[VIEW] = renderView;
  else controller.defineView(VIEW, renderView);

  const navIcon = "chrome://browser/skin/labs-16.svg";
  function ensureNavigation() {
    const nav = categories.querySelector("moz-page-nav");
    if (!nav || nav.querySelector("#category-experiments-authority")) return;
    const item = node("moz-page-nav-button");
    item.id = "category-experiments-authority";
    item.setAttribute("view", VIEW);
    item.setAttribute("iconsrc", navIcon);
    item.title = TITLE;
    item.append(node("span", "", TITLE));
    item.addEventListener("click", () => controller.loadView(VIEW_ID));
    nav.insertBefore(item, nav.querySelector("#category-theme"));
    if (controller.currentViewId === VIEW_ID) nav.currentView = VIEW;
  }

  function onViewSelected(event) {
    if (event.detail.type === VIEW) {
      const nav = categories.querySelector("moz-page-nav");
      if (nav) nav.currentView = VIEW;
      const root = document.querySelector("#main > .experiments-authority-page");
      void root?.eaRefresh?.();
    }
  }

  function onPolicyChange() {
    const root = document.querySelector("#main > .experiments-authority-page");
    root?.eaRefresh?.();
  }

  const navObserver = new MutationObserver(ensureNavigation);
  navObserver.observe(categories, { childList: true, subtree: true });
  document.addEventListener("view-selected", onViewSelected);
  Services.obs.addObserver(onPolicyChange, POLICY_CHANGED_TOPIC);
  const addonListener = {
    onInstalled: onPolicyChange,
    onUninstalled: onPolicyChange,
    onEnabled: onPolicyChange,
    onDisabled: onPolicyChange,
  };
  AddonManager.addAddonListener(addonListener);
  ensureNavigation();

  const cleanup = () => {
    navObserver.disconnect();
    document.removeEventListener("view-selected", onViewSelected);
    Services.obs.removeObserver(onPolicyChange, POLICY_CHANGED_TOPIC);
    AddonManager.removeAddonListener(addonListener);
    controller.views[VIEW] = undefined;
    categories.querySelector("#category-experiments-authority")?.remove();
  };
  window.__eaAddonsCleanup = cleanup;
  window.addEventListener("unload", cleanup, { once: true });
})().catch(error => console.error("[Experiments Authority] about:addons UI failed", error));
