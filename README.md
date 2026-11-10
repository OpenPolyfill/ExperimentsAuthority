# Experiments Authority

Experiments Authority lets Firefox users trust their own X.509 certificate
authorities for Mozilla-format signed XPIs and control WebExtension Experiment
privileges. Mozilla-signed extensions continue to use Firefox's normal path.

## Installation with Sine

Requires Firefox (or a compatible fork) and Sine 2.x.

1. In Sine, install this repository as an unpublished mod using its GitHub URL.
2. Enable `sine.allow-unsafe-js` in `about:config`.
3. Restart Firefox and open **Add-ons and themes → Experiments**.
4. Add a named PEM certificate under **Trusted certificate authorities**.

Sine loads `src/authority.sys.mjs` as a background module and
`src/addons-manager.uc.js` in `about:addons`, as declared in `theme.json`.
The code itself does not depend on Sine and can also be loaded through a
compatible userChrome.js loader.

## Features

- **CA manager:** add, rename, edit, or remove user-trusted signing CAs.
- **Experiment privileges:** trusted add-ons declaring `experiment_apis`
  receive privileged access by default, with per-add-on enable/disable toggles.
- **Experiment API mapping:** map an API name to a provider add-on ID instead
  of Firefox's hardcoded `<api>@experiments.addons.mozilla.org` suffix.

All settings live in a system-principal IndexedDB database named
`experiments-authority`, with `certificates`, `privileges`, and `providers`
object stores. CA changes trigger signature re-verification. Privilege changes
reload affected providers and consumers without rehashing their XPIs.

## Signature verification

The verifier follows Mozilla Autograph's XPI signature structure:
`META-INF/manifest.mf`, `mozilla.sf`, and detached PKCS#7/CMS `mozilla.rsa`.
It validates the archive digests, CMS signature, X.509 chain to a user-trusted
CA, and the signing certificate's add-on ID and code-signing constraints.
The trusted root is **not** imported into Firefox's NSS trust store.

Only packed XPI roots can receive custom trust. Firefox's original signature
verification is unchanged, and the synthetic signing state is not persisted
in `extensions.json`. Removing EA and restarting removes its modifications.

For diagnostics, open the Browser Console (`Ctrl+Shift+J`) and filter
`[Experiments Authority]`.

## Development

The source imports `vendor/pkijs.sys.mjs`, a checked-in PKI.js bundle. Firefox
users do not need Node or npm. Rebuild that vendor module only when its
dependencies change:

```sh
npm ci
npm run build
npm run check
```

Mozilla format reference: [Autograph XPI signer](https://github.com/mozilla-services/autograph/tree/main/signer/xpi).

## License

Experiments Authority is licensed under **MPL-2.0** (see `LICENSE`).
Bundled third-party code retains its own licenses under `third_party_licenses/`.
