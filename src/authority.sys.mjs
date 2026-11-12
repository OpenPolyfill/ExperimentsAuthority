/* Experiments Authority: Mozilla-format XPI signatures with user-managed CA trust. */

import { Certificate, ContentInfo, SignedData } from "../vendor/pkijs.sys.mjs";
import { readPolicySnapshot, POLICY_CHANGED_TOPIC } from "./policy-db.mjs";
import { resolveExperimentDependencies } from "./experiment-dependencies.mjs";

const TAG = "[Experiments Authority]";
const MANIFEST_ENTRY = "META-INF/manifest.mf";
const SIGNATURE_FILE = "META-INF/mozilla.sf";
const SIGNATURE_ENTRY = "META-INF/mozilla.rsa";

const { ExtensionData, Extension } = ChromeUtils.importESModule(
  "resource://gre/modules/Extension.sys.mjs"
);
const { AddonInternal, XPIDatabase } = ChromeUtils.importESModule(
  "resource://gre/modules/addons/XPIDatabase.sys.mjs"
);
const { AddonManager } = ChromeUtils.importESModule(
  "resource://gre/modules/AddonManager.sys.mjs"
);
const { AddonSettings } = ChromeUtils.importESModule(
  "resource://gre/modules/addons/AddonSettings.sys.mjs"
);

const verifiedPackages = new Map();
const verifiedRoots = new Map();
const verifiedIds = new Set();
const verificationGenerations = new Map();
let nextVerificationGeneration = 0;
const nativeSignedStates = new WeakMap();
const emptyPolicy = () => ({ keys: {}, addons: {}, providers: {} });
let policy = emptyPolicy();
let policyGeneration = 0;

function record(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value);
}

function manifestHasExperimentApis(manifest) {
  return record(manifest?.experiment_apis) &&
    Object.keys(manifest.experiment_apis).length > 0;
}

function shouldVerifyCustomCA(experimentApis) {
  return XPIDatabase.mustSign("extension") ||
    (experimentApis && !AddonSettings.EXPERIMENTS_ENABLED);
}

async function shouldVerifyInstalledCA(rootURI) {
  if (XPIDatabase.mustSign("extension")) return true;
  if (AddonSettings.EXPERIMENTS_ENABLED) return false;
  const uri = typeof rootURI === "string" ? Services.io.newURI(rootURI) : rootURI;
  const extension = new ExtensionData(uri);
  await extension.initializeAddonTypeAndID();
  return manifestHasExperimentApis(extension.rawManifest);
}

function validatePolicy(snapshot) {
  try {
    if (!record(snapshot) || !record(snapshot.keys) ||
        !record(snapshot.addons) || !record(snapshot.providers)) {
      throw new Error("Invalid policy snapshot");
    }
    for (const [name, pem] of Object.entries(snapshot.keys)) {
      if (!name || typeof pem !== "string") {
        throw new Error("Invalid named CA certificate");
      }
      const cert = certificateFromPEM(pem);
      if (!cert.extensions?.some(ext => ext.extnID === "2.5.29.19" &&
          ext.parsedValue?.cA === true)) {
        throw new Error(`Trusted certificate ${name} is not a CA`);
      }
    }
    for (const [id, enabled] of Object.entries(snapshot.addons)) {
      if (!id || typeof enabled !== "boolean") {
        throw new Error(`Invalid privilege state for ${id}`);
      }
    }
    for (const [api, addonId] of Object.entries(snapshot.providers)) {
      if (!/^\w+$/.test(api) || typeof addonId !== "string" || !addonId.trim()) {
        throw new Error(`Invalid provider for experiment ${api}`);
      }
    }
    return snapshot;
  } catch (error) {
    console.error(`${TAG} Invalid policy; custom signatures denied`, error);
    return emptyPolicy();
  }
}

const policyReady = readPolicySnapshot().then(snapshot => {
  policy = validatePolicy(snapshot);
  policyGeneration++;
}).catch(error => {
  console.error(`${TAG} Could not load policy`, error);
});

function decodeBase64(base64, length = null) {
  if (typeof base64 !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
    throw new Error("Invalid Base64");
  }
  const binary = atob(base64);
  if (length !== null && binary.length !== length) {
    throw new Error(`Invalid byte length: expected ${length}`);
  }
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function certificateFromPEM(pem) {
  const match = /^-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*$/.exec(pem);
  if (!match) throw new Error("Expected one PEM X.509 certificate");
  const der = decodeBase64(match[1].replace(/\s/g, ""));
  return Certificate.fromBER(der.buffer);
}

function rootKey(id, rootURI) {
  const spec = typeof rootURI === "string" ? rootURI : rootURI?.spec;
  return id && typeof spec === "string" ? `${id}\u0000${spec}` : null;
}

function packageKey(id, digest, generation) {
  return `${id}\u0000${digest}\u0000${generation}`;
}

function clearVerifiedAddon(id) {
  const prefix = `${id}\u0000`;
  for (const key of verifiedPackages.keys()) {
    if (key.startsWith(prefix)) verifiedPackages.delete(key);
  }
  for (const key of verifiedRoots.keys()) {
    if (key.startsWith(prefix)) verifiedRoots.delete(key);
  }
  for (const key of verificationGenerations.keys()) {
    if (key.startsWith(prefix)) verificationGenerations.delete(key);
  }
  verifiedIds.delete(id);
}

function rememberVerified(id, rootURI, verified, generation) {
  const key = packageKey(id, verified.digest, generation);
  verifiedPackages.set(key, { generation, hasExperimentApis: verified.hasExperimentApis });
  verifiedIds.add(id);
  const root = rootKey(id, rootURI);
  if (root) {
    try {
      verifiedRoots.set(root, { key, stamp: archiveStamp(rootURI) });
    } catch {
      verifiedRoots.delete(root);
    }
  }
}

function archiveFile(rootURI) {
  const root = typeof rootURI === "string" ? Services.io.newURI(rootURI) : rootURI;
  return root?.QueryInterface(Ci.nsIJARURI)
    .JARFile.QueryInterface(Ci.nsIFileURL).file;
}

function archiveStamp(rootURI) {
  const file = archiveFile(rootURI);
  return `${file.fileSize}\u0000${file.lastModifiedTime}`;
}

function hashArchive(rootURI) {
  const stream = Cc["@mozilla.org/network/file-input-stream;1"]
    .createInstance(Ci.nsIFileInputStream);
  stream.init(archiveFile(rootURI), 0x01, 0, 0);
  try {
    const hash = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    hash.init(Ci.nsICryptoHash.SHA256);
    hash.updateFromStream(stream, 0xffffffff);
    return hash.finish(true);
  } finally {
    stream.close();
  }
}

function startVerification(id, rootURI) {
  const root = rootKey(id, rootURI);
  const token = ++nextVerificationGeneration;
  if (root) {
    verificationGenerations.set(root, token);
    const previous = verifiedRoots.get(root);
    if (previous) {
      try {
        if (previous.stamp !== archiveStamp(rootURI) ||
            previous.key !== packageKey(id, hashArchive(rootURI), policyGeneration)) {
          verifiedRoots.delete(root);
        }
      } catch {
        verifiedRoots.delete(root);
      }
    }
  }
  return { id, rootURI, root, token, generation: policyGeneration, keyring: policy };
}

function finishVerification(operation, verified) {
  const { id, rootURI, root, token, generation } = operation;
  if (generation !== policyGeneration ||
      (root && verificationGenerations.get(root) !== token)) {
    return false;
  }
  if (root) verificationGenerations.delete(root);
  if (verified) {
    rememberVerified(id, rootURI, verified, generation);
  } else if (root) {
    const previous = verifiedRoots.get(root);
    if (previous) verifiedPackages.delete(previous.key);
    verifiedRoots.delete(root);
  }
  return true;
}

function trustedPackage(id, rootURI) {
  const root = rootKey(id, rootURI);
  if (!root) return null;
  if (!verifiedIds.has(id)) return null;
  let stamp;
  try {
    stamp = archiveStamp(rootURI);
  } catch {
    verifiedRoots.delete(root);
    return null;
  }
  let cached = verifiedRoots.get(root);
  if (!cached || cached.stamp !== stamp) {
    verifiedRoots.delete(root);
    try {
      const key = packageKey(id, hashArchive(rootURI), policyGeneration);
      if (archiveStamp(rootURI) !== stamp || !verifiedPackages.has(key)) return null;
      cached = { key, stamp };
      verifiedRoots.set(root, cached);
    } catch {
      return null;
    }
  }
  const entry = verifiedPackages.get(cached.key);
  return entry?.generation === policyGeneration &&
    shouldVerifyCustomCA(entry.hasExperimentApis) ? entry : null;
}

function isVerified(id, rootURI) {
  return trustedPackage(id, rootURI) !== null;
}

function isVerifiedExperiment(id, rootURI) {
  const pkg = trustedPackage(id, rootURI);
  return pkg !== null && pkg.hasExperimentApis;
}

function safePath(path) {
  return typeof path === "string" && path.length > 0 &&
    !path.includes("\\") && !path.startsWith("/") &&
    !path.includes("\u0000") && !/[\r\n]/.test(path) &&
    !path.split("/").some(part => part === ".." || part === "." || part === "");
}

function excludedEntry(path) {
  const lower = path.toLowerCase();
  if (!lower.startsWith("meta-inf/")) return false;
  const name = lower.slice("meta-inf/".length);
  return name === "manifest.mf" || name.endsWith(".sf") ||
    name.endsWith(".rsa") || name.endsWith(".dsa") ||
    name.startsWith("sig-") || name === "cose.manifest" ||
    name === "cose.sig";
}

function hashEntry(zip, path, algorithm = Ci.nsICryptoHash.SHA256) {
  const stream = zip.getInputStream(path);
  try {
    const hash = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    hash.init(algorithm);
    hash.updateFromStream(stream, 0xffffffff);
    return hash.finish(true);
  } finally {
    stream.close();
  }
}

function hashBytes(bytes, algorithm = Ci.nsICryptoHash.SHA256) {
  const hash = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
  hash.init(algorithm);
  hash.update(bytes, bytes.length);
  return hash.finish(true);
}

function readZipBytes(zip, path, maxSize) {
  if (!zip.hasEntry(path)) return null;
  const entry = zip.getEntry(path);
  if (entry.realSize > maxSize) return null;
  const stream = zip.getInputStream(path);
  try {
    const binary = Cc["@mozilla.org/binaryinputstream;1"]
      .createInstance(Ci.nsIBinaryInputStream);
    binary.setInputStream(stream);
    return Uint8Array.from(binary.readByteArray(entry.realSize));
  } finally {
    stream.close();
  }
}

// JAR manifest/SF headers: continuation lines start with one ASCII space.
// The expected fields and newline conventions come from Autograph signer/xpi/jar.go.
function manifestSections(bytes) {
  const unfolded = new Uint8Array(bytes.length);
  let length = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a && bytes[i + 2] === 0x20) {
      i += 2;
    } else if (bytes[i] === 0x0a && bytes[i + 1] === 0x20) {
      i++;
    } else {
      unfolded[length++] = bytes[i];
    }
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(unfolded.subarray(0, length))
    .replace(/\r\n/g, "\n");
  if (!text.endsWith("\n\n")) throw new Error("Truncated JAR manifest");
  return text.trimEnd().split("\n\n").map(section => {
    const fields = new Map();
    const lines = section.split("\n");
    for (const line of lines) {
      const colon = line.indexOf(": ");
      if (colon <= 0) throw new Error("Invalid JAR manifest header");
      const name = line.slice(0, colon).toLowerCase();
      if (fields.has(name)) throw new Error("Duplicate JAR manifest header");
      fields.set(name, line.slice(colon + 2));
    }
    return fields;
  });
}

function verifyFiles(zip, manifestBytes, sigfileBytes) {
  if (!manifestBytes || !sigfileBytes) return false;
  const manifest = manifestSections(manifestBytes);
  const sf = manifestSections(sigfileBytes);
  if (manifest[0].get("manifest-version") !== "1.0" ||
      sf[0].get("signature-version") !== "1.0" || sf.length !== 1 ||
      sf[0].get("sha256-digest-manifest") !== hashBytes(manifestBytes) ||
      (sf[0].has("sha1-digest-manifest") &&
        sf[0].get("sha1-digest-manifest") !== hashBytes(manifestBytes, Ci.nsICryptoHash.SHA1))) {
    return false;
  }

  const signedFiles = new Map();
  for (const section of manifest.slice(1)) {
    const path = section.get("name");
    if (!safePath(path) || excludedEntry(path) || signedFiles.has(path) ||
        !section.has("sha256-digest")) return false;
    signedFiles.set(path, section);
  }
  if (!signedFiles.size) return false;
  const actualPaths = new Set();
  const entries = zip.findEntries(null);
  while (entries.hasMore()) {
    const path = entries.getNext();
    if (!safePath(path) && !(path.endsWith("/") && safePath(path.slice(0, -1)))) {
      return null;
    }
    if (path.endsWith("/")) {
      continue;
    }
    if (actualPaths.has(path)) {
      return null;
    }
    actualPaths.add(path);
    if (excludedEntry(path)) {
      // Standard PKCS#7 XPI has precisely these three unsigned metadata files.
      if (path !== MANIFEST_ENTRY && path !== SIGNATURE_FILE && path !== SIGNATURE_ENTRY) {
        return false;
      }
      continue;
    }
    const signed = signedFiles.get(path);
    if (!signed || hashEntry(zip, path) !== signed.get("sha256-digest") ||
        (signed.has("sha1-digest") &&
          hashEntry(zip, path, Ci.nsICryptoHash.SHA1) !== signed.get("sha1-digest"))) {
      return false;
    }
  }
  if (!actualPaths.has(MANIFEST_ENTRY) || !actualPaths.has(SIGNATURE_FILE) ||
      !actualPaths.has(SIGNATURE_ENTRY)) return false;
  return [...signedFiles.keys()].every(path => actualPaths.has(path)) &&
    actualPaths.size === signedFiles.size + 3;
}

function subjectName(cert, oid) {
  const values = cert.subject.typesAndValues.filter(entry => entry.type === oid);
  return values.length === 1 ? values[0].value.valueBlock.value : null;
}

async function verifyPKCS7(id, bytes, sfBytes, rootCert) {
  if (!bytes || !sfBytes) return false;
  const cms = ContentInfo.fromBER(bytes.buffer);
  if (cms.contentType !== ContentInfo.SIGNED_DATA) return false;
  const signed = new SignedData({ schema: cms.content });
  if (signed.signerInfos.length !== 1 || signed.encapContentInfo.eContent) return false;
  const result = await signed.verify({
    signer: 0,
    data: sfBytes.buffer,
    trustedCerts: [rootCert],
    checkChain: true,
    checkDate: new Date(),
    extendedMode: true,
  });
  const leaf = result.signerCertificate;
  if (!result.signatureVerified || !result.signerCertificateVerified || !leaf) {
    return false;
  }
  const eku = leaf.extensions?.find(ext => ext.extnID === "2.5.29.37");
  return subjectName(leaf, "2.5.4.3") === id &&
    subjectName(leaf, "2.5.4.11") === "Mozilla Extensions" &&
    eku?.parsedValue?.keyPurposes?.includes("1.3.6.1.5.5.7.3.3") === true;
}

async function verifyArchive(id, rootURI, keyring) {
  const signerNames = Object.keys(keyring.keys);
  if (!signerNames.length) return false;

  const digest = hashArchive(rootURI);
  const file = archiveFile(rootURI);
  const zip = Cc["@mozilla.org/libjar/zip-reader;1"].createInstance(Ci.nsIZipReader);
  let signature, sigfile, hasExperimentApis;
  try {
    zip.open(file);
    const manifest = readZipBytes(zip, MANIFEST_ENTRY, 16 * 1024 * 1024);
    sigfile = readZipBytes(zip, SIGNATURE_FILE, 1024 * 1024);
    signature = readZipBytes(zip, SIGNATURE_ENTRY, 1024 * 1024);
    if (!signature || !verifyFiles(zip, manifest, sigfile)) return false;
    const extensionManifest = readZipBytes(zip, "manifest.json", 2 * 1024 * 1024);
    if (!extensionManifest) return false;
    const metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(extensionManifest));
    hasExperimentApis = manifestHasExperimentApis(metadata);
  } finally {
    zip.close();
  }
  for (const name of signerNames) {
    try {
      if (await verifyPKCS7(id, signature, sigfile, certificateFromPEM(keyring.keys[name]))) {
        return hashArchive(rootURI) === digest ? { digest, hasExperimentApis } : false;
      }
    } catch (error) {
      console.warn(`${TAG} Certificate ${name} did not verify ${id}: ${error.message}`);
    }
  }
  return false;
}

const privilegeDescriptor = Object.getOwnPropertyDescriptor(
  AddonInternal.prototype, "isPrivileged"
);
const signedStateDescriptor = Object.getOwnPropertyDescriptor(
  AddonInternal.prototype, "signedState"
);
if (typeof ExtensionData.constructAsync !== "function" ||
    !privilegeDescriptor?.configurable ||
    typeof privilegeDescriptor.get !== "function" ||
    signedStateDescriptor ||
    typeof AddonInternal.prototype.toJSON !== "function") {
  throw new Error(`${TAG} Incompatible Gecko privilege hooks`);
}

const constructAsync = ExtensionData.constructAsync;
ExtensionData.constructAsync = async function (...args) {
  const extension = await Reflect.apply(constructAsync, this, args);
  if (extension.type !== "extension" || typeof extension.id !== "string") {
    return extension;
  }

  await policyReady;
  if (!shouldVerifyCustomCA(manifestHasExperimentApis(extension.rawManifest)) ||
      !Object.keys(policy.keys).length) {
    return extension;
  }
  const operation = startVerification(extension.id, extension.rootURI);
  try {
    const verified = await verifyArchive(extension.id, extension.rootURI, operation.keyring);
    if (!finishVerification(operation, verified)) return extension;
    if (verified) {
      extension.isPrivileged = verified.hasExperimentApis && policy.addons[extension.id] !== false;
      console.info(`${TAG} Verified signer for ${extension.id}; privileged: ${extension.isPrivileged}`);
    } else {
      console.warn(`${TAG} Signature not trusted for ${extension.id}`);
    }
  } catch (error) {
    finishVerification(operation, false);
    console.error(`${TAG} Verification failed for ${extension.id}`, error);
  }
  return extension;
};

// Install-time ExtensionData has no manifest startup cache. The running
// Extension subclass has its own parseManifest(), which can return cached data.
const parseInstallManifest = ExtensionData.prototype.parseManifest;
const parseRunningManifest = Extension.prototype.parseManifest;
ExtensionData.prototype.parseManifest = async function (...args) {
  await policyReady;
  const result = await Reflect.apply(parseInstallManifest, this, args);
  return this.constructor === ExtensionData
    ? resolveExperimentDependencies(result, policy.providers)
    : result;
};
Extension.prototype.parseManifest = async function (...args) {
  await policyReady;
  const result = await Reflect.apply(parseRunningManifest, this, args);
  return resolveExperimentDependencies(result, policy.providers);
};

// Firefox checks signedState when installing and enabling an add-on. Expose
// SIGNED only while the actual XPI has passed our keyring verification.
// Never persist this synthetic state into extensions.json: without the bridge,
// Firefox must see the original Mozilla signature result.
Object.defineProperty(AddonInternal.prototype, "signedState", {
  configurable: true,
  enumerable: true,
  get() {
    if (this.type === "extension" && isVerified(this.id, this.rootURI)) {
      return AddonManager.SIGNEDSTATE_SIGNED;
    }
    return nativeSignedStates.get(this);
  },
  set(value) {
    nativeSignedStates.set(this, value);
  },
});

const toJSON = AddonInternal.prototype.toJSON;
AddonInternal.prototype.toJSON = function (...args) {
  const result = Reflect.apply(toJSON, this, args);
  if (nativeSignedStates.has(this)) {
    result.signedState = nativeSignedStates.get(this);
  }
  return result;
};

function bindSignedState(addon) {
  const own = Object.getOwnPropertyDescriptor(addon, "signedState");
  if (!own) {
    return;
  }
  if (!own.configurable || !Object.hasOwn(own, "value")) {
    throw new Error("Incompatible stored signedState property");
  }
  delete addon.signedState;
  addon.signedState = own.value;
}

Object.defineProperty(AddonInternal.prototype, "isPrivileged", {
  ...privilegeDescriptor,
  get() {
    if (this.type === "extension" && isVerifiedExperiment(this.id, this.rootURI)) {
      return policy.addons[this.id] !== false;
    }
    return Reflect.apply(privilegeDescriptor.get, this, []);
  },
});

Object.defineProperty(AddonInternal.prototype, "eaVerified", {
  configurable: true,
  get() {
    return this.type === "extension" && isVerified(this.id, this.rootURI);
  },
});

async function reloadAddons(ids, reloadActive = new Set(), reverify = false) {
  const installed = new Map();
  for (const id of ids) {
    const addon = await AddonManager.getAddonByID(id);
    if (addon?.__AddonInternal__?.type === "extension") installed.set(id, addon);
  }
  const visited = new Set();
  const ordered = [];
  function visit(id) {
    if (visited.has(id)) return;
    visited.add(id);
    const addon = installed.get(id);
    if (!addon) return;
    for (const dependency of addon.__AddonInternal__.dependencies || []) visit(dependency);
    ordered.push(addon);
  }
  for (const id of installed.keys()) visit(id);

  for (const addon of ordered) {
    try {
      const id = addon.id;
      const internal = addon?.__AddonInternal__;
      if (!internal || internal.type !== "extension") {
        continue;
      }
      bindSignedState(internal);
      if (reverify) {
        const operation = startVerification(id, internal.rootURI);
        let verified = false;
        try {
          if (Object.keys(operation.keyring.keys).length &&
              await shouldVerifyInstalledCA(internal.rootURI)) {
            verified = await verifyArchive(id, internal.rootURI, operation.keyring);
          }
        } catch (error) {
          finishVerification(operation, false);
          throw error;
        }
        if (!finishVerification(operation, verified)) continue;
      }
      const wasActive = addon.isActive;
      await XPIDatabase.updateAddonDisabledState(internal);
      if (reloadActive.has(id) && wasActive && addon.isActive && typeof addon.reload === "function") {
        await addon.reload();
        console.info(`${TAG} Reloaded ${id}`);
      }
    } catch (error) {
      console.error(`${TAG} Failed to reload ${addon.id}`, error);
    }
  }
}

async function reconcileDependencies() {
  for (const addon of await AddonManager.getAllAddons()) {
    const internal = addon.__AddonInternal__;
    if (!internal || internal.type !== "extension" || !internal.dependencies?.length) {
      continue;
    }
    try {
      const rootURI = typeof internal.rootURI === "string"
        ? Services.io.newURI(internal.rootURI) : internal.rootURI;
      const extension = await ExtensionData.constructAsync({
        rootURI,
        temporarilyInstalled: addon.temporarilyInstalled,
        async checkPrivileged() { return internal.isPrivileged; },
      });
      const data = await extension.parseManifest();
      if (extension.errors.length) {
        throw new Error("Consumer manifest could not be parsed cleanly");
      }
      const dependencies = [...data.dependencies];
      if (dependencies.length === internal.dependencies.length &&
          dependencies.every(id => internal.dependencies.includes(id))) {
        continue;
      }
      XPIDatabase.setAddonProperties(internal, {
        dependencies: Object.freeze(dependencies),
      });
      XPIDatabase.updateXPIStates(internal);
      const wasActive = addon.isActive;
      await XPIDatabase.updateAddonDisabledState(internal);
      if (wasActive && addon.isActive) {
        await addon.reload();
      }
      console.info(`${TAG} Updated experiment dependencies for ${addon.id}`);
    } catch (error) {
      console.error(`${TAG} Failed to update dependencies for ${addon.id}`, error);
    }
  }
}

let updateQueue = policyReady.then(async () => {
  const installed = await AddonManager.getAllAddons();
  await reloadAddons(installed.map(addon => addon.id), new Set(), true);
});
AddonManager.addAddonListener({
  onUninstalled(addon) {
    clearVerifiedAddon(addon.id);
  },
});
const policyObserver = {
  observe() {
    updateQueue = updateQueue.then(async () => {
      const previous = policy;
      const next = validatePolicy(await readPolicySnapshot());
      const caChanged = JSON.stringify(previous.keys) !== JSON.stringify(next.keys);
      if (caChanged) {
        policyGeneration++;
        verifiedPackages.clear();
        verifiedRoots.clear();
        verifiedIds.clear();
        verificationGenerations.clear();
      }
      policy = next;
      const reloadActive = new Set();
      for (const id of new Set([
        ...Object.keys(previous.addons), ...Object.keys(next.addons),
      ])) {
        if (previous.addons[id] !== next.addons[id]) {
          reloadActive.add(id);
        }
      }
      if (caChanged || reloadActive.size) {
        const installed = await AddonManager.getAllAddons();
        if (caChanged) {
          for (const addon of installed) reloadActive.add(addon.id);
        }
        const affected = new Set(reloadActive);
        if (!caChanged) {
          let size;
          do {
            size = affected.size;
            for (const addon of installed) {
              if (addon.__AddonInternal__?.dependencies?.some(id => affected.has(id))) {
                affected.add(addon.id);
              }
            }
          } while (affected.size !== size);
        }
        await reloadAddons(caChanged ? installed.map(addon => addon.id) : [...affected],
          reloadActive, caChanged);
      }
      if (JSON.stringify(previous.providers) !== JSON.stringify(next.providers)) {
        await reconcileDependencies();
      }
    }).catch(error => console.error(`${TAG} Failed to apply policy update`, error));
  },
};
Services.obs.addObserver(policyObserver, POLICY_CHANGED_TOPIC);
const signaturePrefsObserver = {
  observe(_subject, topic) {
    if (topic !== "nsPref:changed") return;
    updateQueue = updateQueue.then(async () => {
      const installed = await AddonManager.getAllAddons();
      const ids = installed.filter(addon => addon.__AddonInternal__?.type === "extension")
        .map(addon => addon.id);
      await reloadAddons(ids, new Set(ids), true);
    }).catch(error => console.error(`${TAG} Failed to apply signature preference change`, error));
  },
};
Services.prefs.addObserver("xpinstall.signatures.required", signaturePrefsObserver);
Services.prefs.addObserver("extensions.experiments.enabled", signaturePrefsObserver);
console.info(`${TAG} Signed bridge active; IndexedDB policy`);
