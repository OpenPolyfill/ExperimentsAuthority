// System-principal IndexedDB shared by the bridge and its about:addons page.
export const DB_NAME = "experiments-authority";
export const DB_VERSION = 2;
export const POLICY_CHANGED_TOPIC = "experiments-authority:policy-changed";

const { IndexedDB } = ChromeUtils.importESModule(
  "resource://gre/modules/IndexedDB.sys.mjs"
);

let databasePromise;

export function openPolicyDatabase() {
  if (!databasePromise) {
    const principal = Services.scriptSecurityManager.getSystemPrincipal();
    databasePromise = IndexedDB.openForPrincipal(
      principal,
      DB_NAME,
      { version: DB_VERSION },
      db => {
        if (db.objectStoreNames.contains("grants")) {
          db.deleteObjectStore("grants");
        }
        if (!db.objectStoreNames.contains("certificates")) {
          db.createObjectStore("certificates", { keyPath: "name" });
        }
        if (!db.objectStoreNames.contains("privileges")) {
          db.createObjectStore("privileges", { keyPath: "addonId" });
        }
        if (!db.objectStoreNames.contains("providers")) {
          db.createObjectStore("providers", { keyPath: "api" });
        }
      }
    ).catch(error => {
      databasePromise = undefined;
      throw error;
    });
  }
  return databasePromise;
}

export async function readPolicySnapshot() {
  const db = await openPolicyDatabase();
  const transaction = db.transaction(["certificates", "privileges", "providers"], "readonly");
  const [certificates, privileges, providers] = await Promise.all([
    transaction.objectStore("certificates").getAll(),
    transaction.objectStore("privileges").getAll(),
    transaction.objectStore("providers").getAll(),
  ]);
  await transaction.promiseComplete();

  const keys = Object.create(null);
  const addons = Object.create(null);
  const mapping = Object.create(null);
  for (const { name, pem } of certificates) {
    if (typeof name !== "string" || !name || typeof pem !== "string") {
      throw new Error("Invalid certificate record");
    }
    keys[name] = pem;
  }
  for (const { addonId, enabled } of privileges) {
    if (typeof addonId !== "string" || !addonId || typeof enabled !== "boolean") {
      throw new Error("Invalid privilege record");
    }
    addons[addonId] = enabled;
  }
  for (const { api, addonId } of providers) {
    if (typeof api !== "string" || !/^\w+$/.test(api) ||
        typeof addonId !== "string" || !addonId.trim()) {
      throw new Error("Invalid experiment provider record");
    }
    mapping[api] = addonId;
  }
  return { keys, addons, providers: mapping };
}
