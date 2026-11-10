export function resolveExperimentDependencies(data, providers) {
  if (!data?.apiNames || typeof data.apiNames[Symbol.iterator] !== "function" ||
      !data.dependencies || typeof data.dependencies[Symbol.iterator] !== "function") {
    return data;
  }
  const apiNames = [...data.apiNames];
  if (apiNames.length === 0) return data;

  // Firefox's manifest parser generates dependencies exclusively from apiNames.
  // Rebuild the set so stale IDs from StartupCache cannot survive a remap.
  const dependencies = new Set();
  for (const api of apiNames) {
    dependencies.add(Object.hasOwn(providers, api)
      ? providers[api] : `${api}@experiments.addons.mozilla.org`);
  }
  return { ...data, dependencies };
}
