let sodiumPromise: Promise<any> | null = null

/**
 * Dynamically load the libsodium-wrappers module on demand.
 * The loader memoizes the resolved module so the heavy WASM bundle is only fetched once.
 */
export const loadSodium = async () => {
  if (!sodiumPromise) {
    sodiumPromise = import('libsodium-wrappers').then(async (module) => {
      const sodium = (module as unknown as { default?: any }).default ?? module

      if (sodium && typeof sodium.ready !== 'undefined') {
        await sodium.ready
      }

      return sodium
    })
  }

  return sodiumPromise
}

/**
 * Reset function is exposed for tests so they can re-initialize the loader.
 */
export const resetSodiumLoader = () => {
  sodiumPromise = null
}

export type SodiumModule = Awaited<ReturnType<typeof loadSodium>>
