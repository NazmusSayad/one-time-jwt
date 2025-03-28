export function createSecretKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret)
}

export async function safePromiseAny<T extends Promise<unknown>[]>(
  promises: T
) {
  try {
    return await Promise.any(promises)
  } catch (err) {
    if (err instanceof AggregateError) {
      return
    }

    throw err
  }
}
