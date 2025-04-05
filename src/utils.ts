export function createSecretKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret)
}

export async function safePromiseAny<T extends Promise<unknown>[]>(
  promises: T
) {
  if (promises.length === 0) return

  try {
    if (promises.length === 1) {
      return (await promises[0]) as Promise<Awaited<T[number]>>
    }

    return await Promise.any(promises)
  } catch (err) {
    if (err instanceof AggregateError) {
      return
    }

    throw err
  }
}
