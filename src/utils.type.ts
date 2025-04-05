export type Prettify<T> = { [K in keyof T]: T[K] } & {}

export type TupleResult<T, U, V = null> = [T, V] | [V, U]
