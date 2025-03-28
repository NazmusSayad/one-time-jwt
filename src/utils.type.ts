export type Prettify<T> = { [K in keyof T]: T[K] } & {}

export type TupleResult<T, U> = [T, null] | [null, U]
