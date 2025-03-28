import { JWTHeaderParameters, JWTVerifyOptions } from 'jose'

export type OneTimeJwtOptions = {
  secretDivider?: string
}

export type OneTimeJwtCreateTokenOptions =
  | (
      | {
          otp?: string
        }
      | {
          otpType?: TOtpType
          otpLength?: number
        }
    )
  | {}

export type OneTimeJwtCreateTokenResult = {
  token: string
  otp: string
}

export type OneTimeJwtVerifyTokenOptions = {
  otp: string
}

export type TOtpType =
  | 'digits'
  | 'letters'
  | 'letters-upper'
  | 'letter-lower'
  | 'alphanumeric'
  | 'base64'

export type TSignOptions = {
  secret: Uint8Array
  algorithm?: string

  issuer?: string
  issuedAt?: number | string | Date
  expiresIn?: number | string | Date
  notBefore?: number | string | Date

  jti?: string
  subject?: string
  audience?: string | string[]
  protectedHeader?: JWTHeaderParameters
}

export type TVerifyOptions = JWTVerifyOptions & {
  secret: Uint8Array
}
