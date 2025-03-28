import {
  InvalidOTPError,
  InvalidTokenError,
  IncorrectOTPError,
  InvalidPurposeError,
} from './errors'
import {
  OneTimeJwtOptions,
  OneTimeJwtCreateTokenOptions,
  OneTimeJwtVerifyTokenOptions,
  OneTimeJwtCreateTokenResult,
} from './types.type'
import { generateOtp } from './helpers'
import { TupleResult } from './utils.type'
import { signJwt, verifyJwt } from './jwt'
import { createSecretKey, safePromiseAny } from './utils'

export default class OneTimeJwt {
  private baseSecret: string
  private options: OneTimeJwtOptions

  constructor(baseSecret: string, options: OneTimeJwtOptions = {}) {
    this.baseSecret = baseSecret
    this.options = options
  }

  private generateOTPSecret(purpose: string, otp: string): Uint8Array {
    if (typeof purpose !== 'string') {
      throw new InvalidPurposeError('Invalid purpose expected string')
    }

    if (purpose === '') {
      throw new InvalidPurposeError('Invalid purpose expected non-empty string')
    }

    if (typeof otp !== 'string') {
      throw new InvalidOTPError('Invalid OTP expected string')
    }

    if (otp === '') {
      throw new InvalidOTPError('Invalid OTP expected non-empty string')
    }

    const OTPSecret = createSecretKey(
      [this.baseSecret, purpose, otp].join(this.options.secretDivider ?? '')
    )

    return OTPSecret
  }

  public async createToken<T extends unknown>(
    purpose: string,
    payload: T,
    options: string | OneTimeJwtCreateTokenOptions = {}
  ): Promise<OneTimeJwtCreateTokenResult> {
    let otp: string
    if (typeof options === 'string') {
      /* 
        If options is a string then it is the otp and we don't have to generate it
       */
      otp = options
    } else if ('otp' in options && options.otp !== undefined) {
      /* 
        If otp is provided in options then we don't have to generate it
       */
      otp = options.otp
    } else if ('otpType' in options || 'otpLength' in options) {
      /* 
        If otpType or otpLength is provided in options then we have to generate the otp
       */
      otp = generateOtp(
        options.otpType ?? 'alphanumeric',
        options.otpLength ?? 6
      )
    } else {
      /* 
        Default to alphanumeric otp of length 6
       */
      otp = generateOtp('alphanumeric', 6)
    }

    const token = await signJwt(
      { purpose, payload },
      {
        ...(typeof options === 'string' ? {} : options),
        secret: this.generateOTPSecret(purpose, otp),
      }
    )

    return { token, otp }
  }

  public async verifyToken<T extends unknown>(
    purpose: string,
    token: string | string[],
    options: string | OneTimeJwtVerifyTokenOptions
  ): Promise<T> {
    const tokenArray = Array.isArray(token) ? token : [token]

    for (const token of tokenArray) {
      if (typeof token !== 'string') {
        throw new InvalidTokenError('Invalid token expected string')
      }
    }

    const otp = typeof options === 'string' ? options : options.otp

    const jwtPayload = await safePromiseAny(
      tokenArray.map((token) =>
        verifyJwt(token, {
          ...(typeof options === 'string' ? {} : options),
          secret: this.generateOTPSecret(purpose, otp),
        })
      )
    )

    if (!jwtPayload) {
      throw new IncorrectOTPError('Incorrect OTP')
    }

    return jwtPayload.payload as T
  }

  public async safeCreateToken<T extends unknown>(
    purpose: string,
    payload: T,
    options: string | OneTimeJwtCreateTokenOptions = {}
  ): Promise<TupleResult<OneTimeJwtCreateTokenResult, Error>> {
    try {
      const result = await this.createToken<T>(purpose, payload, options)
      return [result, null] as TupleResult<OneTimeJwtCreateTokenResult, Error>
    } catch (error) {
      return [null, error] as TupleResult<OneTimeJwtCreateTokenResult, Error>
    }
  }

  public async safeVerifyToken<T extends unknown>(
    purpose: string,
    token: string | string[],
    options: string | OneTimeJwtVerifyTokenOptions
  ): Promise<TupleResult<T, null>> {
    try {
      const result = await this.verifyToken<T>(purpose, token, options)
      return [result, null] as TupleResult<T, null>
    } catch (error) {
      return [null, error] as TupleResult<T, null>
    }
  }
}
