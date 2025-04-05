import {
  InvalidOTPError,
  InvalidTokenError,
  IncorrectOTPError,
  InvalidPurposeError,
} from './errors'
import {
  LogLevel,
  OneTimeJwtOptions,
  OneTimeJwtCreateTokenResult,
  OneTimeJwtCreateTokenOptions,
  OneTimeJwtVerifyTokenOptions,
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

  private log(level: LogLevel, message: string): void {
    if (!this.options.logLevel || this.options.logLevel === 'silent') return

    const levels = ['debug', 'info', 'warn', 'error']
    if (levels.indexOf(level) >= levels.indexOf(this.options.logLevel)) {
      if (level === 'error') {
        console.error(`[OneTimeJwt] ${message}`)
      } else if (level === 'warn') {
        console.warn(`[OneTimeJwt] ${message}`)
      } else {
        console.log(`[OneTimeJwt] ${message}`)
      }
    }
  }

  private generateOTPSecret(purpose: string, otp: string): Uint8Array {
    this.log('debug', `Generating OTP secret for purpose: ${purpose}`)

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
    options: OneTimeJwtCreateTokenOptions = {}
  ): Promise<OneTimeJwtCreateTokenResult> {
    this.log('info', `Creating token for purpose: ${purpose}`)

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

      const otpType = options.otpType ?? 'alphanumeric'
      const otpLength = options.otpLength ?? 6

      if (otpLength <= 0) {
        throw new InvalidOTPError(
          'Invalid OTP length expected positive number > 0'
        )
      }

      otp = generateOtp(otpType, otpLength)
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

    this.log('info', `Token created successfully for purpose: ${purpose}`)

    return { token, otp }
  }

  public async verifyToken<T extends unknown>(
    purpose: string,
    token: string | string[],
    options: OneTimeJwtVerifyTokenOptions
  ): Promise<T> {
    this.log('info', `Verifying token for purpose: ${purpose}`)

    const tokenArray = Array.isArray(token) ? token : [token]

    if (tokenArray.length === 0) {
      throw new InvalidTokenError('No tokens provided for verification')
    }

    for (const token of tokenArray) {
      if (typeof token !== 'string') {
        throw new InvalidTokenError('Invalid token expected string')
      }
    }

    const maxTokenLimitPerPurpose =
      this.options.maxTokenLimitPerPurpose ??
      (typeof options === 'string'
        ? undefined
        : options.maxTokenLimitPerPurpose) ??
      3

    if (tokenArray.length > maxTokenLimitPerPurpose) {
      throw new InvalidTokenError(
        `Invalid token expected at most ${this.options.maxTokenLimitPerPurpose} tokens`
      )
    }

    const otp = typeof options === 'string' ? options : options.otp
    if (typeof otp !== 'string' || !otp) {
      throw new InvalidOTPError('Invalid OTP expected non-empty string')
    }

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

    this.log('info', `Token verified successfully for purpose: ${purpose}`)

    return jwtPayload.payload as T
  }

  public async safeCreateToken<T extends unknown>(
    purpose: string,
    payload: T,
    options: OneTimeJwtCreateTokenOptions = {}
  ): Promise<TupleResult<OneTimeJwtCreateTokenResult, Error>> {
    this.log('info', `Safely creating token for purpose: ${purpose}`)

    try {
      const result = await this.createToken<T>(purpose, payload, options)

      this.log('info', `Token safely created for purpose: ${purpose}`)
      return [result, null] as any
    } catch (error) {
      this.log(
        'error',
        `Error while safely creating token for purpose: ${purpose}: ${error}`
      )
      return [null, error] as any
    }
  }

  public async safeVerifyToken<T extends unknown>(
    purpose: string,
    token: string | string[],
    options: OneTimeJwtVerifyTokenOptions
  ): Promise<TupleResult<T, Error>> {
    this.log('info', `Safely verifying token for purpose: ${purpose}`)
    try {
      const result = await this.verifyToken<T>(purpose, token, options)

      this.log('info', `Token safely verified for purpose: ${purpose}`)
      return [result, null] as any
    } catch (error) {
      this.log(
        'error',
        `Error while safely verifying token for purpose: ${purpose}: ${error}`
      )
      return [null, error] as any
    }
  }
}
