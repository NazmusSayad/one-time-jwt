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

  /**
   * Creates a one-time JWT token with an associated OTP.
   * @param purpose - The purpose of the token.
   * @param payload - The payload to include in the token.
   * @param options - Options for token creation.
   * @returns An object containing the token and OTP.
   * @throws If the OTP length is invalid.
   * @example
   * // Example with numeric OTP of length 4
   * const jwt = new OneTimeJwt('baseSecret');
   * const result = await jwt.createToken('login', { userId: 123 }, { otpType: 'numeric', otpLength: 4 });
   * console.log(result.token, result.otp);
   *
   * // Example with alphanumeric OTP of default length
   * const result2 = await jwt.createToken('register', { email: 'test@example.com' });
   * console.log(result2.token, result2.otp);
   *
   * // Example with custom OTP
   * const result3 = await jwt.createToken('reset', { userId: 456 }, 'customOTP123');
   * console.log(result3.token, result3.otp);
   */
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

  /**
   * Verifies a one-time JWT token using the associated OTP.
   * @param purpose - The purpose of the token.
   * @param token - The token(s) to verify.
   * @param options - Options for token verification.
   * @returns The payload extracted from the verified token.
   * @throws If the token is invalid or exceeds the maximum limit.
   * @throws If the OTP is invalid.
   * @example
   * // Example with single token and OTP
   * const jwt = new OneTimeJwt('baseSecret');
   * const payload = await jwt.verifyToken('login', 'tokenString', { otp: '123456' });
   * console.log(payload);
   *
   * // Example with multiple tokens and OTP
   * const payload2 = await jwt.verifyToken('login', ['token1', 'token2'], { otp: '654321' });
   * console.log(payload2);
   *
   * // Example with OTP as a string
   * const payload3 = await jwt.verifyToken('login', 'tokenString', '123456');
   * console.log(payload3);
   */
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

    try {
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
    } catch (err) {
      if (err instanceof Error && err.name === 'JWSInvalid') {
        this.log('error', `Invalid token for purpose: ${purpose}`)
        throw new InvalidTokenError('Invalid JWT token')
      }

      if (
        err instanceof Error &&
        err.name === 'JWSSignatureVerificationFailed'
      ) {
        this.log('error', `Invalid token signature for purpose: ${purpose}`)
        throw new IncorrectOTPError('Invalid token signature')
      }

      throw err
    }
  }

  /**
   * Safely creates a one-time JWT token with an associated OTP, catching any errors.
   * @param purpose - The purpose of the token.
   * @param payload - The payload to include in the token.
   * @param options - Options for token creation.
   * @returns A tuple containing the result or an error.
   * @example
   * // Example with default options
   * const jwt = new OneTimeJwt('baseSecret');
   * const [result, error] = await jwt.safeCreateToken('login', { userId: 123 });
   * if (error) {
   *   console.error(error);
   * } else {
   *   console.log(result.token, result.otp);
   * }
   *
   * // Example with custom OTP
   * const [result2, error2] = await jwt.safeCreateToken('reset', { userId: 456 }, 'customOTP123');
   * if (error2) {
   *   console.error(error2);
   * } else {
   *   console.log(result2.token, result2.otp);
   * }
   */
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

  /**
   * Safely verifies a one-time JWT token using the associated OTP, catching any errors.
   * @param purpose - The purpose of the token.
   * @param token - The token(s) to verify.
   * @param options - Options for token verification.
   * @returns A tuple containing the result or an error.
   * @example
   * // Example with single token and OTP
   * const jwt = new OneTimeJwt('baseSecret');
   * const [payload, error] = await jwt.safeVerifyToken('login', 'tokenString', { otp: '123456' });
   * if (error) {
   *   console.error(error);
   * } else {
   *   console.log(payload);
   * }
   *
   * // Example with multiple tokens and OTP
   * const [payload2, error2] = await jwt.safeVerifyToken('login', ['token1', 'token2'], { otp: '654321' });
   * if (error2) {
   *   console.error(error2);
   * } else {
   *   console.log(payload2);
   * }
   *
   * // Example with OTP as a string
   * const [payload3, error3] = await jwt.safeVerifyToken('login', 'tokenString', '123456');
   * if (error3) {
   *   console.error(error3);
   * } else {
   *   console.log(payload3);
   * }
   */
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
