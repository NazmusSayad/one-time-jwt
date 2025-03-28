import OneTimeJwt from './one-time-jwt'
import {
  IncorrectOTPError,
  InvalidOTPError,
  InvalidPurposeError,
  InvalidTokenError,
} from './errors'

describe('OneTimeJwt', () => {
  const baseSecret = 'test-secret'
  const oneTimeJwt = new OneTimeJwt(baseSecret)

  describe('generateOTPSecret', () => {
    it('should generate a valid secret', () => {
      const secret = oneTimeJwt['generateOTPSecret']('purpose', 'otp')
      expect(secret).toBeInstanceOf(Uint8Array)
    })

    it('should throw InvalidPurposeError for invalid purpose', () => {
      expect(() => oneTimeJwt['generateOTPSecret'](123 as any, 'otp')).toThrow(
        InvalidPurposeError
      )
      expect(() => oneTimeJwt['generateOTPSecret']('', 'otp')).toThrow(
        InvalidPurposeError
      )
    })

    it('should throw InvalidOTPError for invalid OTP', () => {
      expect(() =>
        oneTimeJwt['generateOTPSecret']('purpose', 123 as any)
      ).toThrow(InvalidOTPError)
      expect(() => oneTimeJwt['generateOTPSecret']('purpose', '')).toThrow(
        InvalidOTPError
      )
    })
  })

  describe('createToken', () => {
    it('should create a token with default options', async () => {
      const { token, otp } = await oneTimeJwt.createToken('purpose', {
        data: 'test',
      })
      expect(typeof token).toBe('string')
      expect(typeof otp).toBe('string')
    })

    it('should create a token with custom OTP', async () => {
      const { token, otp } = await oneTimeJwt.createToken(
        'purpose',
        { data: 'test' },
        'custom-otp'
      )
      expect(typeof token).toBe('string')
      expect(otp).toBe('custom-otp')
    })

    it('should create a token with custom options', async () => {
      const { token, otp } = await oneTimeJwt.createToken(
        'purpose',
        { data: 'test' },
        { otpLength: 8 }
      )
      expect(typeof token).toBe('string')
      expect(otp.length).toBe(8)
    })
  })

  describe('verifyToken', () => {
    it('should verify a valid token', async () => {
      const { token, otp } = await oneTimeJwt.createToken('purpose', {
        data: 'test',
      })
      const payload = await oneTimeJwt.verifyToken('purpose', token, otp)
      expect(payload).toEqual({ purpose: 'purpose', payload: { data: 'test' } })
    })

    it('should throw IncorrectOTPError for invalid OTP', async () => {
      const { token } = await oneTimeJwt.createToken('purpose', {
        data: 'test',
      })
      await expect(
        oneTimeJwt.verifyToken('purpose', token, 'wrong-otp')
      ).rejects.toThrow(IncorrectOTPError)
    })

    it('should throw InvalidTokenError for invalid token', async () => {
      await expect(
        oneTimeJwt.verifyToken('purpose', 123 as any, 'otp')
      ).rejects.toThrow(InvalidTokenError)
    })
  })

  describe('safeCreateToken', () => {
    it('should return a tuple with result and null error for valid input', async () => {
      const [result, error] = await oneTimeJwt.safeCreateToken('purpose', {
        data: 'test',
      })
      expect(result).toHaveProperty('token')
      expect(result).toHaveProperty('otp')
      expect(error).toBeNull()
    })

    it('should return a tuple with null result and error for invalid input', async () => {
      const [result, error] = await oneTimeJwt.safeCreateToken('', {
        data: 'test',
      })
      expect(result).toBeNull()
      expect(error).toBeInstanceOf(InvalidPurposeError)
    })
  })

  describe('safeVerifyToken', () => {
    it('should return a tuple with result and null error for valid input', async () => {
      const { token, otp } = await oneTimeJwt.createToken('purpose', {
        data: 'test',
      })
      const [result, error] = await oneTimeJwt.safeVerifyToken(
        'purpose',
        token,
        otp
      )
      expect(result).toEqual({ purpose: 'purpose', payload: { data: 'test' } })
      expect(error).toBeNull()
    })

    it('should return a tuple with null result and error for invalid input', async () => {
      const [result, error] = await oneTimeJwt.safeVerifyToken(
        'purpose',
        'invalid-token',
        'otp'
      )
      expect(result).toBeNull()
      expect(error).toBeInstanceOf(InvalidTokenError)
    })
  })
})
