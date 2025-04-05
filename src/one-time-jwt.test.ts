import {
  InvalidOTPError,
  IncorrectOTPError,
  InvalidTokenError,
  InvalidPurposeError,
} from './errors'
import OneTimeJwt from './one-time-jwt'
import { describe, it, expect, beforeEach } from 'bun:test'

const baseSecret = 'test-secret'
const testPurpose = 'authentication'
const testPayload = { userId: '123', role: 'admin' }

describe('OneTimeJwt', () => {
  describe('Create Token', () => {
    let otj: OneTimeJwt

    beforeEach(() => {
      otj = new OneTimeJwt(baseSecret)
    })

    it('should create token with default options', async () => {
      const { token, otp } = await otj.createToken(testPurpose, testPayload)
      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      expect(otp).toBeDefined()
      expect(typeof otp).toBe('string')
      expect(otp.length).toBe(6)
    })

    it('should create token with string OTP option', async () => {
      const customOtp = '123456'
      const { token, otp } = await otj.createToken(
        testPurpose,
        testPayload,
        customOtp
      )
      expect(token).toBeDefined()
      expect(otp).toBe(customOtp)
    })

    it('should create token with provided OTP', async () => {
      const customOtp = '987654'
      const { token, otp } = await otj.createToken(testPurpose, testPayload, {
        otp: customOtp,
      })
      expect(token).toBeDefined()
      expect(otp).toBe(customOtp)
    })

    it('should create token with different OTP lengths', async () => {
      const lengths = [1, 4, 8, 12, 16, 32]

      for (const length of lengths) {
        const { token, otp } = await otj.createToken(testPurpose, testPayload, {
          otpLength: length,
        })

        expect(token).toBeDefined()
        expect(otp).toBeDefined()
        expect(otp.length).toBe(length)
      }
    })

    it('should create token with JWT sign options', async () => {
      const { token, otp } = await otj.createToken(testPurpose, testPayload, {
        algorithm: 'HS384',
        expiresIn: '1h',
        issuer: 'test-issuer',
        subject: 'test-subject',
        audience: 'test-audience',
        notBefore: new Date(),
        issuedAt: new Date(),
        jti: 'test-jti',
      })

      expect(token).toBeDefined()
      expect(otp).toBeDefined()
    })

    it('should throw error for invalid OTP length', async () => {
      expect(
        otj.createToken(testPurpose, testPayload, { otpLength: 0 })
      ).rejects.toThrow(InvalidOTPError)

      expect(
        otj.createToken(testPurpose, testPayload, { otpLength: -5 })
      ).rejects.toThrow(InvalidOTPError)
    })

    it('should throw error for invalid purpose', async () => {
      expect(otj.createToken('', testPayload)).rejects.toThrow(
        InvalidPurposeError
      )
    })
  })

  describe('Verify Token', () => {
    let otj: OneTimeJwt
    let token: string
    let otp: string

    beforeEach(async () => {
      otj = new OneTimeJwt(baseSecret)
      const result = await otj.createToken(testPurpose, testPayload)
      token = result.token
      otp = result.otp
    })

    it('should verify token with correct OTP', async () => {
      const payload = await otj.verifyToken(testPurpose, token, otp)
      expect(payload).toEqual(testPayload)
    })

    it('should verify token with OTP object', async () => {
      const payload = await otj.verifyToken(testPurpose, token, { otp })
      expect(payload).toEqual(testPayload)
    })

    it('should verify token when multiple tokens are provided', async () => {
      const { token: token2 } = await otj.createToken(
        'different-purpose',
        testPayload
      )

      const payload = await otj.verifyToken(testPurpose, [token, token2], otp)
      expect(payload).toEqual(testPayload)
    })

    it('should handle array with single token', async () => {
      const payload = await otj.verifyToken(testPurpose, [token], otp)
      expect(payload).toEqual(testPayload)
    })

    it('should throw error for incorrect OTP', async () => {
      expect(otj.verifyToken(testPurpose, token, 'wrong-otp')).rejects.toThrow(
        IncorrectOTPError
      )
    })

    it('should throw error for invalid OTP', async () => {
      expect(otj.verifyToken(testPurpose, token, '')).rejects.toThrow(
        InvalidOTPError
      )

      expect(otj.verifyToken(testPurpose, token, { otp: '' })).rejects.toThrow(
        InvalidOTPError
      )
    })

    it('should throw error for empty token array', async () => {
      expect(otj.verifyToken(testPurpose, [], otp)).rejects.toThrow(
        InvalidTokenError
      )
    })

    it('should throw error when token limit is exceeded', async () => {
      const otjWithLimit = new OneTimeJwt(baseSecret, {
        maxTokenLimitPerPurpose: 2,
      })

      expect(
        otjWithLimit.verifyToken(testPurpose, [token, token, token], otp)
      ).rejects.toThrow(InvalidTokenError)
    })

    it('should respect maxTokenLimitPerPurpose from options object', async () => {
      expect(
        otj.verifyToken(testPurpose, [token, token, token, token], {
          otp,
          maxTokenLimitPerPurpose: 3,
        })
      ).rejects.toThrow(InvalidTokenError)
    })

    it('should verify token with custom JWT options', async () => {
      const { token: customToken, otp: customOtp } = await otj.createToken(
        testPurpose,
        testPayload,
        {
          algorithm: 'HS256',
          expiresIn: '1h',
        }
      )

      const payload = await otj.verifyToken(testPurpose, customToken, customOtp)
      expect(payload).toEqual(testPayload)
    })

    it('should throw error for incorrect OTP with object option', async () => {
      expect(
        otj.verifyToken(testPurpose, token, { otp: 'wrong-otp' })
      ).rejects.toThrow(IncorrectOTPError)
    })

    it('should throw error for incorrect OTP with maxTokenLimitPerPurpose option', async () => {
      expect(
        otj.verifyToken(testPurpose, token, {
          otp: 'wrong-otp',
          maxTokenLimitPerPurpose: 2,
        })
      ).rejects.toThrow(IncorrectOTPError)
    })

    it('should throw error for incorrect OTP with multiple tokens', async () => {
      const { token: token2 } = await otj.createToken(
        'different-purpose',
        testPayload
      )

      expect(
        otj.verifyToken(testPurpose, [token, token2], 'wrong-otp')
      ).rejects.toThrow(IncorrectOTPError)
    })
  })

  describe('Safe Methods', () => {
    let otj: OneTimeJwt

    beforeEach(() => {
      otj = new OneTimeJwt(baseSecret)
    })

    describe('safeCreateToken', () => {
      it('should safely create token with success result', async () => {
        const [result, error] = await otj.safeCreateToken(
          testPurpose,
          testPayload
        )
        expect(result).toBeDefined()
        expect(error).toBeNull()
        expect(result!.token).toBeDefined()
        expect(result!.otp).toBeDefined()
      })

      it('should handle errors gracefully', async () => {
        const [result, error] = await otj.safeCreateToken('', testPayload)
        expect(result).toBeNull()
        expect(error).toBeInstanceOf(InvalidPurposeError)
      })

      it('should work with all token creation options', async () => {
        const [result1] = await otj.safeCreateToken(
          testPurpose,
          testPayload,
          '123456'
        )
        expect(result1).toBeDefined()
        expect(result1?.otp).toBe('123456')

        const [result2] = await otj.safeCreateToken(testPurpose, testPayload, {
          otp: '654321',
        })
        expect(result2).toBeDefined()
        expect(result2?.otp).toBe('654321')

        const [result3] = await otj.safeCreateToken(testPurpose, testPayload, {
          otpType: 'digits',
          otpLength: 8,
        })

        expect(result3).toBeDefined()
        expect(result3!.otp.length).toBe(8)
        expect(/^\d+$/.test(result3!.otp)).toBe(true)
      })
    })

    describe('safeVerifyToken', () => {
      let token: string
      let otp: string

      beforeEach(async () => {
        const result = await otj.createToken(testPurpose, testPayload)
        token = result.token
        otp = result.otp
      })

      it('should safely verify token with success result', async () => {
        const [payload, error] = await otj.safeVerifyToken(
          testPurpose,
          token,
          otp
        )
        expect(payload).toEqual(testPayload)
        expect(error).toBeNull()
      })

      it('should handle verification errors gracefully', async () => {
        const [payload, error] = await otj.safeVerifyToken(
          testPurpose,
          token,
          'wrong-otp'
        )
        expect(payload).toBeNull()
        expect(error).toBeInstanceOf(IncorrectOTPError)
      })

      it('should handle invalid token gracefully', async () => {
        const [payload, error] = await otj.safeVerifyToken(
          testPurpose,
          'invalid-token',
          otp
        )
        expect(payload).toBeNull()
        expect(error).toBeDefined()
      })
    })
  })

  describe('Special Cases', () => {
    let otj: OneTimeJwt

    beforeEach(() => {
      otj = new OneTimeJwt(baseSecret)
    })

    it('should work with custom secret divider', async () => {
      const otjWithDivider = new OneTimeJwt(baseSecret, { secretDivider: '||' })
      const { token, otp } = await otjWithDivider.createToken(
        testPurpose,
        testPayload
      )

      const payload = await otjWithDivider.verifyToken(testPurpose, token, otp)
      expect(payload).toEqual(testPayload)
    })

    it('should handle different payload types', async () => {
      const stringPayload = 'string-payload'
      const { token: token1, otp: otp1 } = await otj.createToken(
        testPurpose,
        stringPayload
      )
      const result1 = await otj.verifyToken<string>(testPurpose, token1, otp1)
      expect(result1).toBe(stringPayload)

      const numberPayload = 12345
      const { token: token2, otp: otp2 } = await otj.createToken(
        testPurpose,
        numberPayload
      )
      const result2 = await otj.verifyToken<number>(testPurpose, token2, otp2)
      expect(result2).toBe(numberPayload)

      const boolPayload = true
      const { token: token3, otp: otp3 } = await otj.createToken(
        testPurpose,
        boolPayload
      )
      const result3 = await otj.verifyToken<boolean>(testPurpose, token3, otp3)
      expect(result3).toBe(boolPayload)

      const arrayPayload = [1, 2, 3, 'test']
      const { token: token4, otp: otp4 } = await otj.createToken(
        testPurpose,
        arrayPayload
      )
      const result4 = await otj.verifyToken<typeof arrayPayload>(
        testPurpose,
        token4,
        otp4
      )
      expect(result4).toEqual(arrayPayload)

      const nullPayload = null
      const { token: token5, otp: otp5 } = await otj.createToken(
        testPurpose,
        nullPayload
      )
      const result5 = await otj.verifyToken<null>(testPurpose, token5, otp5)
      expect(result5).toBeNull()
    })

    it('should handle expired tokens', async () => {
      const { token, otp } = await otj.createToken(testPurpose, testPayload, {
        expiresIn: new Date(Date.now() - 1),
      })

      expect(otj.verifyToken(testPurpose, token, otp)).rejects.toThrow()
    })
  })

  describe('Edge Cases', () => {
    let otj: OneTimeJwt

    beforeEach(() => {
      otj = new OneTimeJwt(baseSecret)
    })

    it('should handle very long OTPs', async () => {
      const { token, otp } = await otj.createToken(testPurpose, testPayload, {
        otpLength: 100,
      })

      expect(otp.length).toBe(100)
      const payload = await otj.verifyToken(testPurpose, token, otp)
      expect(payload).toEqual(testPayload)
    })

    it('should handle complex object payloads', async () => {
      const complexPayload = {
        user: {
          id: 123,
          name: 'Test User',
          roles: ['admin', 'user'],
          metadata: {
            created: new Date().toISOString(),
            preferences: {
              theme: 'dark',
              notifications: true,
            },
          },
        },
        session: {
          id: 'session-123',
          expires: new Date().toISOString(),
        },
      }

      const { token, otp } = await otj.createToken(testPurpose, complexPayload)
      const result = await otj.verifyToken(testPurpose, token, otp)

      expect(result).toEqual(complexPayload)
    })

    it('should handle special characters in purpose', async () => {
      const specialPurpose = 'test/purpose@with#special$characters&'
      const { token, otp } = await otj.createToken(specialPurpose, testPayload)

      const payload = await otj.verifyToken(specialPurpose, token, otp)
      expect(payload).toEqual(testPayload)
    })

    it('should handle special characters in OTP', async () => {
      const specialOtp = 'OTP@#$%^&*()_+'
      const { token } = await otj.createToken(
        testPurpose,
        testPayload,
        specialOtp
      )

      const payload = await otj.verifyToken(testPurpose, token, specialOtp)
      expect(payload).toEqual(testPayload)
    })
  })

  describe('Integration Tests', () => {
    it('should work with complete workflow', async () => {
      const otj = new OneTimeJwt(baseSecret, { secretDivider: '::' })

      const { token, otp } = await otj.createToken(testPurpose, testPayload, {
        otpType: 'letters-upper',
        otpLength: 10,
        expiresIn: '10m',
        issuer: 'test-issuer',
      })

      const payload = await otj.verifyToken(testPurpose, token, otp)
      expect(payload).toEqual(testPayload)

      const [safePayload, safeError] = await otj.safeVerifyToken(
        testPurpose,
        token,
        otp
      )
      expect(safePayload).toEqual(testPayload)
      expect(safeError).toBeNull()

      const [wrongPayload, wrongError] = await otj.safeVerifyToken(
        testPurpose,
        token,
        'WRONG-OTP'
      )
      expect(wrongPayload).toBeNull()
      expect(wrongError).toBeDefined()
    })

    it('should handle multiple tokens and validate correctly', async () => {
      const otj = new OneTimeJwt(baseSecret)

      const { token: token1, otp } = await otj.createToken(
        testPurpose,
        testPayload
      )
      const { token: token2 } = await otj.createToken(testPurpose, {
        ...testPayload,
        additional: 'data',
      })
      const { token: token3 } = await otj.createToken(
        'different-purpose',
        testPayload
      )

      const payload = await otj.verifyToken(
        testPurpose,
        [token1, token2, token3],
        otp
      )
      expect(payload).toEqual(testPayload)
    })
  })

  describe('Extreme Edge Cases', () => {
    let otj: OneTimeJwt

    beforeEach(() => {
      otj = new OneTimeJwt(baseSecret)
    })

    it('should handle tokens with unusual structures', async () => {
      const unusualToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid-signature.extra'
      expect(
        otj.verifyToken(testPurpose, unusualToken, '123456')
      ).rejects.toThrow(InvalidTokenError)
    })

    it('should handle extremely short expiration times', async () => {
      const { token, otp } = await otj.createToken(testPurpose, testPayload, {
        expiresIn: new Date(Date.now() - 1),
      })

      expect(otj.verifyToken(testPurpose, token, otp)).rejects.toThrow()
    })

    it('should handle tokens with missing parts', async () => {
      const incompleteToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
      expect(
        otj.verifyToken(testPurpose, incompleteToken, '123456')
      ).rejects.toThrow(InvalidTokenError)
    })

    it('should handle tokens with invalid base64 encoding', async () => {
      const invalidBase64Token = 'invalid-base64-token'
      expect(
        otj.verifyToken(testPurpose, invalidBase64Token, '123456')
      ).rejects.toThrow(InvalidTokenError)
    })

    it('should handle payloads with special characters', async () => {
      const specialCharPayload = { key: 'value@#$%^&*()_+{}|:"<>?~`' }
      const { token, otp } = await otj.createToken(
        testPurpose,
        specialCharPayload
      )
      const result = await otj.verifyToken(testPurpose, token, otp)
      expect(result).toEqual(specialCharPayload)
    })
  })
})
