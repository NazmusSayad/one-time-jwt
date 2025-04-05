import {
  UnknownError,
  InvalidOTPError,
  IncorrectOTPError,
  InvalidTokenError,
  InvalidPurposeError,
} from './errors'
import OneTimeJwt from './one-time-jwt'
import { describe, it, expect } from 'bun:test'

describe('OneTimeJwt', () => {
  const baseSecret = 'test-secret'
  const otj = new OneTimeJwt(baseSecret)

  describe('createToken', () => {
    it('should create token with default options', async () => {
      const result = await otj.createToken('test', { foo: 'bar' })
      expect(result.token).toBeTruthy()
      expect(result.otp).toBeTruthy()
      expect(result.otp.length).toBe(6)
    })

    it('should create token with custom OTP', async () => {
      const customOtp = '123456'
      const result = await otj.createToken('test', { foo: 'bar' }, customOtp)
      expect(result.token).toBeTruthy()
      expect(result.otp).toBe(customOtp)
    })

    it('should create token with custom OTP in options', async () => {
      const customOtp = '123456'
      const result = await otj.createToken(
        'test',
        { foo: 'bar' },
        { otp: customOtp }
      )
      expect(result.token).toBeTruthy()
      expect(result.otp).toBe(customOtp)
    })

    it('should create token with custom OTP type', async () => {
      const result = await otj.createToken(
        'test',
        { foo: 'bar' },
        { otpType: 'digits', otpLength: 8 }
      )
      expect(result.token).toBeTruthy()
      expect(result.otp).toMatch(/^\d{8}$/)
    })

    it('should throw InvalidPurposeError for empty purpose', async () => {
      await expect(otj.createToken('', { foo: 'bar' })).rejects.toThrow(
        InvalidPurposeError
      )
    })
  })

  describe('verifyToken', () => {
    it('should verify token with correct OTP', async () => {
      const payload = { foo: 'bar' }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })

    it('should verify token with options object', async () => {
      const payload = { foo: 'bar' }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, { otp })
      expect(result).toEqual(payload)
    })

    it('should verify multiple tokens with correct OTP', async () => {
      const payload = { foo: 'bar' }
      const { token: token1, otp } = await otj.createToken('test', payload)
      const { token: token2 } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', [token1, token2], otp)
      expect(result).toEqual(payload)
    })

    it('should throw IncorrectOTPError for wrong OTP', async () => {
      const { token } = await otj.createToken('test', { foo: 'bar' })
      await expect(otj.verifyToken('test', token, 'wrongotp')).rejects.toThrow(
        IncorrectOTPError
      )
    })

    it('should throw InvalidTokenError for invalid token', async () => {
      await expect(
        otj.verifyToken('test', 'invalid-token', '123456')
      ).rejects.toThrow()
    })
  })

  describe('safeCreateToken', () => {
    it('should safely create token and return tuple with result', async () => {
      const [result, error] = await otj.safeCreateToken('test', { foo: 'bar' })
      expect(result).toBeTruthy()
      expect(error).toBeNull()
    })

    it('should return tuple with error for invalid input', async () => {
      const [result, error] = await otj.safeCreateToken('', { foo: 'bar' })
      expect(result).toBeNull()
      expect(error).toBeInstanceOf(InvalidPurposeError)
    })
  })

  describe('safeVerifyToken', () => {
    it('should safely verify token and return tuple with result', async () => {
      const payload = { foo: 'bar' }
      const { token, otp } = await otj.createToken('test', payload)
      const [result, error] = await otj.safeVerifyToken('test', token, otp)
      expect(result).toEqual(payload)
      expect(error).toBeNull()
    })

    it('should return tuple with error for incorrect OTP', async () => {
      const { token } = await otj.createToken('test', { foo: 'bar' })
      const [result, error] = await otj.safeVerifyToken(
        'test',
        token,
        'wrongotp'
      )
      expect(result).toBeNull()
      expect(error).toBeTruthy()
    })
  })

  describe('OTP Generation', () => {
    it('should generate digits OTP', async () => {
      const result = await otj.createToken(
        'test',
        {},
        { otpType: 'digits', otpLength: 6 }
      )
      expect(result.otp).toMatch(/^\d{6}$/)
    })

    it('should generate letters OTP', async () => {
      const result = await otj.createToken(
        'test',
        {},
        { otpType: 'letters', otpLength: 6 }
      )
      expect(result.otp).toMatch(/^[a-zA-Z]{6}$/)
    })

    it('should generate alphanumeric OTP', async () => {
      const result = await otj.createToken(
        'test',
        {},
        { otpType: 'alphanumeric', otpLength: 6 }
      )
      expect(result.otp).toMatch(/^[a-zA-Z0-9]{6}$/)
    })

    it('should generate base64 OTP', async () => {
      const result = await otj.createToken(
        'test',
        {},
        { otpType: 'base64', otpLength: 6 }
      )
      expect(result.otp).toMatch(/^[A-Za-z0-9+/]{6}$/)
    })
  })

  describe('JWT Payload', () => {
    it('should include custom claims in token', async () => {
      const payload = {
        userId: '123',
        role: 'admin',
        custom: { foo: 'bar' },
      }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })

    it('should handle null values in payload', async () => {
      const payload = { nullValue: null }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })

    it('should handle nested objects in payload', async () => {
      const payload = {
        user: {
          id: '123',
          profile: {
            name: 'Test User',
            settings: {
              theme: 'dark',
            },
          },
        },
      }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })
  })

  describe('Error Cases', () => {
    it('should throw error for undefined purpose', async () => {
      // @ts-ignore - Testing runtime error
      await expect(otj.createToken(undefined, {})).rejects.toThrow()
    })

    it('should throw error for null purpose', async () => {
      // @ts-ignore - Testing runtime error
      await expect(otj.createToken(null, {})).rejects.toThrow()
    })

    it('should throw error for non-string purpose', async () => {
      // @ts-ignore - Testing runtime error
      await expect(otj.createToken(123, {})).rejects.toThrow()
    })

    it('should throw error for empty OTP', async () => {
      await expect(otj.createToken('test', {}, '')).rejects.toThrow(
        InvalidOTPError
      )
    })
  })

  describe('Secret Divider', () => {
    it('should work with custom secret divider', async () => {
      const otjWithDivider = new OneTimeJwt(baseSecret, { secretDivider: '|' })
      const payload = { foo: 'bar' }
      const { token, otp } = await otjWithDivider.createToken('test', payload)
      const result = await otjWithDivider.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })

    it('should work with empty secret divider', async () => {
      const otjWithEmptyDivider = new OneTimeJwt(baseSecret, {
        secretDivider: '',
      })
      const payload = { foo: 'bar' }
      const { token, otp } = await otjWithEmptyDivider.createToken(
        'test',
        payload
      )
      const result = await otjWithEmptyDivider.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })
  })

  describe('Performance', () => {
    it('should handle rapid token creation', async () => {
      const promises = Array.from({ length: 100 }, () =>
        otj.createToken('test', { foo: 'bar' })
      )
      const results = await Promise.all(promises)
      expect(results).toHaveLength(100)
      results.forEach((result) => {
        expect(result.token).toBeTruthy()
        expect(result.otp).toBeTruthy()
      })
    })

    it('should handle concurrent verifications', async () => {
      const { token, otp } = await otj.createToken('test', { foo: 'bar' })
      const promises = Array.from({ length: 100 }, () =>
        otj.verifyToken('test', token, otp)
      )
      const results = await Promise.all(promises)
      expect(results).toHaveLength(100)
    })
  })

  describe('Edge Cases', () => {
    it('should handle very long purposes', async () => {
      const longPurpose = 'a'.repeat(1000)
      const { token, otp } = await otj.createToken(longPurpose, { foo: 'bar' })
      const result = await otj.verifyToken(longPurpose, token, otp)
      expect(result).toEqual({ foo: 'bar' })
    })

    it('should handle very long OTPs', async () => {
      const { token, otp } = await otj.createToken(
        'test',
        { foo: 'bar' },
        { otpType: 'alphanumeric', otpLength: 100 }
      )
      expect(otp.length).toBe(100)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual({ foo: 'bar' })
    })

    it('should handle large payloads', async () => {
      const largePayload = { data: 'a'.repeat(10000) }
      const { token, otp } = await otj.createToken('test', largePayload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(largePayload)
    })
  })

  describe('Advanced Security Cases', () => {
    it('should prevent token reuse with different OTP', async () => {
      const { token: token1, otp: otp1 } = await otj.createToken('test', {
        data: 1,
      })
      const { otp: otp2 } = await otj.createToken('test', { data: 2 })
      await expect(otj.verifyToken('test', token1, otp2)).rejects.toThrow()
    })

    it('should prevent purpose tampering', async () => {
      const { token, otp } = await otj.createToken('purpose1', { data: 1 })
      await expect(otj.verifyToken('purpose2', token, otp)).rejects.toThrow()
    })

    it('should handle tokens with special characters in purpose', async () => {
      const specialPurpose = '!@#$%^&*()'
      const { token, otp } = await otj.createToken(specialPurpose, { data: 1 })
      const result = await otj.verifyToken(specialPurpose, token, otp)
      expect(result).toEqual({ data: 1 })
    })

    it('should handle unicode characters in purpose', async () => {
      const unicodePurpose = '🔑🎉💫🌟'
      const { token, otp } = await otj.createToken(unicodePurpose, { data: 1 })
      const result = await otj.verifyToken(unicodePurpose, token, otp)
      expect(result).toEqual({ data: 1 })
    })
  })

  describe('Complex Payload Scenarios', () => {
    it('should handle arrays in payload', async () => {
      const payload = {
        items: [1, 2, 3],
        nested: [{ a: 1 }, { b: 2 }, [1, 2, 3]],
      }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })

    it('should handle Date objects in payload', async () => {
      const date = new Date()
      const payload = { date: date.toISOString() }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })

    it('should handle complex nested structures', async () => {
      const payload = {
        level1: {
          level2: {
            level3: {
              level4: {
                level5: { data: 'deep' },
              },
            },
          },
        },
      }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })
  })

  describe('Concurrent Operations', () => {
    it('should handle multiple concurrent token creations with same purpose', async () => {
      const count = 50
      const results = await Promise.all(
        Array.from({ length: count }, (_, i) =>
          otj.createToken('test', { index: i })
        )
      )
      expect(results).toHaveLength(count)
      const otps = new Set(results.map((r) => r.otp))
      expect(otps.size).toBe(count) // All OTPs should be unique
    })

    it('should handle parallel verification of multiple tokens', async () => {
      const tokens = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          otj.createToken(`test-${i}`, { data: i })
        )
      )

      await Promise.all(
        tokens.map(({ token, otp }, i) =>
          otj.verifyToken(`test-${i}`, token, otp)
        )
      )
    })
  })

  describe('Error Handling and Recovery', () => {
    it('should handle rapidly changing OTPs', async () => {
      const { token } = await otj.createToken('test', { data: 1 })
      for (let i = 0; i < 100; i++) {
        const otp = 'adkfdf'
        await expect(otj.verifyToken('test', token, otp)).rejects.toThrow()
      }
    })

    it('should handle multiple invalid verification attempts', async () => {
      const { token } = await otj.createToken('test', { data: 1 })
      const attempts = Array.from({ length: 100 }, () =>
        otj.verifyToken('test', token, 'wrong-otp')
      )

      const results = await Promise.allSettled(attempts)
      expect(results.every((r) => r.status === 'rejected')).toBe(true)
    })
  })

  describe('Token Array Verification', () => {
    it('should verify first valid token in array', async () => {
      const { token: validToken, otp } = await otj.createToken('test', {
        data: 1,
      })
      const invalidTokens = Array.from({ length: 10 }, () => 'invalid-token')

      const result = await otj.verifyToken(
        'test',
        [...invalidTokens, validToken],
        otp
      )
      expect(result).toEqual({ data: 1 })
    })

    it('should handle array of mixed valid/invalid tokens', async () => {
      const { token: token1, otp } = await otj.createToken('test', { data: 1 })
      const { token: token2 } = await otj.createToken('test', { data: 2 })
      const { token: token3 } = await otj.createToken('test', { data: 3 })

      const tokens = [token1, 'invalid', token2, token3]
      const result = await otj.verifyToken('test', tokens, otp)
      expect(result).toEqual({ data: 1 })
    })
  })

  describe('Boundary Testing', () => {
    it('should handle minimum valid OTP length', async () => {
      const result = await otj.createToken('test', {}, { otpLength: 1 })
      expect(result.otp.length).toBe(1)
    })

    it('should handle maximum practical OTP length', async () => {
      const length = 1000
      const result = await otj.createToken('test', {}, { otpLength: length })
      expect(result.otp.length).toBe(length)
    })

    it('should handle empty objects in payload', async () => {
      const payload = { empty: {}, nested: { empty: {} } }
      const { token, otp } = await otj.createToken('test', payload)
      const result = await otj.verifyToken('test', token, otp)
      expect(result).toEqual(payload)
    })
  })

  describe('Performance Stress Testing', () => {
    it('should handle large number of concurrent operations', async () => {
      const operations = Array.from({ length: 1000 }, async (_, i) => {
        const { token, otp } = await otj.createToken(`test-${i}`, { data: i })
        const result = await otj.verifyToken(`test-${i}`, token, otp)
        return result
      })

      const results = await Promise.all(operations)
      expect(results).toHaveLength(1000)
    })

    it('should maintain performance with large payloads', async () => {
      const largeArray = Array.from({ length: 1000 }, (_, i) => ({
        id: i,
        data: 'x'.repeat(100),
      }))

      const { token, otp } = await otj.createToken('test', { data: largeArray })
      const result = await otj.verifyToken<{ data: typeof largeArray }>(
        'test',
        token,
        otp
      )

      expect(result.data).toHaveLength(1000)
    })
  })
})
