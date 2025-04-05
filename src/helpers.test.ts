import { describe, it, expect } from 'bun:test'
import { generateOtp } from './helpers'
import { TOtpType } from './types.type'
import { createSecretKey } from './utils'

describe('Helper Functions', () => {
  describe('generateOtp', () => {
    it('should generate OTPs with correct length', () => {
      const lengths = [1, 4, 6, 8, 10, 16, 32, 64, 128]

      for (const length of lengths) {
        const otp = generateOtp('digits', length)
        expect(otp.length).toBe(length)
      }
    })

    it('should generate digits OTP with only numbers', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('digits', 10)
        expect(/^\d+$/.test(otp)).toBe(true)
      }
    })

    it('should generate letters-upper OTP with only uppercase letters', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('letters-upper', 10)
        expect(/^[A-Z]+$/.test(otp)).toBe(true)
      }
    })

    it('should generate letters-lower OTP with only lowercase letters', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('letters-lower', 10)
        expect(/^[a-z]+$/.test(otp)).toBe(true)
      }
    })

    it('should generate letters OTP with mixed case letters', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('letters', 20)
        expect(/^[A-Za-z]+$/.test(otp)).toBe(true)
      }
    })

    it('should generate alphanumeric-upper OTP with uppercase letters and numbers', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('alphanumeric-upper', 15)
        expect(/^[A-Z0-9]+$/.test(otp)).toBe(true)
      }
    })

    it('should generate alphanumeric-lower OTP with lowercase letters and numbers', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('alphanumeric-lower', 15)
        expect(/^[a-z0-9]+$/.test(otp)).toBe(true)
      }
    })

    it('should generate alphanumeric OTP with mixed case letters and numbers', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('alphanumeric', 20)
        expect(/^[A-Za-z0-9]+$/.test(otp)).toBe(true)
      }
    })

    it('should generate base64 OTP with base64 characters', () => {
      for (let i = 0; i < 50; i++) {
        const otp = generateOtp('base64', 20)
        expect(/^[A-Za-z0-9+/]+$/.test(otp)).toBe(true)
      }
    })

    it('should verify character distribution in generated OTPs', () => {
      // Test that digits OTP has good distribution of all 10 digits
      const digitCounts: Record<string, number> = {}
      for (let i = 0; i < 1000; i++) {
        const otp = generateOtp('digits', 100)
        for (const char of otp) {
          digitCounts[char] = (digitCounts[char] || 0) + 1
        }
      }

      // Verify all digits 0-9 were used
      for (let i = 0; i <= 9; i++) {
        expect(digitCounts[i.toString()]).toBeGreaterThan(0)
      }

      // Test that letters has good distribution of letters
      const letterCounts: Record<string, number> = {}
      for (let i = 0; i < 1000; i++) {
        const otp = generateOtp('letters', 100)
        for (const char of otp) {
          letterCounts[char] = (letterCounts[char] || 0) + 1
        }
      }

      // Check that both uppercase and lowercase letters were used
      let hasUppercase = false
      let hasLowercase = false
      for (const char in letterCounts) {
        if (/[A-Z]/.test(char)) hasUppercase = true
        if (/[a-z]/.test(char)) hasLowercase = true
      }

      expect(hasUppercase).toBe(true)
      expect(hasLowercase).toBe(true)
    })

    it('should throw error for invalid OTP type', () => {
      expect(() => {
        // @ts-expect-error - Testing invalid type
        generateOtp('invalid-type', 6)
      }).toThrow('Invalid OTP type')
    })

    it('should generate different OTPs on subsequent calls', () => {
      const otps = new Set<string>()
      for (let i = 0; i < 100; i++) {
        const otp = generateOtp('alphanumeric', 10)
        otps.add(otp)
      }

      // All OTPs should be unique (or extremely close to unique)
      // Small chance of collision, so we test that at least 95 are unique
      expect(otps.size).toBeGreaterThan(95)
    })

    it('should test all OTP types with various lengths', () => {
      const otpTypes: TOtpType[] = [
        'base64',
        'digits',
        'letters',
        'letters-upper',
        'letters-lower',
        'alphanumeric',
        'alphanumeric-upper',
        'alphanumeric-lower',
      ]

      const lengths = [4, 6, 8, 16, 32]

      for (const type of otpTypes) {
        for (const length of lengths) {
          const otp = generateOtp(type, length)

          // Verify correct length
          expect(otp.length).toBe(length)

          // Verify correct character set based on type
          if (type === 'digits') {
            expect(/^\d+$/.test(otp)).toBe(true)
          } else if (type === 'letters-upper') {
            expect(/^[A-Z]+$/.test(otp)).toBe(true)
          } else if (type === 'letters-lower') {
            expect(/^[a-z]+$/.test(otp)).toBe(true)
          } else if (type === 'letters') {
            expect(/^[A-Za-z]+$/.test(otp)).toBe(true)
          } else if (type === 'alphanumeric-upper') {
            expect(/^[A-Z0-9]+$/.test(otp)).toBe(true)
          } else if (type === 'alphanumeric-lower') {
            expect(/^[a-z0-9]+$/.test(otp)).toBe(true)
          } else if (type === 'alphanumeric') {
            expect(/^[A-Za-z0-9]+$/.test(otp)).toBe(true)
          } else if (type === 'base64') {
            expect(/^[A-Za-z0-9+/]+$/.test(otp)).toBe(true)
          }
        }
      }
    })
  })

  describe('createSecretKey', () => {
    it('should convert string to Uint8Array', () => {
      const secret = 'test-secret'
      const key = createSecretKey(secret)

      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.length).toBe(new TextEncoder().encode(secret).length)
    })

    it('should handle empty string', () => {
      const key = createSecretKey('')
      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.length).toBe(0)
    })

    it('should handle special characters', () => {
      const specialChars = 'áéíóúñü@#$%^&*()_+=-[]{}|;:,.<>/?'
      const key = createSecretKey(specialChars)

      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.length).toBe(new TextEncoder().encode(specialChars).length)
    })

    it('should handle very long strings', () => {
      // Create a 10KB string
      const longString = 'a'.repeat(10 * 1024)
      const key = createSecretKey(longString)

      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.length).toBe(longString.length)
    })

    it('should create different keys for different inputs', () => {
      const key1 = createSecretKey('secret1')
      const key2 = createSecretKey('secret2')

      // Keys should be different
      let isDifferent = false
      for (let i = 0; i < key1.length; i++) {
        if (key1[i] !== key2[i]) {
          isDifferent = true
          break
        }
      }

      expect(isDifferent).toBe(true)
    })
  })
})
