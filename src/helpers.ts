import { TOtpType } from './types.type'

export function generateNumberOTP(length: number) {
  return Array.from({ length }, () => Math.floor(Math.random() * 10)).join('')
}

export function generateStringOTP(chars: string, length: number) {
  return Array.from(
    { length },
    () => chars[Math.floor(Math.random() * chars.length)]
  ).join('')
}

export function generateAlphanumericOTP(length: number) {
  return generateStringOTP(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    length
  )
}

export function generateBase64OTP(length: number) {
  return generateStringOTP(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    length
  )
}

export function generateLetterOtp(length: number) {
  return generateStringOTP(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    length
  )
}

export function generateOtp(type: TOtpType, length: number): string {
  if (type === 'digits') {
    return generateNumberOTP(length)
  } else if (type === 'letters') {
    return generateLetterOtp(length)
  } else if (type === 'alphanumeric') {
    return generateAlphanumericOTP(length)
  } else if (type === 'base64') {
    return generateBase64OTP(length)
  } else {
    throw new Error('Invalid OTP type')
  }
}
