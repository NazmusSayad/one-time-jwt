import OneTimeJwt from './one-time-jwt'

const otj = new OneTimeJwt('hello world', { logLevel: 'debug' })

;(async () => {
  otj.verifyToken('testPurpose', 'invalid-base64-token', 'otp')
})()
