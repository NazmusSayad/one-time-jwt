import {
  UnknownError,
  InvalidOTPError,
  IncorrectOTPError,
  InvalidTokenError,
  InvalidPurposeError,
} from './errors'
import OneTimeJwt from './one-time-jwt'
import { describe, it, expect } from 'bun:test'

const baseSecret = 'test-secret'
const otj = new OneTimeJwt(baseSecret)
