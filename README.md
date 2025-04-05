# One-Time JWT

One-Time JWT is a TypeScript library for creating and verifying one-time JSON Web Tokens (JWTs) with an associated One-Time Password (OTP). It is designed to provide secure, purpose-specific tokens for authentication and other use cases.

## Features

- Generate one-time JWTs with customizable OTPs.
- Verify JWTs using the associated OTP.
- Support for various OTP types (digits, letters, alphanumeric, base64).
- Configurable logging and token options.
- Safe methods for error handling during token creation and verification.

## Installation

Install the package using npm:

```bash
npm install one-time-jwt
```

Or using Bun:

```bash
bun add one-time-jwt
```

## Usage

### Importing the Library

```typescript
import OneTimeJwt from 'one-time-jwt'
```

### Creating a Token

```typescript
const jwt = new OneTimeJwt('baseSecret')
const result = await jwt.createToken(
  'login',
  { userId: 123 },
  { otpType: 'numeric', otpLength: 6 }
)
console.log(result.token, result.otp)
```

### Verifying a Token

```typescript
const payload = await jwt.verifyToken('login', result.token, result.otp)
console.log(payload)
```

### Safe Methods

Safe methods handle errors gracefully and return a tuple with the result or an error.

#### Safe Create Token

```typescript
const [result, error] = await jwt.safeCreateToken('login', { userId: 123 })
if (error) {
  console.error(error)
} else {
  console.log(result.token, result.otp)
}
```

#### Safe Verify Token

```typescript
const [payload, error] = await jwt.safeVerifyToken(
  'login',
  result.token,
  result.otp
)
if (error) {
  console.error(error)
} else {
  console.log(payload)
}
```

## Configuration

The `OneTimeJwt` class accepts a `baseSecret` and an optional configuration object:

```typescript
const jwt = new OneTimeJwt('baseSecret', {
  logLevel: 'debug',
  secretDivider: '::',
  maxTokenLimitPerPurpose: 5,
})
```

### Options

- `logLevel`: Logging level (`debug`, `info`, `warn`, `error`, `silent`).
- `secretDivider`: String used to separate components of the secret.
- `maxTokenLimitPerPurpose`: Maximum number of tokens allowed per purpose.

## OTP Types

The library supports the following OTP types:

- `digits`: Numeric OTP.
- `base64`: Base64 OTP.
- `letters`: Alphabetic OTP (mixed case).
- `letters-upper`: Uppercase alphabetic OTP.
- `letters-lower`: Lowercase alphabetic OTP.
- `alphanumeric`: Alphanumeric OTP (mixed case).
- `alphanumeric-upper`: Uppercase alphanumeric OTP.
- `alphanumeric-lower`: Lowercase alphanumeric OTP.

## Error Handling

The library provides custom error classes for better error handling:

- `InvalidTokenError`
- `InvalidOTPError`
- `IncorrectOTPError`
- `InvalidPurposeError`
- `UnknownError`

## Testing

Run the tests using Bun:

```bash
bun test
```

## License

This project is licensed under the MIT License.
