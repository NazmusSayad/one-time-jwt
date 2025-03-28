import { SignJWT, jwtVerify, JWTPayload } from 'jose'
import { TSignOptions, TVerifyOptions } from './types.type'

export async function signJwt(payload: JWTPayload, options: TSignOptions) {
  let jwt = new SignJWT(payload)
    .setIssuedAt(options.issuedAt)
    .setExpirationTime(options.expiresIn ?? '600s')
    .setProtectedHeader({ alg: options.algorithm ?? 'HS256' })

  if (options.audience) {
    jwt = jwt.setAudience(options.audience)
  }

  if (options.issuer) {
    jwt = jwt.setIssuer(options.issuer)
  }

  if (options.subject) {
    jwt = jwt.setSubject(options.subject)
  }

  if (options.notBefore) {
    jwt = jwt.setNotBefore(options.notBefore)
  }

  if (options.jti) {
    jwt = jwt.setJti(options.jti)
  }

  if (options.protectedHeader) {
    jwt = jwt.setProtectedHeader(options.protectedHeader)
  }

  return await jwt.sign(options.secret)
}

export async function verifyJwt(
  jwt: string,
  { secret, ...options }: TVerifyOptions
) {
  const parsed = await jwtVerify(jwt, secret, { ...options })
  return parsed.payload as JWTPayload
}
