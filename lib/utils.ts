import { createRemoteJWKSet } from "jose";

export const JWKSCache: Map<string, any> = new Map<string, any>();

export  async function getJWKS(domain: string) {
  const fetchResult = await fetch(`${domain}/.well-known/jwks.json`)
  const jwks = await fetchResult.json();
  return jwks;

  // return createRemoteJWKSet(new URL(`${domain}/.well-known/jwks.json`));
}




// export async function jwtVerify(jwt, key, options) {
//   const verified = await compactVerify(jwt, key, options);
//   if (verified.protectedHeader.crit?.includes('b64') && verified.protectedHeader.b64 === false) {
//       throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
//   }
//   const payload = jwtPayload(verified.protectedHeader, verified.payload, options);
//   const result = { payload, protectedHeader: verified.protectedHeader };
//   if (typeof key === 'function') {
//       return { ...result, key: verified.key };
//   }
//   return result;
// }

// export async function compactVerify(jws, key, options) {
//   if (jws instanceof Uint8Array) {
//       jws = decoder.decode(jws);
//   }
//   if (typeof jws !== 'string') {
//       throw new JWSInvalid('Compact JWS must be a string or Uint8Array');
//   }
//   const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');
//   if (length !== 3) {
//       throw new JWSInvalid('Invalid Compact JWS');
//   }
//   const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
//   const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
//   if (typeof key === 'function') {
//       return { ...result, key: verified.key };
//   }
//   return result;
// }
