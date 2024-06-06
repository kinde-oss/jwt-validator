import { createRemoteJWKSet } from "jose";

export const JWKSCache: Map<string, any> = new Map<string, any>();

export function getJWKS(domain: string) {
  return createRemoteJWKSet(new URL(`${domain}/.well-known/jwks.json`));
}
