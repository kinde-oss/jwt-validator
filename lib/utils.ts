export const JWKSCache: Map<string, any> = new Map<string, any>();

export async function getJWKS(domain: string) {
  const fetchResult = await fetch(`${domain}/.well-known/jwks.json`);
  const jwks = await fetchResult.json();
  return jwks;
}
