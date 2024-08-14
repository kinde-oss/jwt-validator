export const JWKSCache: Map<string, any> = new Map<string, any>();

interface JWK {
  e: string; // Exponent (e.g., "AQAB")
  n: string; // Modulus (long Base64 encoded string)
  alg: string; // Algorithm (e.g., "RS256")
  kid: string; // Key ID (unique identifier for the key)
  kty: string; // Key Type (e.g., "RSA")
  use: string; // Usage (e.g., "sig" for signatures)
}

export interface JWKS {
  keys: JWK[]; // Array of JWK objects
}

export async function getJWKS(domain: string): Promise<JWKS> {
  const maxRetries = 3;
  let attempts = 0;
  while (attempts < maxRetries) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    try {
      const fetchResult = await fetch(`${domain}/.well-known/jwks.json`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!fetchResult.ok) {
        throw new Error(
          `Failed to fetch JWKS: ${fetchResult.status} ${fetchResult.statusText}`,
        );
      }
      return await fetchResult.json();
    } catch (error) {
      attempts++;
      console.error(`Attempt ${attempts} - Error fetching JWKS:`, error);
    }
  }
  throw new Error("Failed to fetch JWKS after multiple retries");
}
