export const JWKSCache: Map<string, any> = new Map<string, any>();

export async function getJWKS(domain: string) {
  try {
    const fetchResult = await fetch(`${domain}/.well-known/jwks.json`);
    if (!fetchResult.ok) {
      throw new Error(`Failed to fetch JWKS: ${fetchResult.status} ${fetchResult.statusText}`);
    }
    const jwks = await fetchResult.json();
  } catch (error) {
    console.error('Error fetching JWKS:', error);
    throw error; // Rethrow or handle as needed
  }
}
}
