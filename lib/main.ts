// import { jwtVerify } from "jose";
import {
  JWKSCache,
  JWKSFetchedAt,
  JWKSInFlight,
  JWKS_REFETCH_INTERVAL_MS,
  getCryptoLib,
  getJWKS,
  type JWKS,
} from "./utils";
export type jwtValidationResponse = {
  valid: boolean;
  message: string;
};
export type jwtValidationOptions = {
  issuer?: string;
  audience?: string | string[];
  clockTolerance?: number;
  algorithms?: string[];
};
import type { RSAKey } from "jsrsasign";

// const crypto: Crypto = global.crypto;

function hasValidationOptions(options: jwtValidationOptions): boolean {
  return (
    options.issuer !== undefined ||
    options.audience !== undefined ||
    options.clockTolerance !== undefined ||
    options.algorithms !== undefined
  );
}

function canRefetchJWKS(domain: string): boolean {
  const fetchedAt = JWKSFetchedAt.get(domain);
  return (
    fetchedAt === undefined ||
    Date.now() - fetchedAt >= JWKS_REFETCH_INTERVAL_MS
  );
}

async function loadJWKS(domain: string, force: boolean): Promise<JWKS> {
  const cached: JWKS | undefined = JWKSCache.get(domain);
  if (cached && !force) {
    return cached;
  }

  const inFlight = JWKSInFlight.get(domain);
  if (inFlight) {
    return inFlight;
  }

  const request = getJWKS(domain)
    .then((fetched) => {
      JWKSCache.set(domain, fetched);
      return fetched;
    })
    .catch((error: unknown) => {
      if (cached) {
        return cached;
      }
      throw error;
    })
    .finally(() => {
      JWKSFetchedAt.set(domain, Date.now());
      JWKSInFlight.delete(domain);
    });
  JWKSInFlight.set(domain, request);
  return request;
}

async function verifyJwt(
  token: string,
  domain: string,
  options: jwtValidationOptions,
  forceJWKSFetch?: boolean,
): Promise<jwtValidationResponse> {
  const optedIn = hasValidationOptions(options);

  const jwks = await loadJWKS(domain, forceJWKSFetch === true);

  try {
    await jwtVerify(token, JSON.stringify(jwks), optedIn);
  } catch (error: unknown) {
    if (!forceJWKSFetch && (!optedIn || canRefetchJWKS(domain))) {
      return verifyJwt(token, domain, options, true);
    }
    return {
      valid: false,
      message: error instanceof Error ? error.message : "Unknown Error",
    };
  }

  if (optedIn) {
    try {
      validateClaims(token, options);
    } catch (error: unknown) {
      return {
        valid: false,
        message: error instanceof Error ? error.message : "Unknown Error",
      };
    }
  }
  return { valid: true, message: "Token is valid" };
}

function validateClaims(token: string, options: jwtValidationOptions): void {
  const [headerEncoded, payloadEncoded] = token.split(".");
  const header = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(headerEncoded)),
  );
  const payload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(payloadEncoded)),
  );

  if (options.algorithms && !options.algorithms.includes(header.alg)) {
    throw new Error("Unsupported signature algorithm");
  }

  if (options.issuer !== undefined && payload.iss !== options.issuer) {
    throw new Error("Invalid token issuer");
  }

  if (options.audience !== undefined) {
    const expected = Array.isArray(options.audience)
      ? options.audience
      : [options.audience];
    const actual = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!actual.some((aud: unknown) => expected.includes(aud as string))) {
      throw new Error("Invalid token audience");
    }
  }

  const now = Math.floor(Date.now() / 1000);
  const tolerance = options.clockTolerance ?? 0;

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number" || now - tolerance >= payload.exp) {
      throw new Error("Token has expired");
    }
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number" || now + tolerance < payload.nbf) {
      throw new Error("Token is not yet valid");
    }
  }
}

async function jwtVerify(
  token: string,
  jwksJson: string,
  signatureOnly = false,
): Promise<boolean> {
  const [headerEncoded, payloadEncoded, signatureEncoded] = token.split(".");

  const header = JSON.parse(atob(headerEncoded));
  const kid = header.kid;

  const jwk = findJWK(jwksJson, kid);

  if (!jwk || jwk.kty !== "RSA" || !jwk.n || !jwk.e || jwk.use !== "sig") {
    throw new Error("Invalid JWK RSA key");
  }

  const crypto = getCryptoLib();
  if (crypto?.subtle) {
    const modulus = base64UrlToBigInt(jwk.n);
    const exponent = base64UrlToBigInt(jwk.e);
    const algorithm = {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" },
    };

    try {
      const jwk = {
        kty: "RSA",
        n: bigintToBase64url(modulus),
        e: bigintToBase64url(exponent),
        alg: "RS256",
      } as JsonWebKey;

      const publicKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        algorithm,
        true,
        ["verify"],
      );

      const data = headerEncoded + "." + payloadEncoded;

      // Correctly decode and convert signature to ArrayBuffer
      const signatureArrayBuffer = base64UrlDecode(signatureEncoded);
      const verifyResult = await crypto.subtle.verify(
        algorithm,
        publicKey,
        signatureArrayBuffer,
        new TextEncoder().encode(data),
      );
      if (!verifyResult) {
        throw new Error("Signature verification failed");
      }
      return verifyResult;
    } catch (error) {
      throw error;
    }
  } else {
    const { KJUR, KEYUTIL, b64utoutf8 } = await import("jsrsasign");
    const header = JSON.parse(b64utoutf8(headerEncoded));
    if (header.alg !== "RS256") {
      // Or your specific algorithm (e.g., HS256)
      throw new Error("Unsupported signature algorithm: " + header);
    }
    const pubKey = KEYUTIL.getKey(jwk) as RSAKey;

    const isValid = signatureOnly
      ? KJUR.jws.JWS.verify(token, pubKey, ["RS256"])
      : KJUR.jws.JWS.verifyJWT(
          token,
          pubKey,
          { alg: ["RS256"] }, // Adjust if using a different algorithm
        );
    if (!isValid) {
      throw new Error("Signature verification failed");
    }
    return true;
  }
}

function bigintToBase64url(value: bigint): string {
  // Convert bigint to a hex string
  let hex = value.toString(16);
  // Ensure even number of characters (pad with 0 if necessary)
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  // Convert hex to Uint8Array
  const byteArray = new Uint8Array(
    hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
  );
  // Convert Uint8Array to base64
  const base64 = btoa(String.fromCharCode.apply(null, Array.from(byteArray)));
  // Convert base64 to base64url
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Helper functions
function findJWK(jwksJson: string, kid: string) {
  const jwks = JSON.parse(jwksJson);
  for (const jwk of jwks.keys) {
    if (jwk.kid === kid) {
      return jwk;
    }
  }
  throw new Error(`JWK not found${kid ? ` for kid ${kid}` : ""}`);
}

function base64UrlToBigInt(base64Url: string) {
  base64Url = base64Url.replace(/[^A-Za-z0-9\-_]/g, "");
  base64Url += Array.from(
    { length: (4 - (base64Url.length % 4)) % 4 },
    () => "=",
  ).join("");
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");

  let binary;
  try {
    binary = atob(base64);
  } catch (error: unknown) {
    throw new Error("Invalid Base64 string: " + (error as Error).message);
  }

  const hex = Array.from(binary, (c) =>
    c.charCodeAt(0).toString(16).padStart(2, "0"),
  ).join("");

  if (
    hex.toLowerCase() === "ffffffffffffffff" ||
    hex.toLowerCase() === "7ff0000000000000"
  ) {
    throw new Error("Decoded value represents NaN or Infinity");
  }

  // Handle leading zeros in the hex representation
  const withoutLeadingZeros = hex.replace(/^0+/, "");
  return BigInt("0x" + withoutLeadingZeros || "0"); // Default to 0 if all zeros
}

function base64UrlDecode(base64Url: string) {
  return Uint8Array.from(
    atob(base64Url.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );
}

export const validateToken = async (
  validateOptions: {
    token?: string;
    domain?: string;
  } & jwtValidationOptions,
): Promise<jwtValidationResponse> => {
  if (!validateOptions.token) {
    return { valid: false, message: "Token is required" };
  }

  if (!validateOptions.domain) {
    return { valid: false, message: "Domain is required" };
  }

  const jwtParts = validateOptions.token.split(".");
  if (jwtParts.length !== 3) {
    return { valid: false, message: "Invalid JWT format" };
  }

  const { token, domain, ...options } = validateOptions;
  const { clockTolerance } = options;
  if (
    clockTolerance !== undefined &&
    (typeof clockTolerance !== "number" ||
      !Number.isFinite(clockTolerance) ||
      clockTolerance < 0)
  ) {
    return {
      valid: false,
      message: "clockTolerance must be a non-negative finite number",
    };
  }
  return await verifyJwt(token, domain, options);
};
