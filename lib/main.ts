// import { jwtVerify } from "jose";
import { JWKSCache, getJWKS } from "./utils";
export type jwtValidationResponse = {
  valid: boolean;
  message: string;
};
import { type RSAKey } from "jsrsasign";

// const crypto: Crypto = global.crypto;

async function verifyJwt(
  token: string,
  domain: string,
  forceJWKSFetch?: boolean,
): Promise<jwtValidationResponse> {
  if (forceJWKSFetch) {
    JWKSCache.delete(domain);
  }
  let JWKS = JWKSCache.get(domain);

  if (!JWKS) {
    JWKS = await getJWKS(domain);
    JWKSCache.set(domain, JWKS);
  }

  try {
    await jwtVerify(token, JSON.stringify(JWKS));
    return { valid: true, message: "Token is valid" };
  } catch (error: unknown) {
    if (!forceJWKSFetch) {
      return verifyJwt(token, domain, true);
    }
    return {
      valid: false,
      message: error instanceof Error ? error.message : "Unknown Error",
    };
  }
}

async function jwtVerify(token: string, jwksJson: string): Promise<boolean> {
  const [headerEncoded, payloadEncoded, signatureEncoded] = token.split(".");

  const header = JSON.parse(atob(headerEncoded));
  const kid = header.kid;

  const jwk = findJWK(jwksJson, kid);

  if (!jwk || jwk.kty !== "RSA" || !jwk.n || !jwk.e || jwk.use !== "sig") {
    throw new Error("Invalid JWK RSA key");
  }

  if (global.crypto?.subtle) {
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

      const publicKey = await global.crypto.subtle.importKey(
        "jwk",
        jwk,
        algorithm,
        true,
        ["verify"],
      );

      const data = headerEncoded + "." + payloadEncoded;

      // Correctly decode and convert signature to ArrayBuffer
      const signatureArrayBuffer = base64UrlDecode(signatureEncoded);
      const verifyResult = await global.crypto.subtle.verify(
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

    const isValid = KJUR.jws.JWS.verifyJWT(
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

export const validateToken = async (validateOptions: {
  token?: string;
  domain?: string;
}): Promise<jwtValidationResponse> => {
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

  return await verifyJwt(validateOptions.token, validateOptions.domain);
};
