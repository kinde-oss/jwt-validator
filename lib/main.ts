// import { jwtVerify } from "jose";
import { JWKSCache, getJWKS } from "./utils";
import { jwtDecoder } from "@kinde/jwt-decoder"
export type jwtValidationResponse = {
  valid: boolean;
  message: string;
};

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
  console.log('JWKS', JSON.stringify(JWKS))
  // console.log('JWKS', jwtDecoder(JWKS)) 

  try {
    // can you make this so it doesnt use jose
    
    await jwtVerify(token, JSON.stringify(JWKS));
    return { valid: true, message: "Token is valid" };
  } catch (error) {
    if (!forceJWKSFetch) {
      return verifyJwt(token, domain, true);
    }
    return {
      valid: false,
      message: error instanceof Error ? error.message : "Unknown Error",
    };
  }
}

async function jwtVerify(token: string, jwksJson: string) {
  const [headerEncoded, payloadEncoded, signatureEncoded] = token.split(".");

  console.log("signatureEncoded", atob(headerEncoded))

  const header = JSON.parse(atob(headerEncoded));
  const kid = header.kid;

  const jwks = JSON.parse(jwksJson);
  const jwk = findJWK(jwksJson, kid);

  console.log("Found JWK:", jwk);

  if (!jwk || jwk.kty !== "RSA" || !jwk.n || !jwk.e || jwk.use !== "sig") {
    throw new Error("Invalid JWK RSA key");
  }

  const modulus = base64UrlToBigInt(jwk.n);
  const exponent = base64UrlToBigInt(jwk.e);

  if (crypto && crypto.subtle) {
    const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

    try {
      // const publicKey = await crypto.subtle.importKey(
      //   "jwk",
      //   { kty: "RSA", n: modulus, e: exponent, alg: "RS256" }, 
      //   algorithm,
      //   false,
      //   ["verify"]
      // );

      // const data = headerEncoded + "." + payloadEncoded; // Keep data as string
      // const signature = base64UrlDecode(signatureEncoded); // Decode to string

      // return await crypto.subtle.verify(algorithm, publicKey, signature, new TextEncoder().encode(data)); 
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n: modulus, e: exponent, alg: "RS256" }, 
        algorithm,
        false,
        ["verify"]
      );

      const data = headerEncoded + "." + payloadEncoded; // Keep data as string

      // Correctly decode and convert signature to ArrayBuffer
      const signatureArrayBuffer = base64UrlDecode(signatureEncoded);

      return await crypto.subtle.verify(
        algorithm,
        publicKey,
        signatureArrayBuffer, 
        new TextEncoder().encode(data)
      );
    } catch (error) {
      console.error("crypto.subtle verification error:", error);
      throw error; 
    }
  } else {
    const jsrsasign = require("jsrsasign");
    const pubKey = jsrsasign.KEYUTIL.getKey(jwk);

    try {
      const data = headerEncoded + "." + payloadEncoded; // Keep data as string
      const signature = base64UrlDecode(signatureEncoded).toString('utf8'); // Decode to string

      const isValid = jsrsasign.KJUR.jws.JWS.verifyJWT(token, pubKey, { alg: ['RS256'] });
      return isValid;
    } catch (error) {
      console.error("jsrsasign verification error:", error);
      throw error;
    }
  }
}


// Helper functions
function findJWK(jwksJson: string, kid: string) {
  const jwks = JSON.parse(jwksJson);
  for (const jwk of jwks.keys) {
    if (jwk.kid === kid) {
      return jwk;
    }
  }
  throw new Error("JWK not found");
}

function base64UrlToUint8Array(base64Url) {
  base64Url = base64Url.replace(/[^A-Za-z0-9\-\_]/g, ''); // Remove all but valid chars
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat(4 - (base64.length % 4));
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// function base64UrlToBigInt(base64Url: string) {
//   const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
//   const padding = "=".repeat(4 - (base64.length % 4));
//   const binary = atob(base64 + padding);
//   console.log('binary', binary)
//   // Convert to hex string without using BigInt constructor
//   const hex = Array.from(binary, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
//   console.log('hex', hex)
//   // Parse hex string as BigInt
//   return BigInt("0x" + hex);
// }

function base64UrlToBigInt(base64Url) {
  console.log("Input Base64URL:", base64Url);
  base64Url = base64Url.replace(/[^A-Za-z0-9\-_]/g, '');
  base64Url += Array.from({ length: (4 - base64Url.length % 4) % 4 }, () => "=").join("");
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");

  let binary;
  try {
    binary = atob(base64);
  } catch (error) {
    throw new Error("Invalid Base64 string: " + error.message);
  }

  const hex = Array.from(binary, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");

  console.log("Decoded Hex String:", hex);

  if (hex.toLowerCase() === "ffffffffffffffff" || hex.toLowerCase() === "7ff0000000000000") {
    throw new Error("Decoded value represents NaN or Infinity");
  }

  // Handle leading zeros in the hex representation
  const withoutLeadingZeros = hex.replace(/^0+/, '');
  return BigInt("0x" + withoutLeadingZeros || "0"); // Default to 0 if all zeros
}

function base64UrlDecode(base64Url: string) {
  return Uint8Array.from(atob(base64Url.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}

function hexFromBigInt(bigIntValue: string) {
  return bigIntValue.toString(16).padStart(bigIntValue.toString(2).length / 4, '0');
}


// Example usage (assuming you have a token and jwksJson):
// const token = "...your JWT token...";
// const jwksJson = "...your JWKS JSON...";

// validateToken(token, jwksJson)
//   .then(isValid => {
//     if (isValid) {
//       console.log("Token is valid!");
//       // Process validated token here
//     } else {
//       console.error("Token is invalid.");
//       // Handle invalid token
//     }
//   })
//   .catch(error => {
//     console.error("Error during validation:", error);
//     // Handle errors
//   });



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

  return await verifyJwt(validateOptions.token, validateOptions.domain);
};
