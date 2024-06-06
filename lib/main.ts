import { jwtVerify } from "jose";
import { JWKSCache, getJWKS } from "./utils";

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
    JWKS = getJWKS(domain);
    JWKSCache.set(domain, JWKS);
  }

  try {
    await jwtVerify(token, JWKS);
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
