import { createRemoteJWKSet, jwtVerify } from "jose";

export type jwtValidationResponse = {
  valid: boolean;
  message: string;
};

async function verifyJwt(
  token: string,
  domain: string,
): Promise<jwtValidationResponse> {
  const JWKS = createRemoteJWKSet(new URL(`${domain}/.well-known/jwks.json`));

  try {
    await jwtVerify(token, JWKS);
    return { valid: true, message: "Token is valid" };
  } catch (error) {
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
