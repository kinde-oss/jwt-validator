import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSign, generateKeyPairSync } from "node:crypto";
import { validateToken } from "../main";
import * as utils from "../utils";

const domain = "https://claims-nocrypto.kinde.com";
const kid = "test-key";
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const publicJwk = publicKey.export({ format: "jwk" });
const jwks = {
  keys: [
    {
      kid,
      kty: "RSA",
      use: "sig",
      alg: "RS256",
      n: publicJwk.n!,
      e: publicJwk.e!,
    },
  ],
};

const encode = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function sign(payload: Record<string, unknown>): string {
  const data = `${encode({ alg: "RS256", typ: "JWT", kid })}.${encode(payload)}`;
  const signature = createSign("RSA-SHA256").update(data).sign(privateKey);
  return `${data}.${signature.toString("base64url")}`;
}

const now = () => Math.floor(Date.now() / 1000);

describe("claim checks on the jsrsasign fallback path", () => {
  beforeEach(() => {
    vi.stubGlobal("crypto", undefined);
    utils.JWKSCache.clear();
    utils.JWKSFetchedAt.clear();
    utils.JWKSInFlight.clear();
    vi.spyOn(utils, "getJWKS").mockResolvedValue(jwks);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("applies clockTolerance to exp", async () => {
    const token = sign({ exp: now() - 10 });
    expect(
      (await validateToken({ token, domain, clockTolerance: 30 })).valid,
    ).toBe(true);
    expect(await validateToken({ token, domain, clockTolerance: 0 })).toEqual({
      valid: false,
      message: "Token has expired",
    });
  });

  it("checks the issuer after the signature", async () => {
    const token = sign({ iss: "other", exp: now() + 60 });
    expect(await validateToken({ token, domain, issuer: "expected" })).toEqual({
      valid: false,
      message: "Invalid token issuer",
    });
  });
});
