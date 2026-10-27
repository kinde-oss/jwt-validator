import {
  describe,
  it,
  expect,
  vi,
  beforeAll,
  beforeEach,
  afterEach,
} from "vitest";
import { validateToken } from "../main";
import * as utils from "../utils";
import type { JWKS } from "../utils";

const domain = "https://claims.kinde.com";
const kid = "test-key";

let privateKey: CryptoKey;
let jwks: JWKS;

function encode(value: object | Uint8Array): string {
  const bytes =
    value instanceof Uint8Array
      ? value
      : new TextEncoder().encode(JSON.stringify(value));
  return Buffer.from(bytes).toString("base64url");
}

async function sign(
  claims: Record<string, unknown>,
  header: Record<string, unknown> = { alg: "RS256", typ: "JWT", kid },
): Promise<string> {
  const payload = { exp: now() + 3600, ...claims };
  const data = `${encode(header)}.${encode(payload)}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(data),
  );
  return `${data}.${encode(new Uint8Array(signature))}`;
}

beforeAll(async () => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  privateKey = keyPair.privateKey;
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  jwks = {
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
});

beforeEach(() => {
  utils.JWKSCache.clear();
  utils.JWKSFetchedAt.clear();
  utils.JWKSInFlight.clear();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  vi.spyOn(utils, "getJWKS").mockResolvedValue(jwks);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const now = () => Math.floor(Date.now() / 1000);

describe("backwards compatibility", () => {
  it("ignores claims when no options are supplied", async () => {
    const token = await sign({ iss: "other", exp: now() - 3600 });
    expect(await validateToken({ token, domain })).toEqual({
      valid: true,
      message: "Token is valid",
    });
  });

  it("re-fetches the JWKS after every failed verification", async () => {
    const token = await sign({});
    const tampered = `${token.slice(0, -4)}AAAA`;
    await validateToken({ token: tampered, domain });
    await validateToken({ token: tampered, domain });
    expect(utils.getJWKS).toHaveBeenCalledTimes(3);
  });
});

describe("issuer", () => {
  it("accepts a matching issuer", async () => {
    const token = await sign({ iss: "https://claims.kinde.com" });
    const result = await validateToken({
      token,
      domain,
      issuer: "https://claims.kinde.com",
    });
    expect(result.valid).toBe(true);
  });

  it("rejects a different issuer", async () => {
    const token = await sign({ iss: "https://evil.example.com" });
    expect(
      await validateToken({
        token,
        domain,
        issuer: "https://claims.kinde.com",
      }),
    ).toEqual({ valid: false, message: "Invalid token issuer" });
  });

  it("rejects a missing issuer", async () => {
    const token = await sign({});
    const result = await validateToken({ token, domain, issuer: "expected" });
    expect(result.message).toBe("Invalid token issuer");
  });
});

describe("audience", () => {
  it("accepts a matching string audience", async () => {
    const token = await sign({ aud: "api" });
    expect(
      (await validateToken({ token, domain, audience: "api" })).valid,
    ).toBe(true);
  });

  it("accepts when the token audience array contains an expected value", async () => {
    const token = await sign({ aud: ["web", "api"] });
    expect(
      (await validateToken({ token, domain, audience: ["api", "other"] }))
        .valid,
    ).toBe(true);
  });

  it("rejects an unexpected audience", async () => {
    const token = await sign({ aud: "web" });
    expect(await validateToken({ token, domain, audience: "api" })).toEqual({
      valid: false,
      message: "Invalid token audience",
    });
  });

  it("rejects a missing audience", async () => {
    const token = await sign({});
    const result = await validateToken({ token, domain, audience: "api" });
    expect(result.message).toBe("Invalid token audience");
  });
});

describe("algorithms", () => {
  it("accepts an allowed algorithm", async () => {
    const token = await sign({});
    expect(
      (await validateToken({ token, domain, algorithms: ["RS256"] })).valid,
    ).toBe(true);
  });

  it("rejects an algorithm that is not allowed", async () => {
    const token = await sign({});
    expect(
      await validateToken({ token, domain, algorithms: ["ES256"] }),
    ).toEqual({ valid: false, message: "Unsupported signature algorithm" });
  });
});

describe("exp and nbf", () => {
  it("rejects an expired token", async () => {
    const token = await sign({ exp: now() - 10 });
    expect(await validateToken({ token, domain, clockTolerance: 0 })).toEqual({
      valid: false,
      message: "Token has expired",
    });
  });

  it("accepts an expired token within the clock tolerance", async () => {
    const token = await sign({ exp: now() - 10 });
    expect(
      (await validateToken({ token, domain, clockTolerance: 30 })).valid,
    ).toBe(true);
  });

  it("rejects a token that is not yet valid", async () => {
    const token = await sign({ nbf: now() + 10 });
    expect(await validateToken({ token, domain, clockTolerance: 0 })).toEqual({
      valid: false,
      message: "Token is not yet valid",
    });
  });

  it("accepts a not-yet-valid token within the clock tolerance", async () => {
    const token = await sign({ nbf: now() + 10 });
    expect(
      (await validateToken({ token, domain, clockTolerance: 30 })).valid,
    ).toBe(true);
  });

  it("accepts a token with future exp and past nbf", async () => {
    const token = await sign({ exp: now() + 60, nbf: now() - 60 });
    expect(
      (await validateToken({ token, domain, clockTolerance: 0 })).valid,
    ).toBe(true);
  });

  it("rejects a non-numeric exp", async () => {
    const token = await sign({ exp: "tomorrow" });
    const result = await validateToken({ token, domain, clockTolerance: 0 });
    expect(result.message).toBe("Token has expired");
  });
});

describe("JWKS re-fetch rate limit", () => {
  it("does not re-fetch on a claim failure", async () => {
    const token = await sign({ iss: "other" });
    await validateToken({ token, domain, issuer: "expected" });
    expect(utils.getJWKS).toHaveBeenCalledTimes(1);
  });

  it("does not re-fetch again within the interval", async () => {
    const token = await sign({});
    const tampered = `${token.slice(0, -4)}AAAA`;
    const options = { domain, clockTolerance: 0 };

    await validateToken({ token: tampered, ...options });
    await validateToken({ token: tampered, ...options });
    await validateToken({ token: tampered, ...options });

    expect(utils.getJWKS).toHaveBeenCalledTimes(1);
  });

  it("re-fetches once the interval has elapsed", async () => {
    const token = await sign({});
    const tampered = `${token.slice(0, -4)}AAAA`;
    const options = { domain, clockTolerance: 0 };

    await validateToken({ token: tampered, ...options });
    vi.setSystemTime(Date.now() + utils.JWKS_REFETCH_INTERVAL_MS);
    await validateToken({ token: tampered, ...options });

    expect(utils.getJWKS).toHaveBeenCalledTimes(2);
  });

  it("shares one fetch between parallel failures", async () => {
    const valid = await sign({});
    await validateToken({ token: valid, domain, clockTolerance: 0 });
    vi.setSystemTime(Date.now() + utils.JWKS_REFETCH_INTERVAL_MS + 1000);
    vi.mocked(utils.getJWKS).mockClear();
    vi.mocked(utils.getJWKS).mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(jwks), 10)),
    );

    const unknownKid = await sign({}, { alg: "RS256", typ: "JWT", kid: "x" });
    await Promise.all(
      Array.from({ length: 5 }, () =>
        validateToken({ token: unknownKid, domain, clockTolerance: 0 }),
      ),
    );

    expect(utils.getJWKS).toHaveBeenCalledTimes(1);
  });

  it("shares one fetch between parallel cold-cache calls", async () => {
    vi.mocked(utils.getJWKS).mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(jwks), 10)),
    );
    const token = await sign({});

    await Promise.all(
      Array.from({ length: 5 }, () => validateToken({ token, domain })),
    );

    expect(utils.getJWKS).toHaveBeenCalledTimes(1);
  });
});

describe("failed JWKS re-fetch", () => {
  it.each([
    ["with options", { clockTolerance: 0 }],
    ["without options", {}],
  ])("keeps the cached keys %s", async (_label, options) => {
    const valid = await sign({});
    await validateToken({ token: valid, domain, ...options });
    vi.setSystemTime(Date.now() + utils.JWKS_REFETCH_INTERVAL_MS + 1000);
    vi.mocked(utils.getJWKS).mockClear();
    vi.mocked(utils.getJWKS).mockRejectedValueOnce(new Error("network down"));

    const tampered = `${valid.slice(0, -4)}AAAA`;
    const failed = await validateToken({
      token: tampered,
      domain,
      ...options,
    });
    const afterwards = await validateToken({
      token: valid,
      domain,
      ...options,
    });

    expect(failed.valid).toBe(false);
    expect(afterwards.valid).toBe(true);
    expect(utils.getJWKS).toHaveBeenCalledTimes(1);
  });
});

describe("clockTolerance validation", () => {
  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["a negative number", -1],
    ["a string", "60" as unknown as number],
  ])("rejects %s before any JWKS work", async (_label, clockTolerance) => {
    const expired = await sign({ exp: now() - 3600 });
    const early = await sign({ nbf: now() + 3600 });

    for (const token of [expired, early]) {
      expect(await validateToken({ token, domain, clockTolerance })).toEqual({
        valid: false,
        message: "clockTolerance must be a non-negative finite number",
      });
    }
    expect(utils.getJWKS).not.toHaveBeenCalled();
  });

  it("still accepts zero and positive tolerances", async () => {
    const token = await sign({});
    expect(
      (await validateToken({ token, domain, clockTolerance: 0 })).valid,
    ).toBe(true);
    expect(
      (await validateToken({ token, domain, clockTolerance: 5 })).valid,
    ).toBe(true);
  });
});

describe("clockTolerance validation", () => {
  it.each([NaN, Infinity, -1, "60" as unknown as number])(
    "rejects clockTolerance %s",
    async (clockTolerance) => {
      const token = await sign({ exp: now() - 3600 });
      expect(await validateToken({ token, domain, clockTolerance })).toEqual({
        valid: false,
        message: "clockTolerance must be a non-negative finite number",
      });
    },
  );
});

describe("JWKS re-fetch robustness", () => {
  it("shares one re-fetch between parallel failures", async () => {
    const good = await sign({ exp: now() + 3600 });
    await validateToken({ token: good, domain, clockTolerance: 0 });
    vi.setSystemTime(Date.now() + utils.JWKS_REFETCH_INTERVAL_MS);

    const unknownKid = await sign({}, { alg: "RS256", typ: "JWT", kid: "new" });
    await Promise.all(
      Array.from({ length: 5 }, () =>
        validateToken({ token: unknownKid, domain, clockTolerance: 0 }),
      ),
    );

    expect(utils.getJWKS).toHaveBeenCalledTimes(2);
  });

  it("keeps the cached keys when a re-fetch fails", async () => {
    const good = await sign({ exp: now() + 3600 });
    await validateToken({ token: good, domain, clockTolerance: 0 });
    vi.mocked(utils.getJWKS).mockRejectedValue(new Error("network down"));
    vi.setSystemTime(Date.now() + utils.JWKS_REFETCH_INTERVAL_MS);

    const tampered = `${good.slice(0, -4)}AAAA`;
    expect(
      (await validateToken({ token: tampered, domain, clockTolerance: 0 }))
        .valid,
    ).toBe(false);
    expect(
      (await validateToken({ token: good, domain, clockTolerance: 0 })).valid,
    ).toBe(true);
    expect(utils.getJWKS).toHaveBeenCalledTimes(2);
  });
});

describe("exp requirement", () => {
  it("rejects a token without exp when options are supplied", async () => {
    const token = await sign({ iss: "x", exp: undefined });
    expect(await validateToken({ token, domain, issuer: "x" })).toEqual({
      valid: false,
      message: "Token has no exp claim",
    });
  });

  it("still accepts a token without exp when no options are supplied", async () => {
    const token = await sign({ iss: "x", exp: undefined });
    expect((await validateToken({ token, domain })).valid).toBe(true);
  });
});
