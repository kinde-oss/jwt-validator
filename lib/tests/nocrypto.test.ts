import { describe, it, expect, vi, beforeAll } from "vitest";
import { createHmac } from "crypto";
import { validateToken } from "../main";

function base64UrlEncode(str: string) {
  return Buffer.from(str)
    .toString("base64")
    .replace("+", "-")
    .replace("/", "_")
    .replace(/=+$/, "");
}

function jwtSign({
  header,
  payload,
  secret,
}: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  secret: string;
}) {
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  const signature = createHmac("sha256", secret)
    .update(encodedHeader + "." + encodedPayload)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return encodedHeader + "." + encodedPayload + "." + signature;
}

vi.stubGlobal("crypto", undefined);
Object.defineProperty(global, "crypto", {
  value: undefined, // Set to undefined to 'clear' crypto
  writable: true, // Allow the property to be rewritten later if needed
  configurable: true, // Allow the property definition itself to be changed, enabling resetting in teardown
});

describe("Validate token no crypto", () => {
  beforeAll(() => {
    if (typeof global !== "undefined" && global.crypto) {
      // Use Object.defineProperty to redefine the 'crypto' property
      Object.defineProperty(global, "crypto", {
        value: undefined, // Set to undefined to 'clear' crypto
        writable: true, // Allow the property to be rewritten later if needed
        configurable: true, // Allow the property definition itself to be changed, enabling resetting in teardown
      });
    }
    //@ts-ignore
    global.crypto = undefined;
    // vi.mock('crypto', () => undefined);
  });

  it("mocks the crypto API being unavailable", () => {
    // Mock the global object to remove the crypto property

    vi.stubGlobal("crypto", undefined);

    // Code that uses the crypto API
    const isCryptoAvailable = !!global.crypto;

    expect(isCryptoAvailable).toBe(false);
  });

  it("no token supplied", async () => {
    const isTokenValid = await validateToken({});
    expect(isTokenValid).toEqual({
      valid: false,
      message: "Token is required",
    });
  });

  it("no domain supplied", async () => {
    const token = jwtSign({
      header: { alg: "HS256", typ: "JWT" },
      payload: { sub: "1234567890", name: "John Doe", iat: 1516239022 },
      secret: "your-256-bit-secret",
    });
    const isTokenValid = await validateToken({ token });
    expect(isTokenValid).toEqual({
      valid: false,
      message: "Domain is required",
    });
  });

  it("token is valid", async () => {
    const token =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRjOmZhOjllOmQ2OjQ3OjIzOmI3OjM5OmM3OjhmOjk3OjI4OjQ1OmExOjg0OjM1IiwidHlwIjoiSldUIn0.eyJkYXRhIjp7InVzZXIiOnsiZW1haWwiOiJkYW5pZWxAa2luZGUuY29tIiwiZmlyc3RfbmFtZSI6IkRhbmllbCIsImlkIjoia3BfNjViMjhkNzFiYmExNGZhMzgwZDU2ZDJkOGQzNTAzZGEiLCJpc19wYXNzd29yZF9yZXNldF9yZXF1ZXN0ZWQiOmZhbHNlLCJpc19zdXNwZW5kZWQiOmZhbHNlLCJsYXN0X25hbWUiOiJSaXZlcnMiLCJvcmdhbml6YXRpb25zIjpbeyJjb2RlIjoib3JnXzU5MGQ3ZjFhODZhIiwicGVybWlzc2lvbnMiOm51bGwsInJvbGVzIjpudWxsfV0sInBob25lIjpudWxsLCJ1c2VybmFtZSI6ImRhbmllbCJ9fSwiZXZlbnRfaWQiOiJldmVudF8wMThmMzMxYTMxNzhmN2ZlZjI4NGI5NWZlNjc3MDM4NCIsInNvdXJjZSI6ImFkbWluIiwidGltZXN0YW1wIjoiMjAyNC0wNS0wMVQxNzo0MTo0NS41OTIxNDUrMTA6MDAiLCJ0eXBlIjoidXNlci51cGRhdGVkIn0.hAxfcxDNnzN8_U7sovti71NElh5pqVe6UEFKgVD1ZygVJUdEhmjYQOOSr6Aixj2ySs_hujZBvCRWeqG6jNPYbHRiV5kx0XaL6g3cW1DCoqpTpkxXtjf18HNYHCJmsUqMiSwfYpmVcI7kaIDfd0XwhWWH5gRdjAAMDneEwMKANklTzR_g_kIl5cVW5eVWntC4rFsSjRVvGSNb-OMsy2GJLWXUF8fc8Qru56VkJImeOE6ZOMi6wBhtx7HhOZEcEFgQjRvHeoQKdVmEE3BRUnO_LXTMMSjvP_kyfrS4JMaGWHc6mc8k1hZo_maASLSuXMF8882LZnr96cJFMHj8irRAug";
    const isTokenValid = await validateToken({
      token,
      domain: "https://danielkinde.kinde.com",
    });
    expect(isTokenValid).toEqual({
      valid: true,
      message: "Token is valid",
    });
  });

  it("token has invalid signature", async () => {
    const token =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRjOmZhOjllOmQ2OjQ3OjIzOmI3OjM5OmM3OjhmOjk3OjI4OjQ1OmExOjg0OjM1IiwidHlwIjoiSldUIn0.eyJkYXRhIjp7InVzZXIiOnsiZW1haWwiOiJtZSt3ZWJvb2tAZGFuaWVscml2ZXJzLmNvbSIsImZpcnN0X25hbWUiOiJhYSIsImlkIjoia3BfYmM2YjI4MTczZDZkNGRmYWI1NjU3NTg4NWIwMjE0YjEiLCJpc19wYXNzd29yZF9yZXNldF9yZXF1ZXN0ZWQiOmZhbHNlLCJpc19zdXNwZW5kZWQiOmZhbHNlLCJsYXN0X25hbWUiOiJhaGEiLCJvcmdhbml6YXRpb25zIjpbeyJjb2RlIjoib3JnXzU5MGQ3ZjFhODZhIiwicGVybWlzc2lvbnMiOm51bGwsInJvbGVzIjpudWxsfV0sInBob25lIjpudWxsLCJ1c2VybmFtZSI6bnVsbH19LCJldmVudF9pZCI6ImV2ZW50XzAxOGYyYTllNTkyZWNjZjUyMzI5MTgzYTQ1Y2QxOTU2Iiwic291cmNlIjoiYWRtaW4iLCJ0aW1lc3RhbXAiOiIyMDI0LTA0LTMwVDAyOjA5OjMxLjY0OTE2MisxMDowMCIsInR5cGUiOiJ1c2VyLnVwZGF0ZWQifQ.YIFd21Ek7R_hfpfEpAcwW5ebaDSDsT7TMYF5HTbg70CfWw36IDqKqQWKR6T1_vP0lI5s0xJlDptbjykvWfSm44fkz0LgjCWQhM_ENzTZiAa89pa2X1prjKH4vyS7lTqSCNXvCeYiAaFZSlr2X3s2aztASB4jGBDETziGCh_klNh4Gun3AcbkWOXz_QPm3YGNqgc3hYSBsLdOQbCQ_BxS2Wc60D3NAShVaodPrtOLC1bvY1vn_HucZHT9l-KuTKgY1st6D4er2K6DuHZaFBMMdvTaFQX5zN8OZltxeiucja4sg2vbtexryMdSdHY3y5Cz70dKWW6Ph2kHucK6xScQoQs";
    const isTokenValid = await validateToken({
      token,
      domain: "https://danielkinde.kinde.com",
    });
    expect(isTokenValid).toEqual({
      valid: false,
      message: "Signature verification failed",
    });
  });

  it("token is present but not valid", async () => {
    const token = jwtSign({
      header: { alg: "HS256", typ: "JWT" },
      payload: { sub: "1234567890", name: "John Doe", iat: 1516239022 },
      secret: "your-256-bit-secret",
    });

    const isTokenValid = await validateToken({
      token,
      domain: "https://danielkinde.kinde.com",
    });
    expect(isTokenValid).toEqual({
      valid: false,
      message: "JWK not found",
    });
  });
});
