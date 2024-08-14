// setToken.test.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { validateToken } from "../main";
import * as utils from "../utils";
import { JWKS } from "../utils";
import createFetchMock from "vitest-fetch-mock";
const fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

vi.mock("./utils");
describe("Generic tests", () => {
  beforeEach(() => {
    vi.spyOn(utils, "getJWKS").mockReturnValue(
      Promise.resolve({
        keys: [
          {
            alg: "RS256",
            e: "AQAB",
            kid: "4c:fa:9e:d6:47:23:b7:39:c7:8f:97:28:45:a1:84:35",
            kty: "BOB",
            n: "v7J7",
          },
        ],
      } as JWKS),
    );
  });
  it("Invalid JWK RSA key", async () => {
    const isTokenValid = await validateToken({
      token:
        "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRjOmZhOjllOmQ2OjQ3OjIzOmI3OjM5OmM3OjhmOjk3OjI4OjQ1OmExOjg0OjM1IiwidHlwIjoiSldUIn0.eyJkYXRhIjp7InVzZXIiOnsiZW1haWwiOiJkYW5pZWxAa2luZGUuY29tIiwiZmlyc3RfbmFtZSI6IkRhbmllbCIsImlkIjoia3BfNjViMjhkNzFiYmExNGZhMzgwZDU2ZDJkOGQzNTAzZGEiLCJpc19wYXNzd29yZF9yZXNldF9yZXF1ZXN0ZWQiOmZhbHNlLCJpc19zdXNwZW5kZWQiOmZhbHNlLCJsYXN0X25hbWUiOiJSaXZlcnMiLCJvcmdhbml6YXRpb25zIjpbeyJjb2RlIjoib3JnXzU5MGQ3ZjFhODZhIiwicGVybWlzc2lvbnMiOm51bGwsInJvbGVzIjpudWxsfV0sInBob25lIjpudWxsLCJ1c2VybmFtZSI6ImRhbmllbCJ9fSwiZXZlbnRfaWQiOiJldmVudF8wMThmMzMxYTMxNzhmN2ZlZjI4NGI5NWZlNjc3MDM4NCIsInNvdXJjZSI6ImFkbWluIiwidGltZXN0YW1wIjoiMjAyNC0wNS0wMVQxNzo0MTo0NS41OTIxNDUrMTA6MDAiLCJ0eXBlIjoidXNlci51cGRhdGVkIn0.hAxfcxDNnzN8_U7sovti71NElh5pqVe6UEFKgVD1ZygVJUdEhmjYQOOSr6Aixj2ySs_hujZBvCRWeqG6jNPYbHRiV5kx0XaL6g3cW1DCoqpTpkxXtjf18HNYHCJmsUqMiSwfYpmVcI7kaIDfd0XwhWWH5gRdjAAMDneEwMKANklTzR_g_kIl5cVW5eVWntC4rFsSjRVvGSNb-OMsy2GJLWXUF8fc8Qru56VkJImeOE6ZOMi6wBhtx7HhOZEcEFgQjRvHeoQKdVmEE3BRUnO_LXTMMSjvP_kyfrS4JMaGWHc6mc8k1hZo_maASLSuXMF8882LZnr96cJFMHj8irRAug",
      domain: "https://danielkinde.kinde.com",
    });
    expect(isTokenValid).toEqual({
      valid: false,
      message: "Invalid JWK RSA key",
    });
  });

  it("Incomplete token", async () => {
    const isTokenValid = await validateToken({
      token:
        "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRjOmZhOjllOmQ2OjQ3OjIzOmI3OjM5OmM3OjhmOjk3OjI4OjQ1OmExOjg0OjM1IiwidHlwIjoiSldUIn0.hAxfcxDNnzN8_U7sovti71NElh5pqVe6UEFKgVD1ZygVJUdEhmjYQOOSr6Aixj2ySs_hujZBvCRWeqG6jNPYbHRiV5kx0XaL6g3cW1DCoqpTpkxXtjf18HNYHCJmsUqMiSwfYpmVcI7kaIDfd0XwhWWH5gRdjAAMDneEwMKANklTzR_g_kIl5cVW5eVWntC4rFsSjRVvGSNb-OMsy2GJLWXUF8fc8Qru56VkJImeOE6ZOMi6wBhtx7HhOZEcEFgQjRvHeoQKdVmEE3BRUnO_LXTMMSjvP_kyfrS4JMaGWHc6mc8k1hZo_maASLSuXMF8882LZnr96cJFMHj8irRAug",
      domain: "https://danielkinde.kinde.com",
    });
    expect(isTokenValid).toEqual({
      valid: false,
      message: "Invalid JWT format",
    });
  });
});
