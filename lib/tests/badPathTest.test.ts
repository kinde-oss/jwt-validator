// setToken.test.ts
import { describe, it, vi, expect } from "vitest";
import { getJWKS } from "../utils";
import createFetchMock from "vitest-fetch-mock";
const fetchMocker = createFetchMock(vi);
fetchMocker.enableMocks();

describe("Generic tests", () => {
  it("fail to load jwks", async () => {
    fetchMocker.mockReject();
    expect(() => getJWKS("https://danielkinde.kinde.com")).rejects.toThrowError(
      "Failed to fetch JWKS after multiple retries",
    );
  });

  it("fetch bad response", async () => {
    fetchMocker.mockResponses([
      "",
      {
        status: 500,
      },
    ]);
    expect(() => getJWKS("https://danielkinde.kinde.com")).rejects.toThrowError(
      "Failed to fetch JWKS after multiple retries",
    );
  });
});
