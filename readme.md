# Kinde JWT validator

## Description

Simple library to validate JWT tokens

## Installation

```bash
# npm
npm install @kinde/jwt-validator
# yarn
yarn add @kinde/jwt-validator
# pnpm
pnpm install @kinde/jwt-validator
```

## Usage

```js
import { validateToken, type jwtValidationResponse } from "@kinde/jwt-validator";

const validationResult: jwtValidationResponse = await validateToken({
  token: "eyJhbGc...",
  domain: "http://mybusiness.kinde.com"
});
```

### Optional claim checks

All checks are opt-in. Passing any of the options below also enables `exp` and
`nbf` validation (a token without `exp` is rejected) and rate-limits the re-fetch of signing keys to once per minute
per domain.

Without any options, the default WebCrypto path checks only the signature, so an
expired token is reported as valid. Pass at least one option (for example
`clockTolerance: 0`) to enforce `exp` and `nbf`.

Because re-fetches are limited to once a minute, a token signed with a newly
rotated key can be rejected for up to 60 seconds after the last fetch.

```js
const validationResult = await validateToken({
  token: "eyJhbGc...",
  domain: "http://mybusiness.kinde.com",
  issuer: "http://mybusiness.kinde.com",
  audience: "my-api",
  clockTolerance: 5,
  algorithms: ["RS256"],
});
```

| Option           | Type                 | Description                                                    |
| ---------------- | -------------------- | -------------------------------------------------------------- |
| `issuer`         | `string`             | Expected `iss` claim.                                          |
| `audience`       | `string \| string[]` | Accepted `aud` values. The token must contain at least one.    |
| `clockTolerance` | `number`             | Seconds of leeway applied to `exp` and `nbf`. Defaults to `0`. |
| `algorithms`     | `string[]`           | Allowed values for the token header `alg`.                     |

Signatures are always verified as RS256, the only supported algorithm. `algorithms`
checks the value declared in the token header and cannot enable other algorithms.

## Kinde documentation

[Kinde Documentation](https://kinde.com/docs/) - Explore the Kinde docs

## Contributing

If you'd like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

### Development and testing

The development toolchain requires Node.js 22.12 or newer and the pnpm version
pinned in `package.json`. These are development requirements, not consumer runtime
requirements.

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm build
pnpm test:coverage --run
```

Tests use Vitest 5. Always await asynchronous assertions such as
`expect(promise).rejects` and `expect(promise).resolves`; unawaited assertions fail
the test.

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.
