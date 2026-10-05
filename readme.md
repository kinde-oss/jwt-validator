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
