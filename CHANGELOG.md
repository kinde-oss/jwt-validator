# Changelog


## 0.5.0

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.6...0.5.0)

### 🚀 Enhancements

- Add optional JWT claim validation ([3ae637b](https://github.com/kinde-oss/jwt-validator/commit/3ae637b))
- Require exp claim when claim validation is opted in ([84ea08b](https://github.com/kinde-oss/jwt-validator/commit/84ea08b))

### 🩹 Fixes

- Share in-flight JWKS fetch and keep cached keys on failed refresh ([8210ad3](https://github.com/kinde-oss/jwt-validator/commit/8210ad3))
- Reject invalid clockTolerance values ([23e23bf](https://github.com/kinde-oss/jwt-validator/commit/23e23bf))

### 📖 Documentation

- Clarify that algorithms checks only the header alg ([a3feba7](https://github.com/kinde-oss/jwt-validator/commit/a3feba7))
- Document default-path expiry and key-rotation behavior ([4675bd3](https://github.com/kinde-oss/jwt-validator/commit/4675bd3))
- Use https in readme examples ([b4857d8](https://github.com/kinde-oss/jwt-validator/commit/b4857d8))

### ✅ Tests

- Add regression tests for clockTolerance and JWKS re-fetch fixes ([2aa9510](https://github.com/kinde-oss/jwt-validator/commit/2aa9510))
- Cover claim checks on the jsrsasign fallback path ([0ebe6f1](https://github.com/kinde-oss/jwt-validator/commit/0ebe6f1))

### ❤️ Contributors

- Asher Muneer <asher.muneer@whiteboxtech.net>

## 0.4.6

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.5...0.4.6)

### 🩹 Fixes

- Keep jsrsasign lazily imported ([233fa6d](https://github.com/kinde-oss/jwt-validator/commit/233fa6d))

### ❤️ Contributors

- Koosha Owji <koosha.owji@gmail.com>

## 0.4.5

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.4...0.4.5)

### 🏡 Chore

- Migrate to TypeScript 7 - verbatimModuleSyntax and type-only imports ([4b15ed3](https://github.com/kinde-oss/jwt-validator/commit/4b15ed3))
- Release v0.4.4 ([f80d078](https://github.com/kinde-oss/jwt-validator/commit/f80d078))
- Standardize Renovate config with release-age cooldown ([292757a](https://github.com/kinde-oss/jwt-validator/commit/292757a))

### ❤️ Contributors

- Shafal Adhikari <adhikarishafal0@gmail.com>
- Koosha Owji <koosha.owji@gmail.com>

## 0.4.4

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.3...0.4.4)

### 🩹 Fixes

- **build:** Restore type declarations via tsc and add CI guard ([2b5d2f5](https://github.com/kinde-oss/jwt-validator/commit/2b5d2f5))

### 🏡 Chore

- Release v0.4.3 ([42ba4c9](https://github.com/kinde-oss/jwt-validator/commit/42ba4c9))

### ❤️ Contributors

- Shafal Adhikari <adhikarishafal0@gmail.com>
- Koosha Owji <koosha.owji@gmail.com>

## 0.4.3

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.2...0.4.3)

### 🩹 Fixes

- Update tsconfig for TypeScript 6 - Bundler moduleResolution and node types ([eab2010](https://github.com/kinde-oss/jwt-validator/commit/eab2010))

### 🏡 Chore

- ReleaseV0.4.2 ([9f07460](https://github.com/kinde-oss/jwt-validator/commit/9f07460))
- Update changelog headers ([70361b2](https://github.com/kinde-oss/jwt-validator/commit/70361b2))

### 🤖 CI

- Remove unsupported pnpm config command ([85747cf](https://github.com/kinde-oss/jwt-validator/commit/85747cf))

### ❤️ Contributors

- Koosha Owji <koosha.owji@gmail.com>

## 0.4.2

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.1...0.4.2)

### 🩹 Fixes

- Remove redundant pnpm version from workflow for action-setup v6 compat ([58df997](https://github.com/kinde-oss/jwt-validator/commit/58df997))

### 🏡 Chore

- Release v0.4.1 ([1eae5ff](https://github.com/kinde-oss/jwt-validator/commit/1eae5ff))
- **release:** Bump version to v0.4.1 in changelog.md ([80665fe](https://github.com/kinde-oss/jwt-validator/commit/80665fe))

### ❤️ Contributors

- Koosha Owji <koosha.owji@gmail.com>

## 0.4.1

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.4.0...0.4.1)

### 🏡 Chore

- Ignore renovate.json ([d68aa70](https://github.com/kinde-oss/jwt-validator/commit/d68aa70))
- Remove package lock ([5e8e60a](https://github.com/kinde-oss/jwt-validator/commit/5e8e60a))
- Update CODEOWNERS for dependency files ([ce43aeb](https://github.com/kinde-oss/jwt-validator/commit/ce43aeb))

### ❤️ Contributors

- Andre Selton <andre@kinde.com>
- Daniel Rivers ([@DanielRivers](https://github.com/DanielRivers))

## 0.3.0...main

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.3.0...main)

### 🩹 Fixes

- Crypto window ([cacad44](https://github.com/kinde-oss/jwt-validator/commit/cacad44))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## 0.2.0...main

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.2.0...main)

### 🚀 Enhancements

- Replace jose & add no crypto support ([f950936](https://github.com/kinde-oss/jwt-validator/commit/f950936))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## 0.2.0...feat/replace-jose

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.2.0...feat/replace-jose)

### 🚀 Enhancements

- Replace jose ([dc45de5](https://github.com/kinde-oss/jwt-validator/commit/dc45de5))
- Remove jose and add mobile support ([dd07306](https://github.com/kinde-oss/jwt-validator/commit/dd07306))

### 🩹 Fixes

- Build ([aef5b25](https://github.com/kinde-oss/jwt-validator/commit/aef5b25))
- Syntax ([50bc9a7](https://github.com/kinde-oss/jwt-validator/commit/50bc9a7))

### 🏡 Chore

- Lint ([abbf8c6](https://github.com/kinde-oss/jwt-validator/commit/abbf8c6))
- Cleanup tests ([cc53804](https://github.com/kinde-oss/jwt-validator/commit/cc53804))
- Remove errorous import ([e0cb5dd](https://github.com/kinde-oss/jwt-validator/commit/e0cb5dd))
- Remove .only from tests ([206b57f](https://github.com/kinde-oss/jwt-validator/commit/206b57f))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## 0.2.0...feat/replace-jose

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.2.0...feat/replace-jose)

### 🚀 Enhancements

- Replace jose ([dc45de5](https://github.com/kinde-oss/jwt-validator/commit/dc45de5))
- Remove jose and add mobile support ([dd07306](https://github.com/kinde-oss/jwt-validator/commit/dd07306))

### 🩹 Fixes

- Build ([aef5b25](https://github.com/kinde-oss/jwt-validator/commit/aef5b25))
- Syntax ([50bc9a7](https://github.com/kinde-oss/jwt-validator/commit/50bc9a7))

### 🏡 Chore

- Lint ([abbf8c6](https://github.com/kinde-oss/jwt-validator/commit/abbf8c6))
- Cleanup tests ([cc53804](https://github.com/kinde-oss/jwt-validator/commit/cc53804))
- Remove errorous import ([e0cb5dd](https://github.com/kinde-oss/jwt-validator/commit/e0cb5dd))
- Remove .only from tests ([206b57f](https://github.com/kinde-oss/jwt-validator/commit/206b57f))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## 0.2.0...feat/replace-jose

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.2.0...feat/replace-jose)

### 🚀 Enhancements

- Replace jose ([dc45de5](https://github.com/kinde-oss/jwt-validator/commit/dc45de5))
- Remove jose and add mobile support ([dd07306](https://github.com/kinde-oss/jwt-validator/commit/dd07306))

### 🩹 Fixes

- Build ([aef5b25](https://github.com/kinde-oss/jwt-validator/commit/aef5b25))
- Syntax ([50bc9a7](https://github.com/kinde-oss/jwt-validator/commit/50bc9a7))

### 🏡 Chore

- Lint ([abbf8c6](https://github.com/kinde-oss/jwt-validator/commit/abbf8c6))
- Cleanup tests ([cc53804](https://github.com/kinde-oss/jwt-validator/commit/cc53804))
- Remove errorous import ([e0cb5dd](https://github.com/kinde-oss/jwt-validator/commit/e0cb5dd))
- Remove .only from tests ([206b57f](https://github.com/kinde-oss/jwt-validator/commit/206b57f))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## 0.2.0...feat/replace-jose

[compare changes](https://github.com/kinde-oss/jwt-validator/compare/0.2.0...feat/replace-jose)

### 🚀 Enhancements

- Replace jose ([dc45de5](https://github.com/kinde-oss/jwt-validator/commit/dc45de5))
- Remove jose and add mobile support ([dd07306](https://github.com/kinde-oss/jwt-validator/commit/dd07306))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## ...main


### 🚀 Enhancements

- Add token validation ([e219c96](https://github.com/kinde-oss/jwt-validator/commit/e219c96))
- Add jwks caching ([5be5858](https://github.com/kinde-oss/jwt-validator/commit/5be5858))

### 🏡 Chore

- Release v0.1.0 ([dea5af0](https://github.com/kinde-oss/jwt-validator/commit/dea5af0))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

## ...main


### 🚀 Enhancements

- Add token validation ([e219c96](https://github.com/kinde-oss/jwt-validator/commit/e219c96))

### ❤️ Contributors

- Daniel Rivers ([@DanielRivers](http://github.com/DanielRivers))

