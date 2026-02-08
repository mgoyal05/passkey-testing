# Tara Passkey + OTP Demo

This Spring Boot (Java 17) app implements OTP + passkey (WebAuthn) registration and a payment flow that requires passkey approval. All `/api/**` calls are wrapped in an application-layer encryption envelope (RSA-OAEP + AES-256-CBC + HMAC-SHA256).

## Running locally

```bash
./mvnw spring-boot:run
```

Visit: `http://localhost:8080/login`

## Configuration

`src/main/resources/application.yml` contains safe defaults for local development. Adjust:

- `app.webauthn.rp-id`: RP ID that matches your domain.
- `app.webauthn.origins`: Allowed origins list (must match the browser origin).
- `app.otp.base-url` and `app.otp.access-key`: Tara OTP API settings.
- `app.crypto.key-store-path`, `app.crypto.key-store-password`, `app.crypto.key-alias`: RSA key store settings.

### RSA Keypair / Keystore

On startup, the app loads a PKCS12 keystore from `app.crypto.key-store-path`. If the keystore does not exist, a new RSA-2048 keypair is generated in memory for development convenience. Replace this in production with a secure keystore and secrets management.

## Passkeys

- Discoverable (resident) credentials required.
- `userVerification` is required.
- Device-bound enforcement: backup-eligible or backed-up credentials are rejected.

## Encryption Envelope

The browser encrypts the entire request body with AES-256-CBC, signs with HMAC-SHA256, and wraps the per-request key material with RSA-OAEP. The server verifies HMAC before decrypting and enforces replay protection.

## Payments (UPI-like signing)

Each payment requires a passkey assertion that is bound to a canonical transaction payload, hashed with SHA-256. Any mismatch of payee or amount is rejected.

## Tests

Basic unit tests cover crypto roundtrip and payment canonicalization.
