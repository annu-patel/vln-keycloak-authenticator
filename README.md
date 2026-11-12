# VLN Keycloak custom authentication PoC

This project builds a Java 21 Keycloak 26.x custom authenticator provider and a matching custom login theme for the VLN Portal.

## Build

```powershell
cd .\vln-keycloak-authenticator
mvn clean package
```

This produces a deployable JAR:

```text
vln-keycloak-authenticator-1.0.0.jar
```

## Deploy to Keycloak

Copy the JAR into the Keycloak providers directory:

```powershell
Copy-Item .\target\vln-keycloak-authenticator-1.0.0.jar "C:\path\to\keycloak\providers\"
```

Then start Keycloak locally:

```powershell
cd C:\path\to\keycloak
.\bin\kc.bat start-dev --http-port=9090
```

## Configure the realm and flow

1. Create a realm named `vln-poc`.
2. Open Authentication -> Flows.
3. Duplicate the Browser flow as `VLN Browser MFA`.
4. Add the authenticator `VLN Email OTP Authenticator` to the flow and set it to REQUIRED.
5. Keep the built-in Browser flow untouched.
6. In Authentication -> Bindings -> Browser Flow, select `VLN Browser MFA`.
7. In Realm Settings -> Themes -> Login Theme, select `vln-theme`.

## Theme

The custom theme lives under:

```text
themes\vln-theme\
  login\
    theme.properties
    login.ftl
    resources\css\styles.css
```

It renders a single page with username/email, password, verification code, send code, resend action, and login button.

## Security notes

- Password validation uses Keycloak credential APIs.
- OTP is generated with `SecureRandom`.
- OTP is stored only in the Keycloak authentication session for the PoC.
- OTP is single use and invalidated after successful validation.
- Resend uses a cooldown and validation attempts are bounded.
- Sensitive values are not logged.
- The implementation intentionally keeps the public frontend separate and leaves authentication inside Keycloak.
- Development delivery mode is explicitly unsafe and must never be enabled in UAT or production. It is for local PoC use only.

## Local development OTP delivery mode

This authenticator supports two modes:

- `EMAIL`: default and safe production-style mode. Uses Keycloak `EmailSenderProvider` and requires SMTP/email configuration.
- `DEV`: local-only mode. It still generates and validates a secure OTP exactly like the real flow, but it displays the OTP on the same custom login page for local testing. This must never be enabled outside a developer workstation.

Recommended configuration in Keycloak Admin Console for the `VLN Email OTP Authenticator`:

- `otpDeliveryMode`: `EMAIL` (default)
- `otp.length`: `6`
- `otp.expiration.minutes`: `5`
- `otp.max.attempts`: `5`
- `otp.resend.cooldown.seconds`: `30`

When `otpDeliveryMode=DEV`, the flow shows a development-only warning with the generated OTP on the screen. This is intentionally not hidden and is only for a local test environment.

## Future Angular / Spring Boot integration

The Angular application should use OIDC Authorization Code + PKCE S256 against the Keycloak public client `vln-frontend`. The custom Keycloak login page handles the combined username + password + email OTP challenge before the authorization code is issued.

Spring Boot remains an OAuth2 resource server and validates the JWT access token, issuer, expiration, audience (if configured), and roles.

## Flow reference

```text
User -> Angular -> Keycloak OIDC login -> VLN custom login page -> Keycloak auth flow -> JWT -> Angular -> Spring Boot
```

This project intentionally does not add Angular auth logic or any Spring Boot OTP validation.
