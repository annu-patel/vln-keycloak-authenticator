VLN Keycloak Authenticator PoC
Custom Keycloak authentication implementation for the VLN Portal PoC.

Environment
Keycloak: 26.8.2
Realm: vln-poc
Keycloak URL: http://localhost:9090
Angular VLN Portal: http://localhost:4200
Local SMTP: Mailpit
Mailpit SMTP: 127.0.0.1:1025
Mailpit UI: http://localhost:8025
Authentication Flow
VLN Portal → Keycloak → Username / Email + Password → Password validation → Email OTP → OTP verification → Successful authentication → Redirect to VLN Portal

The authentication flow is mandatory Password + Email OTP.

Password and OTP are not alternative authentication methods.

Features
Custom VLN/SITA Keycloak login theme
Username/password authentication
Mandatory email OTP second factor
OTP resend
OTP expiration
Mailpit SMTP support for local development
Forgot Password using Keycloak native reset-credentials flow
Realm role-based VLN Portal authorization
Responsive login UI
Mobile-compatible Keycloak theme
Realm Roles
The PoC includes the realm role:

operator

The VLN Portal maps the Keycloak operator role to:

VFS Operator

Repository Structure
src/ Custom Keycloak authenticator Java implementation

keycloak-theme/ vln-theme/ Custom VLN login theme, CSS and resources

realm-config/ vln-poc-realm-sanitized.json

The realm JSON committed to this repository is sanitized and must not contain passwords, client secrets, SMTP credentials, or exported users.

Build
From the repository root:

mvn clean package

Expected result:

BUILD SUCCESS

The generated provider JAR will be available under:

target/vln-keycloak-authenticator-1.0.0.jar

Fresh System Recovery
1. Install prerequisites
Install:

Java 21 or the Java version compatible with the project
Maven
Git
Keycloak 26.8.2
Mailpit
2. Clone repository
git clone https://github.com/annu-patel/vln-keycloak-authenticator.git

cd vln-keycloak-authenticator

git switch vln-mfa-forgot-password-final

3. Build authenticator
mvn clean package

4. Deploy provider
Copy:

target/vln-keycloak-authenticator-1.0.0.jar

to the Keycloak installation:

providers/

5. Deploy VLN theme
Copy:

keycloak-theme/vln-theme

to:

/themes/vln-theme

6. Restore realm configuration
Use:

realm-config/vln-poc-realm-sanitized.json

to restore/recreate the vln-poc realm configuration.

Important:

The committed realm configuration intentionally excludes sensitive secrets and user credentials.

After restoration, manually configure any environment-specific values that are required.

7. Configure local SMTP for Mailpit
For local PoC testing configure Keycloak realm email settings:

Host: 127.0.0.1 Port: 1025 SSL: Off StartTLS: Off Authentication: Off

Start Mailpit and verify:

http://localhost:8025

8. Start Keycloak
From the Keycloak installation directory:

.\bin\kc.bat start-dev --http-port=9090

Admin Console:

http://localhost:9090/admin/

9. Verify realm
Confirm:

Realm: vln-poc
Custom login theme: vln-theme
Forgot Password: Enabled
Realm role: operator
VLN Browser MFA authentication flow
Password authentication
VLN Email OTP execution
10. Create test user
In:

Keycloak Admin Console → vln-poc → Users → Add user

Configure:

Username
Email
First name
Last name
Permanent password
Realm role: operator
Do not store user passwords in Git.

11. Start VLN Portal
Start the Angular VLN Portal separately.

Local URL:

http://localhost:4200

Expected authentication journey:

VLN Portal → Keycloak login → Password → Email OTP → OTP verification → VLN Portal → VFS Operator access

Forgot Password Flow
Forgot Password? → Username / Email → Keycloak sends reset email → Reset link → New password → Successful authentication → VLN Portal

For local development, password-reset emails are captured in Mailpit.

Security Notes
Never commit:

User passwords
OTP values
Keycloak client secrets
SMTP passwords
Admin passwords
Raw Keycloak user exports
H2 database files
Access or refresh tokens
Generated JAR files
.env files
Only sanitized configuration should be stored in Git.

Working Git Branch
vln-mfa-forgot-password-final

Recovery Checkpoint
Use the final working branch as the source of truth:

git switch vln-mfa-forgot-password-final git pull

Repository:

https://github.com/annu-patel/vln-keycloak-authenticator