package com.coforge.vln.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

public class VlnEmailOtpAuthenticator implements Authenticator {

    public static final String ACTION_SEND_CODE = "sendOtp";
    public static final String ACTION_LOGIN = "login";
    public static final String ACTION_RESEND = "resendOtp";

    public static final String AUTH_NOTE_OTP_HASH = "vln.otp.hash";
    public static final String AUTH_NOTE_OTP_EXPIRES_AT = "vln.otp.expiresAt";
    public static final String AUTH_NOTE_OTP_ATTEMPTS = "vln.otp.attempts";
    public static final String AUTH_NOTE_OTP_LAST_SENT = "vln.otp.lastSent";
    public static final String AUTH_NOTE_OTP_EMAIL = "vln.otp.email";
    public static final String AUTH_NOTE_DEV_OTP = "vln.otp.devCode";

    private static final int DEFAULT_OTP_LENGTH = 6;
    private static final int DEFAULT_OTP_TTL_MINUTES = 5;
    private static final int DEFAULT_MAX_ATTEMPTS = 5;
    private static final int DEFAULT_RESEND_COOLDOWN_SECONDS = 30;
    private static final String DELIVERY_MODE_EMAIL = "EMAIL";
    private static final String DELIVERY_MODE_DEV = "DEV";

    private final SecureRandom secureRandom = new SecureRandom();

    private enum DeliveryMode {
        EMAIL,
        DEV
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Initial OIDC challenge: render the custom form without any credential validation.
        context.challenge(buildChallenge(context, null));
    }

    @Override
    public void close() {
        // No-op for the PoC.
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String action = getFirst(form, "action");
        String username = getFirst(form, "username");
        String password = getFirst(form, "password");
        String otp = getFirst(form, "otp");

        if (action == null || action.isBlank()) {
            action = ACTION_LOGIN;
        }

        if (ACTION_SEND_CODE.equalsIgnoreCase(action) || ACTION_RESEND.equalsIgnoreCase(action)) {
            handleSendCode(context, username, password);
            return;
        }

        if (ACTION_LOGIN.equalsIgnoreCase(action)) {
            handleLogin(context, username, password, otp);
            return;
        }

        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, buildChallenge(context, "Invalid action requested."));
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No additional required actions for the PoC.
    }

    private void handleSendCode(AuthenticationFlowContext context, String username, String password) {
        if (username == null || username.isBlank()) {
            challengeWithError(context, "Missing username or email.");
            return;
        }

        UserModel user = resolveUser(context, username);
        if (user == null) {
            challengeWithError(context, "Invalid username or password.");
            return;
        }
        if (!user.isEnabled()) {
            challengeWithError(context, "Account is disabled.");
            return;
        }
        if (password == null || password.isBlank()) {
            challengeWithError(context, "Password is required.");
            return;
        }
        if (!validatePassword(user, password)) {
            challengeWithError(context, "Invalid username or password.");
            return;
        }

        String email = safeUserEmail(user);
        if (email == null || email.isBlank()) {
            challengeWithError(context, "User has no registered email address.");
            return;
        }
        if (isCooldownActive(context)) {
            challengeWithError(context, "Please wait before requesting a new verification code.");
            return;
        }

        String otp = generateOtp(context);
        long expiresAt = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(readIntConfig(context, "otp.expiration.minutes", DEFAULT_OTP_TTL_MINUTES));

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(AUTH_NOTE_OTP_HASH, hashOtp(otp));
        authSession.setAuthNote(AUTH_NOTE_OTP_EXPIRES_AT, Long.toString(expiresAt));
        authSession.setAuthNote(AUTH_NOTE_OTP_ATTEMPTS, "0");
        authSession.setAuthNote(AUTH_NOTE_OTP_LAST_SENT, Long.toString(System.currentTimeMillis()));
        authSession.setAuthNote(AUTH_NOTE_OTP_EMAIL, email);

        try {
            String deliveryMode = readDeliveryMode(context);
            if (DELIVERY_MODE_DEV.equalsIgnoreCase(deliveryMode)) {
                authSession.setAuthNote(AUTH_NOTE_DEV_OTP, otp);
                context.getEvent().success();
                challengeWithInfo(context, "Development mode verification code: " + otp);
                return;
            }

            sendOtpEmail(context, user, email, otp);
        } catch (EmailException ex) {
            clearOtpState(authSession);
            context.getEvent().error("email_send_failed");
            if (ex.getCause() != null) {
                System.err.println("[VLN OTP] Email send failed. Cause=" + ex.getCause().getClass().getName() + ": " + ex.getCause().getMessage());
            } else {
                System.err.println("[VLN OTP] Email send failed. Reason=" + ex.getMessage());
            }
            challengeWithError(context, "Could not send the verification code. Please try again later.");
            return;
        } catch (RuntimeException ex) {
            clearOtpState(authSession);
            context.getEvent().error("email_send_failed");
            System.err.println("[VLN OTP] Unexpected runtime exception while sending OTP. " + ex.getClass().getName() + ": " + ex.getMessage());
            ex.printStackTrace(System.err);
            challengeWithError(context, "Could not send the verification code. Please try again later.");
            return;
        }

        context.getEvent().success();
        challengeWithInfo(context, "Verification code sent. Please check your email.");
    }

    private void handleLogin(AuthenticationFlowContext context, String username, String password, String otp) {
        if (username == null || username.isBlank()) {
            challengeWithError(context, "Username or email is required.");
            return;
        }
        if (password == null || password.isBlank()) {
            challengeWithError(context, "Password is required.");
            return;
        }
        if (otp == null || otp.isBlank()) {
            challengeWithError(context, "Verification code is required.");
            return;
        }

        UserModel user = resolveUser(context, username);
        if (user == null) {
            challengeWithError(context, "Invalid username or password.");
            return;
        }
        if (!validatePassword(user, password)) {
            challengeWithError(context, "Invalid username or password.");
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String otpHash = authSession.getAuthNote(AUTH_NOTE_OTP_HASH);
        String expiresAtValue = authSession.getAuthNote(AUTH_NOTE_OTP_EXPIRES_AT);
        String attemptsValue = authSession.getAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
        String registeredEmail = authSession.getAuthNote(AUTH_NOTE_OTP_EMAIL);

        if (otpHash == null || otpHash.isBlank() || expiresAtValue == null || expiresAtValue.isBlank() || registeredEmail == null || registeredEmail.isBlank()) {
            challengeWithError(context, "Verification code has not been requested.");
            return;
        }

        long expiresAt = Long.parseLong(expiresAtValue);
        if (System.currentTimeMillis() > expiresAt) {
            clearOtpState(authSession);
            challengeWithError(context, "Verification code expired. Please request a new one.");
            return;
        }

        int attempts = attemptsValue == null || attemptsValue.isBlank() ? 0 : Integer.parseInt(attemptsValue);
        int maxAttempts = readIntConfig(context, "otp.max.attempts", DEFAULT_MAX_ATTEMPTS);
        if (attempts >= maxAttempts) {
            clearOtpState(authSession);
            challengeWithError(context, "Too many incorrect verification code attempts. Please request a new code.");
            return;
        }

        if (!isOtpMatch(otp, otpHash)) {
            attempts++;
            authSession.setAuthNote(AUTH_NOTE_OTP_ATTEMPTS, Integer.toString(attempts));
            if (attempts >= maxAttempts) {
                clearOtpState(authSession);
                challengeWithError(context, "Too many incorrect verification code attempts. Please request a new code.");
                return;
            }
            challengeWithError(context, "Incorrect verification code.");
            return;
        }

        clearOtpState(authSession);
        context.setUser(user);
        context.success();
    }

    private void challengeWithError(AuthenticationFlowContext context, String error) {
        context.form().setError(error);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, buildChallenge(context, error));
    }

    private void challengeWithInfo(AuthenticationFlowContext context, String info) {
        context.form().setInfo(info);
        context.challenge(buildChallenge(context, null));
    }

    private Response buildChallenge(AuthenticationFlowContext context, String error) {
        LoginFormsProvider form = context.form();
        form.setExecution(context.getExecution().getId());
        if (error != null && !error.isBlank()) {
            form.addError(new FormMessage("username", error));
        }
        return form.createLoginUsernamePassword();
    }

    private UserModel resolveUser(AuthenticationFlowContext context, String username) {
        if (username == null || username.isBlank()) {
            return null;
        }

        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username.trim());
        if (user == null && context.getRealm().isLoginWithEmailAllowed()) {
            user = context.getSession().users().getUserByEmail(context.getRealm(), username.trim());
        }
        return user;
    }

    private boolean validatePassword(UserModel user, String password) {
        return user != null && password != null && !password.isBlank() && user.credentialManager().isValid(UserCredentialModel.password(password));
    }

    private String safeUserEmail(UserModel user) {
        if (user == null) {
            return null;
        }
        String email = user.getEmail();
        return email == null || email.isBlank() ? null : email.trim();
    }

    private boolean isCooldownActive(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String lastSent = authSession.getAuthNote(AUTH_NOTE_OTP_LAST_SENT);
        if (lastSent == null || lastSent.isBlank()) {
            return false;
        }
        long lastSentAt = Long.parseLong(lastSent);
        long cooldownMs = TimeUnit.SECONDS.toMillis(readIntConfig(context, "otp.resend.cooldown.seconds", DEFAULT_RESEND_COOLDOWN_SECONDS));
        return System.currentTimeMillis() - lastSentAt < cooldownMs;
    }

    private String generateOtp(AuthenticationFlowContext context) {
        int otpLength = Math.max(1, readIntConfig(context, "otp.length", DEFAULT_OTP_LENGTH));
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            otp.append(secureRandom.nextInt(10));
        }
        return otp.toString();
    }

    private String hashOtp(String otp) {
        byte[] bytes = otp.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean isOtpMatch(String rawOtp, String storedHash) {
        if (rawOtp == null || storedHash == null) {
            return false;
        }
        return Objects.equals(hashOtp(rawOtp.trim()), storedHash);
    }

    private void clearOtpState(AuthenticationSessionModel authSession) {
        if (authSession == null) {
            return;
        }
        authSession.removeAuthNote(AUTH_NOTE_OTP_HASH);
        authSession.removeAuthNote(AUTH_NOTE_OTP_EXPIRES_AT);
        authSession.removeAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
        authSession.removeAuthNote(AUTH_NOTE_OTP_LAST_SENT);
        authSession.removeAuthNote(AUTH_NOTE_OTP_EMAIL);
        authSession.removeAuthNote(AUTH_NOTE_DEV_OTP);
    }

    private String readDeliveryMode(AuthenticationFlowContext context) {
        if (context.getAuthenticatorConfig() == null || context.getAuthenticatorConfig().getConfig() == null) {
            return DELIVERY_MODE_EMAIL;
        }
        String value = context.getAuthenticatorConfig().getConfig().get("otpDeliveryMode");
        if (value == null || value.isBlank()) {
            return DELIVERY_MODE_EMAIL;
        }
        return value.trim().toUpperCase();
    }

    private int readIntConfig(AuthenticationFlowContext context, String key, int fallback) {
        if (context.getAuthenticatorConfig() == null || context.getAuthenticatorConfig().getConfig() == null) {
            return fallback;
        }
        String value = context.getAuthenticatorConfig().getConfig().get(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    private String getFirst(MultivaluedMap<String, String> form, String name) {
        if (form == null || name == null) {
            return null;
        }
        String value = form.getFirst(name);
        return value == null ? null : value.trim();
    }

    private void sendOtpEmail(AuthenticationFlowContext context, UserModel user, String email, String otp) throws EmailException {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        EmailSenderProvider sender = session.getProvider(EmailSenderProvider.class);
        if (sender == null) {
            throw new EmailException("Email sender provider is not configured");
        }

        Map<String, String> smtpConfig = realm != null ? realm.getSmtpConfig() : null;
        String smtpHost = smtpConfig != null ? smtpConfig.get("host") : null;
        String smtpPort = smtpConfig != null ? smtpConfig.get("port") : null;
        String smtpFrom = smtpConfig != null ? smtpConfig.get("from") : null;

        String realmName = realm != null ? realm.getName() : "unknown";
        String userId = user != null ? user.getId() : "unknown";

        System.err.println("[VLN OTP] EMAIL send start: realm=" + realmName + ", userId=" + userId + ", recipient=" + email + ", smtpHost=" + smtpHost + ", smtpPort=" + smtpPort + ", smtpFrom=" + smtpFrom + ", template=verify-email");

        if (smtpConfig == null || smtpConfig.isEmpty()) {
            throw new EmailException("Realm SMTP configuration is missing. Check Realm Settings -> Email.");
        }

        Map<String, String> config = new HashMap<>(smtpConfig);
        config.put("from", smtpFrom == null ? "" : smtpFrom);
        config.put("replyTo", smtpFrom == null ? "" : smtpFrom);

        int otpTtlMinutes = readIntConfig(context, "otp.expiration.minutes", DEFAULT_OTP_TTL_MINUTES);
        String otpBody = "Your VLN Portal verification code is: " + otp + ". This code expires in " + otpTtlMinutes + " minutes.";

        try {
            sender.send(config, user, "VLN Portal verification code", otpBody, "");
        } catch (Exception ex) {
            System.err.println("[VLN OTP] Email send failed. Realm=" + realmName + ", userId=" + userId + ", recipient=" + email + ", host=" + smtpHost + ", port=" + smtpPort + ", from=" + smtpFrom);
            System.err.println("[VLN OTP] Raw email exception class=" + ex.getClass().getName() + ", message=" + ex.getMessage());
            ex.printStackTrace(System.err);
            if (ex instanceof EmailException emailException) {
                throw emailException;
            }
            throw new EmailException("Failed to send OTP email via configured Keycloak SMTP provider", ex);
        }
    }
}
