package com.coforge.vln.keycloak;

import java.util.List;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class VlnEmailOtpAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "vln-email-otp-authenticator";
    public static final String DISPLAY_TYPE = "VLN Email OTP Authenticator";
    public static final String HELP_TEXT = "Custom browser authenticator for same-screen username, password and email OTP validation.";

    private static final VlnEmailOtpAuthenticator SINGLETON = new VlnEmailOtpAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        // Nothing to initialize for the PoC; production hardening may add configurable values here.
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        // No-op.
    }

    @Override
    public void close() {
        // No-op.
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("otpDeliveryMode")
                .type(ProviderConfigProperty.LIST_TYPE)
                .label("OTP delivery mode")
                .defaultValue("EMAIL")
                .helpText("Development mode displays the OTP on the page. EMAIL uses the Keycloak Email Sender provider. Default is EMAIL for safety.")
                .options(List.of("EMAIL", "DEV"))
                .add()
                .property()
                .name("otp.length")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("OTP length")
                .defaultValue("6")
                .helpText("Length of generated OTP digits.")
                .add()
                .property()
                .name("otp.expiration.minutes")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("OTP expiration minutes")
                .defaultValue("5")
                .helpText("Time in minutes before OTP expires.")
                .add()
                .property()
                .name("otp.max.attempts")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Maximum attempt count")
                .defaultValue("5")
                .helpText("Maximum validation attempts before OTP is invalidated.")
                .add()
                .property()
                .name("otp.resend.cooldown.seconds")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Resend cooldown seconds")
                .defaultValue("30")
                .helpText("Cooldown in seconds before a new OTP can be sent again.")
                .add()
                .build();
    }
}
