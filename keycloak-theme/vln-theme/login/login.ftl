<#import "template.ftl" as layout>

<@layout.registrationLayout displayInfo=false displayMessage=true; section>
    <#if section = "header">
        <div class="vln-brand">
            <div class="vln-logo">SITA</div>
            <h1>VLN PORTAL</h1>
        </div>
    <#elseif section = "form">
        <div class="vln-card">
            <form id="kc-form-login" class="vln-form password-mode" action="${url.loginAction}" method="post">
                <input type="hidden" name="credentialId" value="${client.clientId}"/>
                <input type="hidden" name="loginMode" id="loginMode" value="${(loginMode!'PASSWORD')}"/>

                <div class="form-row">
                    <label for="username">Email / Username</label>
                    <input id="username" name="username" type="text" autocomplete="username" value="${(auth.attemptedUsername!'')}" />
                </div>

                <div class="form-row form-password">
                    <label for="password">Password</label>
                    <input id="password" name="password" type="password" autocomplete="current-password" />
                </div>

                <#if realm.resetPasswordAllowed && url.loginResetCredentialsUrl?has_content>
                    <div class="reset-row form-password">
                        <a class="reset-link" href="${url.loginResetCredentialsUrl}">Forgot Password?</a>
                    </div>
                </#if>

                <div class="form-row form-otp" style="display:none;">
                    <label for="otp">Verification Code</label>
                    <div class="otp-inline">
                        <input id="otp" name="otp" type="text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" />
                    </div>
                </div>

                <div class="resend-row form-otp" style="display:none;">
                    <button type="button" class="resend-link">Didn't receive the code? Resend Code</button>
                </div>

                <div class="login-actions">
                    <button id="kc-login-button" type="submit" name="action" value="login" class="primary-btn">LOGIN</button>
                </div>

                <#if messagesPerField.existsError('username','password','otp')>
                    <div class="form-error">
                        <#if messagesPerField.existsError('username')>
                            <div>${kcSanitize(messagesPerField.getFirstError('username'))?no_esc}</div>
                        </#if>
                        <#if messagesPerField.existsError('password')>
                            <div>${kcSanitize(messagesPerField.getFirstError('password'))?no_esc}</div>
                        </#if>
                        <#if messagesPerField.existsError('otp')>
                            <div>${kcSanitize(messagesPerField.getFirstError('otp'))?no_esc}</div>
                        </#if>
                    </div>
                </#if>

                <#if realm.internationalizationEnabled>
                    <div class="lang-select">
                        <#list locale.supported as l>
                            <a href="${l.url}">${l.label}</a>
                        </#list>
                    </div>
                </#if>
            </form>

            <script>
                (function() {
                    var form = document.getElementById('kc-form-login');
                    var loginModeInput = document.getElementById('loginMode');
                    var passwordField = document.getElementById('password');
                    var otpField = document.getElementById('otp');
                    var passwordBlocks = document.querySelectorAll('.form-password');
                    var otpBlocks = document.querySelectorAll('.form-otp');
                    var mode = (loginModeInput && loginModeInput.value) || 'PASSWORD';

                    function setMode(nextMode) {
                        var isOtp = nextMode === 'OTP';
                        if (form) {
                            form.classList.toggle('password-mode', !isOtp);
                            form.classList.toggle('otp-mode', isOtp);
                        }
                        if (loginModeInput) {
                            loginModeInput.value = nextMode;
                        }
                        passwordBlocks.forEach(function(block) {
                            block.style.display = isOtp ? 'none' : '';
                        });
                        var resetBlock = document.querySelectorAll('.reset-row');
                        resetBlock.forEach(function(block) {
                            block.style.display = isOtp ? 'none' : '';
                        });
                        otpBlocks.forEach(function(block) {
                            block.style.display = isOtp ? '' : 'none';
                        });

                        if (passwordField) {
                            passwordField.required = !isOtp;
                        }
                        if (otpField) {
                            otpField.required = isOtp;
                        }

                        var loginButton = document.getElementById('kc-login-button');
                        if (loginButton) {
                            loginButton.textContent = isOtp ? 'VERIFY' : 'LOGIN';
                            loginButton.value = isOtp ? 'login' : 'login';
                        }
                    }

                    form.addEventListener('submit', function(event) {
                        var submitter = event.submitter || document.activeElement;
                        var action = submitter && submitter.name === 'action' ? submitter.value : 'login';
                        if (action === 'resendCode') {
                            if (passwordField) passwordField.required = false;
                            if (otpField) otpField.required = false;
                            return;
                        }
                        if (loginModeInput && loginModeInput.value === 'OTP') {
                            if (otpField) otpField.required = true;
                            if (passwordField) passwordField.required = false;
                            return;
                        }
                        if (passwordField) passwordField.required = true;
                        if (otpField) otpField.required = false;
                    });

                    document.querySelectorAll('.resend-link').forEach(function(link) {
                        link.addEventListener('click', function(event) {
                            event.preventDefault();
                            var actionField = document.createElement('input');
                            actionField.type = 'hidden';
                            actionField.name = 'action';
                            actionField.value = 'resendCode';
                            form.appendChild(actionField);
                            form.submit();
                        });
                    });

                    setMode(mode);
                })();
            </script>
        </div>
    </#if>
</@layout.registrationLayout>
