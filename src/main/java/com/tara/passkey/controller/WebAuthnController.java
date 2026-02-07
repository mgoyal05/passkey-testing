package com.tara.passkey.controller;

import com.tara.passkey.security.SessionConstants;
import com.tara.passkey.webauthn.PublicKeyCredentialCreationOptions;
import com.tara.passkey.webauthn.PublicKeyCredentialRequestOptions;
import com.tara.passkey.webauthn.WebAuthnAssertionRequest;
import com.tara.passkey.webauthn.WebAuthnAssertionResult;
import com.tara.passkey.webauthn.WebAuthnAttestationRequest;
import com.tara.passkey.webauthn.WebAuthnService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebAuthnController {
    private final WebAuthnService webAuthnService;

    public WebAuthnController(WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    @PostMapping("/api/webauthn/register/options")
    public PublicKeyCredentialCreationOptions registerOptions(@RequestBody RegisterOptionsRequest request,
                                                               HttpSession session) {
        String mobileNumber = request.mobileNumber();
        if (mobileNumber == null) {
            mobileNumber = (String) session.getAttribute(SessionConstants.PRE_AUTH_MOBILE);
        }
        return webAuthnService.startRegistration(session.getId(), mobileNumber, "Consumer");
    }

    @PostMapping("/api/webauthn/register/finish")
    public Map<String, Object> registerFinish(@RequestBody WebAuthnAttestationRequest request,
                                              HttpServletRequest servletRequest,
                                              HttpSession session) {
        String origin = servletRequest.getHeader("Origin");
        webAuthnService.finishRegistration(session.getId(), request, origin);
        session.setAttribute(SessionConstants.AUTHENTICATED_USER, session.getAttribute(SessionConstants.PRE_AUTH_MOBILE));
        return Map.of("ok", true);
    }

    @PostMapping("/api/webauthn/auth/options")
    public PublicKeyCredentialRequestOptions authOptions(HttpSession session) {
        return webAuthnService.startAuthentication(session.getId());
    }

    @PostMapping("/api/webauthn/auth/finish")
    public Map<String, Object> authFinish(@RequestBody WebAuthnAssertionRequest request,
                                          HttpServletRequest servletRequest,
                                          HttpSession session) {
        String origin = servletRequest.getHeader("Origin");
        WebAuthnAssertionResult result = webAuthnService.finishAuthentication(session.getId(), request, origin);
        session.setAttribute(SessionConstants.AUTHENTICATED_USER, result.mobileNumber());
        return Map.of("ok", true);
    }

    public record RegisterOptionsRequest(String mobileNumber) {
    }
}
