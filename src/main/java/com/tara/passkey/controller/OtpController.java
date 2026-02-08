package com.tara.passkey.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.tara.passkey.security.SessionConstants;
import com.tara.passkey.service.OtpService;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OtpController {
    private final OtpService otpService;

    public OtpController(OtpService otpService) {
        this.otpService = otpService;
    }

    @PostMapping("/api/otp/send")
    public Map<String, Object> sendOtp(@RequestBody OtpRequest request) {
        JsonNode response = otpService.sendOtp(request.mobileNumber(), request.customerType(), request.otpContext());
        String message = response != null && response.has("message") ? response.get("message").asText() : "OTP sent";
        return Map.of("message", message);
    }

    @PostMapping("/api/otp/validate")
    public Map<String, Object> validateOtp(@RequestBody OtpValidateRequest request, HttpSession session) {
        JsonNode response = otpService.validateOtp(request.mobileNumber(), request.otp(), request.customerType());
        session.setAttribute(SessionConstants.PRE_AUTH, true);
        session.setAttribute(SessionConstants.PRE_AUTH_MOBILE, request.mobileNumber());
        return Map.of("status", "ok", "response", response);
    }

    public record OtpRequest(String mobileNumber, String customerType, String otpContext) {
    }

    public record OtpValidateRequest(String mobileNumber, String otp, String customerType) {
    }
}
