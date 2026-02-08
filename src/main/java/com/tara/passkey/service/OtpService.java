package com.tara.passkey.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.tara.passkey.config.OtpProperties;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class OtpService {
    private final RestTemplate restTemplate;
    private final OtpProperties properties;

    public OtpService(RestTemplate restTemplate, OtpProperties properties) {
        this.restTemplate = restTemplate;
        this.properties = properties;
    }

    public JsonNode sendOtp(String mobileNumber, String customerType, String otpContext) {
        OtpSendRequest payload = new OtpSendRequest(new OtpSendData(mobileNumber, customerType, otpContext, properties.getAccessKey()));
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "Tara/1.0 Merchant OS:Android/iOS");
        headers.set("vrsn", "77");
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.postForObject(properties.getBaseUrl() + "/v0.1/tara/auth/otp", new HttpEntity<>(payload, headers), JsonNode.class);
    }

    public JsonNode validateOtp(String mobileNumber, String otp, String customerType) {
        OtpValidateRequest payload = new OtpValidateRequest(new OtpValidateData(mobileNumber, null, otp, customerType));
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "Tara");
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.postForObject(properties.getBaseUrl() + "/v0.1/tara/auth/v2/otp/validate", new HttpEntity<>(payload, headers), JsonNode.class);
    }

    private record OtpSendRequest(OtpSendData data) {
    }

    private record OtpSendData(String mobileNumber, String customerType, String otpContext,
                               @JsonProperty("access-key") String accessKey) {
    }

    private record OtpValidateRequest(OtpValidateData data) {
    }

    private record OtpValidateData(String mobileNumber, String password, String otp, String customerType) {
    }
}
