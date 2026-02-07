package com.tara.passkey.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.webauthn")
public class WebAuthnProperties {
    private String rpId = "localhost";
    private String rpName = "Tara";
    private List<String> origins = new ArrayList<>();

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public void setRpName(String rpName) {
        this.rpName = rpName;
    }

    public List<String> getOrigins() {
        return origins;
    }

    public void setOrigins(List<String> origins) {
        this.origins = origins;
    }
}
