package com.tara.passkey.crypto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class EnvelopeRequest {
    private int v;
    private String requestId;
    private long ts;
    private String path;
    private String ek;
    private String iv;
    private String ct;
    private String mac;

    public int getV() {
        return v;
    }

    public void setV(int v) {
        this.v = v;
    }

    @JsonProperty("requestId")
    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public long getTs() {
        return ts;
    }

    public void setTs(long ts) {
        this.ts = ts;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getEk() {
        return ek;
    }

    public void setEk(String ek) {
        this.ek = ek;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getCt() {
        return ct;
    }

    public void setCt(String ct) {
        this.ct = ct;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }
}
