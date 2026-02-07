package com.tara.passkey.controller;

import com.tara.passkey.crypto.CryptoService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptoController {
    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @GetMapping(value = "/crypto/server-pubkey", produces = MediaType.TEXT_PLAIN_VALUE)
    public String serverPublicKey() {
        return cryptoService.getPublicKeyPem();
    }
}
