package com.tara.passkey.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@ControllerAdvice
public class CryptoResponseBodyAdvice implements ResponseBodyAdvice<Object> {
    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;

    public CryptoResponseBodyAdvice(CryptoService cryptoService, ObjectMapper objectMapper) {
        this.cryptoService = cryptoService;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request,
                                  ServerHttpResponse response) {
        if (!(request instanceof ServletServerHttpRequest servletRequest)) {
            return body;
        }
        HttpServletRequest httpRequest = servletRequest.getServletRequest();
        RequestCryptoContext context = (RequestCryptoContext) httpRequest.getAttribute(CryptoService.REQUEST_CONTEXT_ATTR);
        if (context == null) {
            return body;
        }
        try {
            byte[] plaintext = objectMapper.writeValueAsBytes(body);
            EnvelopeResponse envelope = cryptoService.encryptResponse(
                    context.getRequestId(),
                    context.getPath(),
                    200,
                    plaintext,
                    context.getAesKey(),
                    context.getMacKey());
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            return envelope;
        } catch (Exception ex) {
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            return "{\"error\":\"encryption_failed\"}";
        }
    }
}
