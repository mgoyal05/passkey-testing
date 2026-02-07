package com.tara.passkey.crypto;

import com.tara.passkey.crypto.CryptoService.DecryptedEnvelope;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class CryptoFilter extends OncePerRequestFilter {
    private final CryptoService cryptoService;

    public CryptoFilter(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String contentType = request.getContentType();
        if (contentType == null || !contentType.toLowerCase().startsWith(MediaType.APPLICATION_JSON_VALUE)) {
            filterChain.doFilter(request, response);
            return;
        }
        byte[] body = request.getInputStream().readAllBytes();
        if (body.length == 0) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            DecryptedEnvelope decrypted = cryptoService.decryptEnvelope(body, request.getRequestURI());
            request.setAttribute(CryptoService.REQUEST_CONTEXT_ATTR, decrypted.getContext());
            DecryptedRequestWrapper wrapped = new DecryptedRequestWrapper(request, decrypted.getPlaintext());
            filterChain.doFilter(wrapped, response);
        } catch (CryptoValidationException ex) {
            response.setStatus(ex.getStatus().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"" + ex.getMessage() + "\"}");
        }
    }
}
