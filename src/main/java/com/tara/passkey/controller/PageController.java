package com.tara.passkey.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class PageController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/passkey/enroll")
    public String passkeyEnrollPage() {
        return "passkey-enroll";
    }

    @GetMapping("/pay")
    public String payPage() {
        return "pay";
    }

    @GetMapping("/pay/confirm/{txnId}")
    public String confirmPayment(@PathVariable String txnId, Model model) {
        model.addAttribute("txnId", txnId);
        return "pay-confirm";
    }
}
