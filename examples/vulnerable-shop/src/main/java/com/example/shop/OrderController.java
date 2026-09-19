package com.example.shop;

import java.io.File;
import java.util.Random;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.transaction.annotation.Transactional;

@RestController
public class OrderController {

    private final UserService userService = new UserService();
    private static final String password = "SuperSecret123";

    @GetMapping("/orders")
    public String orders(@RequestParam Long id) {
        return userService.displayName(id);
    }

    @PostMapping("/refund")
    @Transactional
    public String refund(@RequestParam Long id, @RequestParam Long amount) {
        String token = String.valueOf(new Random().nextInt());
        userService.createOrder(new UserService.OrderRequest());
        return token;
    }

    @GetMapping("/export")
    public File export(@RequestParam String filename) {
        return new File("/var/data/exports/" + filename);
    }
}
