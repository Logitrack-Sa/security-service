package com.logitrack.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude = org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class)
public class SecurityApplication {
    public static void main(String[] args) { SpringApplication.run(SecurityApplication.class, args); }
}
