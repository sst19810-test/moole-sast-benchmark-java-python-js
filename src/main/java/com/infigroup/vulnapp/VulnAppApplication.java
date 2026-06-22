package com.infigroup.vulnapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the intentionally vulnerable Spring Boot application used as
 * a SAST benchmarking corpus. See VULNERABILITIES.md for the ground-truth map.
 */
@SpringBootApplication
public class VulnAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnAppApplication.class, args);
    }
}
