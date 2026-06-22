package com.infigroup.vulnapp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Demonstrates a reflected-XSS sink: tainted input echoed into an HTML
 * response with the content type set to text/html and no escaping.
 */
@RestController
public class SearchController {

    /** SINK (CWE-79): 'q' reflected into an HTML body unescaped. */
    @GetMapping(value = "/search", produces = "text/html")
    public String search(@RequestParam String q) {
        return "<html><body>Results for: " + q + "</body></html>";
    }
}
