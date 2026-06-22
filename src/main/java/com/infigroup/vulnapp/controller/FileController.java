package com.infigroup.vulnapp.controller;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.infigroup.vulnapp.service.CommandService;
import com.infigroup.vulnapp.util.SerializationUtil;
import com.infigroup.vulnapp.util.XmlUtil;

/**
 * File, command, XML, SSRF and deserialization endpoints. All inbound values
 * are SOURCES feeding the corresponding sinks.
 */
@RestController
public class FileController {

    private final CommandService commandService;

    public FileController(CommandService commandService) {
        this.commandService = commandService;
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        // SOURCE (CWE-78): host -> CommandService.ping -> Runtime.exec
        return commandService.ping(host);
    }

    @GetMapping("/file")
    public String file(@RequestParam String name) throws Exception {
        // SOURCE (CWE-22): name -> CommandService.readUserFile -> FileInputStream
        return commandService.readUserFile(name);
    }

    @PostMapping("/xml")
    public String xml(@RequestBody String body) throws Exception {
        // SOURCE (CWE-611): request body -> XmlUtil.parse (XXE)
        return XmlUtil.parse(body);
    }

    @PostMapping("/object")
    public String object(@RequestBody String base64) throws Exception {
        // SOURCE (CWE-502): base64 body -> ObjectInputStream.readObject
        byte[] raw = Base64.getDecoder().decode(base64);
        Object o = SerializationUtil.deserialize(raw);
        return o.getClass().getName();
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        // SOURCE (CWE-918): SSRF — server opens a connection to a user URL.
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        byte[] data = conn.getInputStream().readAllBytes();
        return new String(data, StandardCharsets.UTF_8);
    }
}
