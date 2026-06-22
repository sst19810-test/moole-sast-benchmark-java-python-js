package com.infigroup.vulnapp.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.springframework.stereotype.Service;

/**
 * OS interaction helpers. Command and file sinks live here.
 */
@Service
public class CommandService {

    /** SINK (CWE-78): user input concatenated into a shell command. */
    public String ping(String host) throws IOException, InterruptedException {
        String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + host};
        Process p = Runtime.getRuntime().exec(cmd);
        p.waitFor();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }

    /** SINK (CWE-22): user path used to open a file under a base directory. */
    public String readUserFile(String name) throws IOException {
        File f = new File("/var/app/data/" + name);
        try (InputStream in = new FileInputStream(f)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
