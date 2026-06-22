package com.infigroup.vulnapp.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * Application configuration. Intentionally embeds credentials in source.
 */
@Configuration
public class AppConfig {

    // CWE-798: hardcoded credentials in source.
    public static final String DB_USERNAME = "sa";
    public static final String DB_PASSWORD = "Sup3rSecret!";
    public static final String API_TOKEN = "ghp_hardcodedGitHubTokenAABBCCDDEEFF00112233";
    public static final String ENCRYPTION_KEY = "1234567890123456"; // 16-byte AES key in source

    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.h2.Driver");
        ds.setUrl("jdbc:h2:mem:vulnapp;DB_CLOSE_DELAY=-1;INIT=RUNSCRIPT FROM 'classpath:schema.sql'");
        ds.setUsername(DB_USERNAME);
        ds.setPassword(DB_PASSWORD);
        return ds;
    }
}
