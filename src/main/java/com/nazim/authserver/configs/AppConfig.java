package com.nazim.authserver.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class AppConfig {

    @Value("${key.rotation.cron}")
    private String keyRotationCron;

    @Value("${key.cleanup.cron}")
    private String keyCleanupCron;

    @Bean
    public String keyRotationCron() {
        return keyRotationCron;
    }

    @Bean
    public String keyCleanupCron() {
        return keyCleanupCron;
    }
}
