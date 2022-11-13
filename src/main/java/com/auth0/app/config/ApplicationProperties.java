package com.auth0.app.config;

import lombok.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@Value
@ConstructorBinding
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

    private String clientOriginUrl;

    private String audience;
}