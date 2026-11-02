package com.bac.java_a3_010;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/sys/**").authenticated()
                        .requestMatchers("/internal/**").hasAnyRole("ADMIN", "OPS")
                        .anyRequest().permitAll());
        return http.build();
    }
}
