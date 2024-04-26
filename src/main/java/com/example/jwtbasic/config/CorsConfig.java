package com.example.jwtbasic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);    // 서버가 응답할 때 json을 js에서 처리할 수 있게 할지를 설정하는 것, false면 js로 요청받으면 실행 안됨
        corsConfiguration.addAllowedOrigin("*");        // 모든 ip에 응답을 허용
        corsConfiguration.addAllowedHeader("*");        // 모든 header에 응답을 허용
        corsConfiguration.addAllowedMethod("*");        // 모든 post, get, put, delete, patch 요청을 허용
        source.registerCorsConfiguration("/api/**", corsConfiguration);

        return new CorsFilter(source);
    }
}
