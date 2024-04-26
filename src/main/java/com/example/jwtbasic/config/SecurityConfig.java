package com.example.jwtbasic.config;

import com.example.jwtbasic.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // 이게 제일 먼저 한번 실행되나? 필터 순서가 이상해
        http
            .addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class)
            .csrf(csrf -> csrf
                .disable())
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))    // 세션 안씀
            .addFilter(corsFilter)  // @CrossOrigin(인증x), security filter에 등록(인증o)
            .formLogin(form -> form
                .disable())     // form 태그 안씀
            .httpBasic(basic -> basic
                .disable())     // http 통신 안씀
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
            );

        return http.build();
    }
}
