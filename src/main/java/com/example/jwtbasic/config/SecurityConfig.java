package com.example.jwtbasic.config;

import com.example.jwtbasic.auth.PrincipalDetailsService;
import com.example.jwtbasic.filter.MyFilter3;
import com.example.jwtbasic.jwt.JwtAuthenticationFilter;
import com.example.jwtbasic.jwt.JwtAuthorizationFilter;
import com.example.jwtbasic.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Autowired
    private UserRepository userRepository;

    private final CorsFilter corsFilter;
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManagerBuilder를 사용하여 AuthenticationManager를 설정하고 빌드합니다.
    // AuthenticationManager 빈 직접 구성
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        // HttpSecurity의 AuthenticationManagerBuilder를 통해 구성
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(new PrincipalDetailsService(userRepository))
            .passwordEncoder(bCryptPasswordEncoder());
        return builder.build();
    }


    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // 이게 제일 먼저 한번 실행되나? 필터 순서가 이상해
        AuthenticationManager authenticationManager = authenticationManager(http);
        http
            .authenticationManager(authenticationManager)
//            .addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class)
            .csrf(csrf -> csrf
                .disable())
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))    // 세션 안씀
            .addFilter(corsFilter)  // @CrossOrigin(인증x), security filter에 등록(인증o)
            .formLogin(form -> form
                .disable())     // form 태그 안씀
            .httpBasic(basic -> basic
                .disable())     // http 통신 안씀
            .addFilter(new JwtAuthenticationFilter(authenticationManager)) // AuthenticationManager를 매개변수로 담아줘야함.
            .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/user/**").hasAnyAuthority("ROLE_USER", "ROLE_MANAGER", "ROLE_ADMIN")   // SpringSecurity는 내부적으로 권한 앞에 "ROLE_"을 기대할 수 있음
                    .requestMatchers("/api/v1/manager/**").hasAnyAuthority("ROLE_MANAGER", "ROLE_ADMIN")
                .requestMatchers("/api/v1/admin/**").hasAuthority("ROLE_ADMIN")
                .anyRequest().permitAll()
            );
        return http.build();
    }
}
