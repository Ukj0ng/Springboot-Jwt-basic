package com.example.jwtbasic.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwtbasic.auth.PrincipalDetails;
import com.example.jwtbasic.model.User;
import com.example.jwtbasic.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// Security가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter가 있음
// 권한이나 인증이 필요한 특정 url을 요청했을 때 위 필터를 무조건 거치게 되어있음
// 만약 권한이나 인증이 필요한 url이 아니라면 이 필터는 거치지 않음
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;
    public JwtAuthorizationFilter(
        AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 filter를 거칠 것
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain); 이게 있으면 응답을 두번해줌
        System.out.println("인증이나 권한이 필요한 url 요청이 됨.");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader: " + jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        String username = JWT
            .require(Algorithm.HMAC256("cos"))
            .build()
            .verify(jwtToken).getClaim("username")
            .asString();

        // 서명이 정상적으로 됨
        if (username != null) {
            System.out.println("username 실행");
            User userEntity = userRepository.findByUsername(username);
            System.out.println("userEntity: " + userEntity.getUsername());

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            System.out.println("principalDetails: " + principalDetails.getUsername());

            // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, true, principalDetails.getAuthorities());
            System.out.println("authentication: " + authentication.getPrincipal().toString());
            // 강제로 security의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
