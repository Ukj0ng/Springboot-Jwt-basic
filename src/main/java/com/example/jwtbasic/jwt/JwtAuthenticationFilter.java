package com.example.jwtbasic.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwtbasic.auth.PrincipalDetails;
import com.example.jwtbasic.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// spring security에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password를 post로 전송하면 UsernamePasswordAuthenticationFilter가 동작함 -> 하지만 formlogin disable때문에 동작을 안해서
// 우리가 따로 필터를 만들어서 SecurityConfig에 넣어줘야함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도중");
        // 1. username, password  받아서
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
//                일반적인 웹에서는 x-www-form-urlencoded 방식으로 로그인함 => username=ssar&password=1234
//                아래는 json이고 이번엔 json으로 parsing할꺼임
//                {
//                    "username" : "gosu",
//                    "password" : 1234
//                }
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);  // User(id=0, username=gosu, password=1234, roles=null)

            UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // authenticationManager.authenticate(authenticationToken)이 실행되면
            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            // 정상이면 authentication이 return
            // 이 의미는 DB에 있는 username과 password가 일치한다!
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            System.out.println("authentication: " + authentication);    // authentication: UsernamePasswordAuthenticationToken [Principal=PrincipalDetails(user=User(id=1, username=gosu, password=$2a$10$.8/L034xpX0qP3DEt02PM.P5RCnZZvsK37BSX/9MmayQfXfNahfWG, roles=USER)), Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[com.example.jwtbasic.auth.PrincipalDetails$$Lambda$1621/0x00000001257ab310@65ae190b]]

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            // principalDetails에 값이 잘 들어갔다면 => login이 되었다!
            System.out.println("principalDetails: " + principalDetails.getUsername()); // principalDetails: PrincipalDetails(user=User(id=1, username=gosu, password=$2a$10$.8/L034xpX0qP3DEt02PM.P5RCnZZvsK37BSX/9MmayQfXfNahfWG, roles=USER))
            System.out.println("principalDetails: " + principalDetails.getUser().getUsername());    // principalDetails.getUsername(), principalDetails.getUser().getUsername()이 두개는 같아
            // return authentication이 실행되면 => authentication 객체가 session영역에 저장됨
            // session에 저장하는 이유는 권한 관리를 security가 대신 해줘서 편하기 때문
            // jwt 토큰을 사용하면서 세션을 굳이 만들 이유는 없지만 권한 처리 때문에 session에 넣어줌
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    // jwt 토큰을 만들어서 request요청한 사용자에게 jwt토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult)
        throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증완료");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
            .withSubject(principalDetails.getUser().getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
            .withClaim("id", principalDetails.getUser().getId())
            .withClaim("username", principalDetails.getUser().getUsername())
            .sign(Algorithm.HMAC256("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
        System.out.println(jwtToken);
//        super.successfulAuthentication(request, response, chain, authResult); 이게 있으면 Authorization에 토큰이 안들어가
        
    }
}
