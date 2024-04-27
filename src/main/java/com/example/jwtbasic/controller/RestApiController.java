package com.example.jwtbasic.controller;

import com.example.jwtbasic.auth.PrincipalDetails;
import com.example.jwtbasic.model.User;
import com.example.jwtbasic.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    @Autowired
    private final BCryptPasswordEncoder encoder;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        user.setRoles("USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    // user, manager, admin 접근 가능
    @GetMapping("/api/v1/user")
    public String user(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication: " + principalDetails.getUsername());
        return "user";
    }

    // manager, admin 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    // admin 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
