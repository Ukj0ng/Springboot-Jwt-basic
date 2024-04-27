package com.example.jwtbasic.repository;

import com.example.jwtbasic.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {
    // findBy규칙 -> Username, Jpa query methods
    // select * from user where username = 1?
    User findByUsername(String username);
}
