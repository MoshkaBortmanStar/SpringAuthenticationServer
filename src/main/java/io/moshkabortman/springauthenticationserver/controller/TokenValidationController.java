package io.moshkabortman.springauthenticationserver.controller;

import io.moshkabortman.springauthenticationserver.component.JwtTokenProvider;
import io.moshkabortman.springauthenticationserver.data.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenValidationController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserDetailsService userDetailsService; // Ваш сервис для работы с пользователями

    @PostMapping("api/auth/validateToken")
    public boolean validateToken(@RequestHeader("token") String token) {
        return tokenProvider.validateToken(token);
    }


    @PostMapping("api/auth/login")
    public ResponseEntity<String> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        return ResponseEntity.ok(tokenProvider.generateToken(authentication));
    }
}
