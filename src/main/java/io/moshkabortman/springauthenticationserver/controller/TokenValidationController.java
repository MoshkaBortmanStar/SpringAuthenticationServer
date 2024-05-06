package io.moshkabortman.springauthenticationserver.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.moshkabortman.springauthenticationserver.component.JwtTokenProvider;
import io.moshkabortman.springauthenticationserver.data.JwtAuthenticationResponse;
import io.moshkabortman.springauthenticationserver.data.LoginRequest;
import io.moshkabortman.springauthenticationserver.data.TokenValidationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
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
    public boolean validateToken(@RequestBody TokenValidationRequest request) {
        String token = request.getToken();
        return tokenProvider.validateToken(token);
    }


    @GetMapping("api/auth/validateToken")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        String jwt = tokenProvider.generateToken(authentication);
        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }
}
