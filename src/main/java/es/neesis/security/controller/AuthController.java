package es.neesis.security.controller;

import es.neesis.security.config.auth.AuthResponse;
import es.neesis.security.model.dto.UserDTO;
import es.neesis.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("")
@RequiredArgsConstructor
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody UserDTO userDTO) {
        AuthResponse response = authService.login(userDTO);
        if (!response.getStatus().equals(HttpStatus.OK)) {
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody UserDTO registerDTO) {
        AuthResponse response = authService.register(registerDTO);
        if (!response.getStatus().equals(HttpStatus.OK)) {
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

}
