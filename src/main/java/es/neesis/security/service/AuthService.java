package es.neesis.security.service;

import es.neesis.security.config.auth.AuthResponse;
import es.neesis.security.model.User;
import es.neesis.security.model.UserRole;
import es.neesis.security.model.dto.UserDTO;
import es.neesis.security.repository.UserRepository;
import es.neesis.security.utils.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthResponse login(UserDTO userDTO) {
        String password = passwordEncoder.encode(userDTO.getPassword());
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDTO.getUsername(), password));
        UserDetails user = userRepository.findByUsername(userDTO.getUsername());
        return AuthResponse.builder().token(jwtService.getToken(user)).build(); // TODO puede fallar si es null (?)
    }

    public AuthResponse register(UserDTO userDTO) {
        User user = UserMapper.convertToEntity(userDTO);
        String password = passwordEncoder.encode(userDTO.getPassword());
        user.setPassword(password);
        user.setRole(UserRole.USER);
        user.setEnabled(true);
        User cloned = userRepository.findByUsername(user.getUsername());
        if (cloned == null) {
            userRepository.save(user);
        } else {
            return AuthResponse.builder().status(HttpStatus.BAD_REQUEST).reason("User already exists").build();
        }
        return AuthResponse.builder().token(jwtService.getToken(user)).status(HttpStatus.OK).build();
    }

}
