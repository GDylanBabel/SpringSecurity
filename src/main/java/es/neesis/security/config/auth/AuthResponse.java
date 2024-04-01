package es.neesis.security.config.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    public String token;
    public HttpStatus status;
    public String reason; // No se si tiene sentido realmente
}
