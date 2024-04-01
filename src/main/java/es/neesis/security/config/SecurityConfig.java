package es.neesis.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authRequest ->
                        authRequest
                                .requestMatchers(antMatcher("/WEB-INF/**")).permitAll()
                                .requestMatchers("/register").permitAll()
                                .requestMatchers("/login").permitAll()
                                .requestMatchers(antMatcher("/h2-console/**")).permitAll()
                                .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/home")
                        .permitAll()
                )
                .logout(LogoutConfigurer::permitAll)
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sessionManager ->
                        sessionManager
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> httpSecurityOAuth2ResourceServerConfigurer.jwt(jwtConfigurer -> {
                }))
                .authenticationProvider(authProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
        // TODO el siguiente código da un ClassNotFoundException (dependencias?)
//        return http.
//                csrf(AbstractHttpConfigurer::disable).
//                cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configure(http))
//                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry.
//                        requestMatchers(HttpMethod.GET, "/user/info", "/api/foos/**").hasAuthority(""))
//                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer ->
//                        httpSecurityOAuth2ResourceServerConfigurer.
//                                jwt(jwtConfigurer -> {
//                                }))
//                .sessionManagement(httpSecuritySessionManagementConfigurer -> {
//                    httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//                })
//                .authenticationProvider(authProvider)
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
    }

}
