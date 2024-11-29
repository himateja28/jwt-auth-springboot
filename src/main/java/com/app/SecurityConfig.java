package com.app;

import java.util.Date;
import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.app.model.User;
import com.app.repo.UserRepo;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Configuration
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

    private final UserRepo userRepository;

    public SecurityConfig(UserRepo userRepository) {
        this.userRepository = userRepository;
    }

    private static final String JWT_SECRET = "e4bd7cd35440386059264256bc5c3a98e245b9cf542438c6a2af036aef798b2c";
    private static final long JWT_EXPIRATION_TIME = 86400000;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        http
            .cors().and() // Enable CORS
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/signup", "/user/signup", "/aboutus", "/contactus").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JsonUsernamePasswordAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .permitAll())
            .csrf().disable();

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // Generate JWT token
    private String generateJwtToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION_TIME);

        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(SignatureAlgorithm.HS512, JWT_SECRET)
            .compact();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            Optional<User> userOptional = userRepository.findByEmail(email);
            User user = userOptional.get();

            return org.springframework.security.core.userdetails.User
                    .withUsername(user.getEmail())
                    .password("{noop}" + user.getPassword()) // NoOp for plaintext password
                    .roles(user.getRole())
                    .build();
        };
    }

    // Configure CORS to allow requests from React app running on port 3000
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000") // Allow React app running on port 3000
                .allowedMethods("GET", "POST", "PUT", "DELETE") // Allow HTTP methods as needed
                .allowedHeaders("*") // Allow any header
                .allowCredentials(true); // Allow credentials (cookies, authorization headers)
    }
}
