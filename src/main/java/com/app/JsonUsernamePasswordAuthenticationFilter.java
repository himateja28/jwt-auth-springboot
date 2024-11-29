package com.app;

import java.io.IOException;
import java.security.Key;
import java.util.Date;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // Define JWT expiration time (24 hours in milliseconds)
    private static final long JWT_EXPIRATION_TIME = 86400000;

    // Secret key (should be stored securely in environment variables or a config file)
    private static final String JWT_SECRET = "AcCZ-xa-2E_TJe85G2VHEf2yd64vAeRSQsUpW3SVABVcPwqkrO3GVLGuGtNHKiAi62xH0d35U6yG_HZklm32fA";

    public JsonUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // Override attemptAuthentication to parse JSON request body
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            // Parse the JSON request body to get username and password
            Map<String, String> credentials = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            String username = credentials.get("username");
            String password = credentials.get("password");

            // Create authentication token using parsed credentials
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

            // Delegate authentication to the AuthenticationManager
            return authenticationManager.authenticate(authToken);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse authentication request body", e);
        }
    }

    // Method to get signing key securely
    private Key getSigningKey() {
        try {
            // Specify the algorithm for HMAC (HS512 in this case)
            String algorithm = "HmacSHA512"; 
            
            // Use the JWT secret key to generate the signing key
            SecretKeySpec signingKey = new SecretKeySpec(JWT_SECRET.getBytes(), algorithm);
            
            // Return the signing key (you could also return the result of Mac.getInstance() if needed)
            return signingKey;
        } catch (Exception e) {
            throw new RuntimeException("Error generating signing key", e);
        }
    }

    // Override successfulAuthentication to generate and send JWT token
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // Generate the JWT token
        String token = generateJwtToken(authResult.getName());

        // Send the JWT token in the response body
        response.setContentType("application/json");
        response.getWriter().write("{\"token\":\"" + token + "\"}");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    // Override unsuccessfulAuthentication to handle authentication failures
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("{\"error\": \"Invalid login credentials\"}");
    }

    // Method to generate the JWT token
    private String generateJwtToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION_TIME);

        // Build the JWT token with subject (username), issue date, and expiration date
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(getSigningKey())  // Use the secure signing key
            .compact();
    }
}
