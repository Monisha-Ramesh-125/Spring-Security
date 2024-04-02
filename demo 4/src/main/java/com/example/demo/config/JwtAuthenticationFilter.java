package com.example.demo.config;

import com.example.demo.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor // if a variables are in final then this annotation will create a contructor for that final variable
public class JwtAuthenticationFilter extends OncePerRequestFilter {
private final JwtService jwtService;
private final UserDetailsService userDetailsService;
private final TokenRepository tokenRepository;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
                                  @NonNull  HttpServletResponse response,
                                  @NonNull  FilterChain filterChain)
                             throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization") ; //jwt token is send in this.Authorization is a header name.
        final String jwt;
        final String userEmail;
        // 1 st step of checking if the jwt token is present or not
        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        jwt = authHeader.substring(7); //extracting the jwt token
        userEmail= jwtService.extractUsername(jwt);     // extract the user email from jwt token //for this we need class to manipulate this token
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t->!t.isExpired() && !t.isRevoked())
                    .orElse(false);
            if(jwtService.isTokenValid(jwt,userDetails) && isTokenValid==true){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,null,userDetails.getAuthorities()
                ); // to update the the security context holder
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
                System.out.println(authToken);
            }

        }
        filterChain.doFilter(request,response);
  System.out.println("test");
    }}
