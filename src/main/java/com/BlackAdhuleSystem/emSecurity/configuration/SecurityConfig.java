package com.BlackAdhuleSystem.emSecurity.configuration;

import com.BlackAdhuleSystem.emSecurity.filter.JwtFilter;
import com.BlackAdhuleSystem.emSecurity.service.CustomUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailService customUserDetailService;
    private final JwtProperties JwtProperties;

    /**
     * Bean pour encoder les mots de passe avec BCrypt
     * (très utilisé pour sécuriser les mots de passe dans Spring Security)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Bean pour récupérer le gestionnaire d’authentification (AuthenticationManager)
     * Ce gestionnaire sera utilisé pour authentifier un utilisateur lors du login.
     */
    @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http,PasswordEncoder passwordEncoder) throws Exception{
        AuthenticationManagerBuilder authenticationManagerBuilder=http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder);
        return  authenticationManagerBuilder.build();
    }
    /**
     * Configuration principale de la sécurité HTTP
     * - Désactive CSRF (utile pour les API REST)
     * - Autorise certaines routes publiques (ex: /app/auth/*)
     * - Exige une authentification JWT pour toutes les autres routes
     * - Ajoute le filtre JWT avant le filtre standard d’authentification
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return  http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth-> auth
                        .requestMatchers("/api/auth/*").permitAll() // La route de login/inscription est publique
                        .anyRequest().authenticated()                 // TOUTES les autres routes nécessitent un utilisateur authentifié (JWT)
                )
                // ... (Le reste de votre configuration)
                .addFilterBefore(new JwtFilter(customUserDetailService,JwtProperties),UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
