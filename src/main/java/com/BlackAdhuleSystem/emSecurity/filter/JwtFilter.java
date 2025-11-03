package com.BlackAdhuleSystem.emSecurity.filter;

import com.BlackAdhuleSystem.emSecurity.configuration.JwtProperties;
import com.BlackAdhuleSystem.emSecurity.service.CustomUserDetailService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final CustomUserDetailService customUserDetailService;
    private final JwtProperties jwtProperties;

    /**
     * Cette méthode s’exécute une seule fois par requête HTTP.
     * Elle vérifie la présence d’un token JWT valide et, si oui,
     * configure le contexte de sécurité Spring avec l’utilisateur authentifié.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        //  Récupération du header Authorization dans la requête HTTP
        final String authHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        //  Vérification : le header doit exister et commencer par "Bearer "
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // On récupère le token en enlevant "Bearer "
            jwt = authHeader.substring(7);
            try {
                // Extraction du nom d’utilisateur contenu dans le token
                username = jwtProperties.extractUsername(jwt);
            } catch (Exception e) {
                // Si le token est mal formé ou expiré, on ignore et on continue
                System.out.println(" Erreur lors de la lecture du token : " + e.getMessage());
            }
        }

        //  Si on a un nom d’utilisateur valide et qu’aucune authentification n’est encore active
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Récupération de l’utilisateur depuis la base (UserDetailsService)
            UserDetails userDetails = customUserDetailService.loadUserByUsername(username);

            // Vérification que le token est valide pour cet utilisateur
            if (jwtProperties.validateToken(jwt, userDetails)) {

                // Création d’un objet d’authentification avec les rôles de l’utilisateur
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,      // utilisateur
                                null,             // pas de mot de passe ici
                                userDetails.getAuthorities() // rôles/permissions
                        );

//                // Attache des détails de la requête (IP, session, etc.)
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //  Mise à jour du contexte de sécurité Spring
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        //  Passage de la requête au filtre suivant
        filterChain.doFilter(request, response);
    }
}
