package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.ObjectUtils;

import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.auth.service.JWTServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTService jwtService;
	private List<String> publicEndpoints;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
		
		// Configura las rutas públicas que no requieren autorización
        //this.publicEndpoints = Arrays.asList("/listar-rest", "/api/clientes/**", "/api/clientes**");
        this.publicEndpoints = Arrays.asList("/listar-rest", "/api/clientes/**", "/images/**");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader(JWTServiceImpl.HEADER_STRING);
		
		// Verifica si el endpoint es público y no requiere autorización
        if (isPublicEndpoint(request)) {
            chain.doFilter(request, response);
            return;
        }

		if (!requiresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = null;

		if (jwtService.validate(header)) {

			authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null, jwtService.getRoles(header));
		}

		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}

	protected boolean requiresAuthentication(String header) {

		if (ObjectUtils.isEmpty(header) && !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
			return false;
		}
		return true;
	}
	
	private boolean isPublicEndpoint(HttpServletRequest request) {
        /**String requestURI = request.getRequestURI();
        return publicEndpoints.contains(requestURI);*/
        
        String requestURI = request.getRequestURI();
        for (String publicEndpoint : publicEndpoints) {
            if (new AntPathMatcher().match(publicEndpoint, requestURI)) {
                return true;
            }
        }
        return false;
    }

}
