package com.bolsadeideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.bolsadeideas.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.bolsadeideas.springboot.app.auth.filter.JWTAuthorizationFilter;
//import com.bolsadeideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SpringSecurityConfig {
	
	//@Autowired
	//private LoginSuccessHandler successHandler;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	 @Autowired
     private JpaUserDetailsService userDetailService;
	 
	 @Autowired
     private AuthenticationConfiguration authenticationConfiguration;
	 
	 @Autowired
	 private JWTService jwtService;
	 
	 @Autowired
	 public void userDetailsService(AuthenticationManagerBuilder build) throws Exception {
		 build.userDetailsService(userDetailService)
        .passwordEncoder(passwordEncoder);
	 }

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.csrf(
			csrf -> csrf.disable()
		).authorizeHttpRequests(authz -> authz
    		.requestMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/listarx", "/locale", "/api/clientes/**").permitAll()
        )
	    .addFilter(
    		new JWTAuthenticationFilter(authenticationConfiguration.getAuthenticationManager(), jwtService)
		)
	    .addFilter(
    		new JWTAuthorizationFilter(authenticationConfiguration.getAuthenticationManager(), jwtService)
		)
        .sessionManagement(
			session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		);

		return http.build();
		
		/*http.authorizeHttpRequests(authz -> authz
	    		.requestMatchers("/", "/css/**", "/js/**", "/images/**", "/listar", "/locale").permitAll()
	            .anyRequest().authenticated()
	        )
	        .formLogin(formLogin -> formLogin
	    		.successHandler(successHandler)
	            .loginPage("/login")
	            .permitAll()
	        )
	        .logout(logout -> logout
	    		.logoutSuccessUrl("/login?logout")
	    		.permitAll()
			).exceptionHandling((exceptionHandling) -> exceptionHandling
				.accessDeniedPage("/error_403")
			);

			return http.build();*/
	}
	
}
