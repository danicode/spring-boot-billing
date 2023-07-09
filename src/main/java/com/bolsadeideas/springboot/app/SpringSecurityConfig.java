package com.bolsadeideas.springboot.app;

//import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.bolsadeideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SpringSecurityConfig {
	
	@Autowired
	private LoginSuccessHandler successHandler;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	/*@Autowired
	private DataSource dataSource;*/
	
	 @Autowired
     private JpaUserDetailsService userDetailService;
	 
	 @Autowired
	 public void userDetailsService(AuthenticationManagerBuilder build) throws Exception {
		 build.userDetailsService(userDetailService)
        .passwordEncoder(passwordEncoder);
	 }

	// Registrar usuarios
	/*@Bean
	public static BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}*/
	
	/*@Bean
    public UserDetailsService userDetailsService() throws Exception {
		
		PasswordEncoder encoder = this.passwordEncoder;

        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
 
        manager.createUser(User.withUsername("danicode")
                               //.password(passwordEncoder().encode("1234"))
                               .password(encoder.encode("1234"))
                               .roles("USER").build());
 
        manager.createUser(User.withUsername("admin")
                               //.password(passwordEncoder().encode("1234"))
                               .password(encoder.encode("1234"))
                               .roles("ADMIN", "USER").build());
 
        return manager;
    }*/
	
	/*@Bean
    AuthenticationManager authManager(HttpSecurity http) throws Exception {*/
		
        // Configure AuthenticationManagerBuilder
        /*AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
        	.jdbcAuthentication()
        	.dataSource(dataSource)
        	.passwordEncoder(passwordEncoder)
        	.usersByUsernameQuery("select username, password, enabled from users where username=?")
        	.authoritiesByUsernameQuery("select u.username, a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?");

        // Get AuthenticationManager
        return authenticationManagerBuilder.build();*/

       /* return http.getSharedObject(AuthenticationManagerBuilder.class)
                .jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(passwordEncoder)
                .usersByUsernameQuery("select username, password, enabled from users where username=?")
                .authoritiesByUsernameQuery("select u.username, a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?")
                .and().build();
    }
	*/
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		// FOrma anterior
        /*http.authorizeHttpRequests()
            .requestMatchers("/", "/css/**", "/js/**", "/images/**", "/listar").permitAll()
            .requestMatchers("/ver/**").hasAnyRole("USER")
            .requestMatchers("/uploads/**").hasAnyRole("USER")
            .requestMatchers("/form/**").hasAnyRole("ADMIN")
            .requestMatchers("/eliminar/**").hasAnyRole("ADMIN")
            .requestMatchers("/factura/**").hasAnyRole("ADMIN")
            .anyRequest().authenticated()
            .and()
            .formLogin().permitAll()
            .and()
            .logout().permitAll();
 
        return http.build();*/
		
		// Configure AuthenticationManagerBuilder
        /*AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
	    	.jdbcAuthentication()
	    	.dataSource(dataSource)
	    	.passwordEncoder(passwordEncoder)
	    	.usersByUsernameQuery("select username, password, enabled from users where username=?")
	    	.authoritiesByUsernameQuery("select u.username, a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?");
        // Get AuthenticationManager
        AuthenticationManager authenticationManager =  authenticationManagerBuilder.build();*/

		http.authorizeHttpRequests(authz -> authz
    		.requestMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/listarx", "/locale", "/api/clientes/**").permitAll()
            /*.requestMatchers("/ver/**").hasAnyRole("USER")
            .requestMatchers("/uploads/**").hasAnyRole("USER")
            .requestMatchers("/form/**").hasAnyRole("ADMIN")
            .requestMatchers("/eliminar/**").hasAnyRole("ADMIN")
            .requestMatchers("/factura/**").hasAnyRole("ADMIN")
            .anyRequest().authenticated()*/
        )
		//.authenticationManager(authenticationManager)
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
		//http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll());

		return http.build();
	}
	
	
}
