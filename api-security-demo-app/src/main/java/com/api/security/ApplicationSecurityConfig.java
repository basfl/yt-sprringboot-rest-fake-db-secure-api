package com.api.security;

import static com.api.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.api.auth.ApplicationUserService;
import com.api.jwt.JwtTokenVerifier;
import com.api.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;

	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// super.configure(http);
		// http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
		http.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
		.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
		.addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)
		.authorizeRequests().antMatchers("/", "index", "/css/*", "/js/*").permitAll()
				.antMatchers("/api/**").hasAnyRole(STUDENT.name()).anyRequest().authenticated();
	}

//	@Override
//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails user1 = User.builder().username("user1").password(passwordEncoder.encode("123"))
//				// .roles(STUDENT.name()) // ROLE_STUDENT
//				.authorities(STUDENT.getGrantedAuthorities()).build();
//		UserDetails user2 = User.builder().username("user2").password(passwordEncoder.encode("user2@123"))
//				// .roles(ADMIN.name()) // ROLE_ADMIn
//				.authorities(ADMIN.getGrantedAuthorities()).build();
//		UserDetails user3 = User.builder().username("user3").password(passwordEncoder.encode("user3@123"))
////	                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//				.authorities(ADMINTRAINEE.getGrantedAuthorities()).build();
//		return new InMemoryUserDetailsManager(user1, user2, user3);
//	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

}
