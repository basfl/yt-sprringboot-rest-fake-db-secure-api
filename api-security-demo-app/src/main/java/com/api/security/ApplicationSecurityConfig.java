package com.api.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.api.security.ApplicationUserRole.*;

import java.sql.Time;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;

	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		// super.configure(http);
		// http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
		http.csrf().disable().authorizeRequests().antMatchers("/", "index", "/css/*", "/js/*").permitAll()
				.antMatchers("/api/**").hasAnyRole(STUDENT.name()).anyRequest().authenticated().and().formLogin()
				.loginPage("/login").permitAll().defaultSuccessUrl("/courses", true).passwordParameter("password")
				.usernameParameter("username").and().rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toMicros(21))
				.rememberMeParameter("remember-me").key("supersecurekey").and().logout().logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")).clearAuthentication(true)
				.invalidateHttpSession(true).deleteCookies("JSESSIONID", "remember-me").logoutSuccessUrl("/login");

	}

	@Override
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user1 = User.builder().username("user1").password(passwordEncoder.encode("123"))
				// .roles(STUDENT.name()) // ROLE_STUDENT
				.authorities(STUDENT.getGrantedAuthorities()).build();
		UserDetails user2 = User.builder().username("user2").password(passwordEncoder.encode("user2@123"))
				// .roles(ADMIN.name()) // ROLE_ADMIn
				.authorities(ADMIN.getGrantedAuthorities()).build();
		UserDetails user3 = User.builder().username("user3").password(passwordEncoder.encode("user3@123"))
//	                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
				.authorities(ADMINTRAINEE.getGrantedAuthorities()).build();
		return new InMemoryUserDetailsManager(user1, user2, user3);
	}

}
