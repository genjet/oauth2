package com.example.oauth2.config;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/login.html").permitAll().anyRequest().authenticated().and().oauth2Login()
				.loginPage("/login.html").defaultSuccessUrl("/success.html");
	}

	@Bean
	public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
		return new GrantedAuthoritiesMapper() {

			@Override
			public Collection<? extends GrantedAuthority> mapAuthorities(
					Collection<? extends GrantedAuthority> authorities) {
				Set<GrantedAuthority> mappedAuthorities = new HashSet<GrantedAuthority>();
				authorities.forEach(authority -> {
					mappedAuthorities.add(authority);
					if (OidcUserAuthority.class.isInstance(authority)) {
						OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
						Object email = oidcUserAuthority.getAttributes().get("email");
						if ("c8904026@gmail.com".equals(email.toString())) {
							mappedAuthorities.add(new OidcUserAuthority("ROLE_ADMIN", oidcUserAuthority.getIdToken(),
									oidcUserAuthority.getUserInfo()));
						}
					}
				});
				return mappedAuthorities;
			}
		};
	}
}
