package com.example.sociallogin.config.security;

import java.util.List;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.example.sociallogin.config.security.handler.CustomLogoutSuccessHandler;
import com.example.sociallogin.config.security.handler.OAuth2FailHandler;
import com.example.sociallogin.config.security.handler.OAuth2SuccessHandler;
import com.example.sociallogin.config.security.jwt.JwtProperties;
import com.example.sociallogin.config.security.jwt.filter.JwtAuthenticationFilter;
import com.example.sociallogin.config.security.jwt.filter.JwtAuthorizationFilter;
import com.example.sociallogin.config.security.jwt.handler.JwtAuthenticationDeniedHandler;
import com.example.sociallogin.config.security.jwt.handler.JwtAuthenticationEntryPoint;
import com.example.sociallogin.config.security.oauth.PrincipalOauth2UserService;
import com.example.sociallogin.repository.user.UserRepository;

import lombok.RequiredArgsConstructor;

/*
    # Spring Security 설정 클래스
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final PrincipalOauth2UserService principalOauth2UserService;

	private final UserRepository userRepository;

	private final CorsFilter corsFilter;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.cors()
			.configurationSource(corsConfigurationSource())
			.and()
			.csrf()
			.disable()
			.formLogin()
			.disable()
			.httpBasic()
			.disable();

		http.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new JwtAuthenticationFilter(authenticationManager(), userRepository),
				UsernamePasswordAuthenticationFilter.class
			)
			.addFilterBefore(new JwtAuthorizationFilter(authenticationManager(), userRepository),
				BasicAuthenticationFilter.class
			);

		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.authorizeRequests().anyRequest().permitAll();

		http.exceptionHandling()
			.accessDeniedHandler(new JwtAuthenticationDeniedHandler())
			.authenticationEntryPoint(new JwtAuthenticationEntryPoint());

		http.oauth2Login()
			.successHandler(oauth2SuccessHandler())
			.failureHandler(oauth2FailHandler())
			.userInfoEndpoint()
			.userService(principalOauth2UserService);

		http.logout()
			.logoutUrl("/logout")
			.logoutSuccessHandler(logoutSuccessHandler())
			.invalidateHttpSession(true)
			.deleteCookies(JwtProperties.JWT_REFRESH_HEADER);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Bean
	public LogoutSuccessHandler logoutSuccessHandler() {
		return new CustomLogoutSuccessHandler();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();

		configuration.setAllowedOrigins(List.of("http://127.0.0.1:3000", "http://localhost:3000"));
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public AuthenticationSuccessHandler oauth2SuccessHandler() {
		return new OAuth2SuccessHandler(userRepository);
	}

	@Bean
	public AuthenticationFailureHandler oauth2FailHandler() {
		return new OAuth2FailHandler();
	}
}
