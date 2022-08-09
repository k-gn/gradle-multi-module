package com.example.sociallogin.config.security.jwt.filter;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.sociallogin.config.security.auth.PrincipalDetails;
import com.example.sociallogin.config.security.jwt.JwtProperties;
import com.example.sociallogin.config.security.jwt.JwtUtils;
import com.example.sociallogin.constants.ErrorCode;
import com.example.sociallogin.dto.user.UserLoginRequest;
import com.example.sociallogin.repository.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

/*
    # 인증을 위한 필터
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final UserRepository userRepository;

	public JwtAuthenticationFilter(
		AuthenticationManager authenticationManager,
		UserRepository userRepository
	) {
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
	}

	@Override
	public Authentication attemptAuthentication(
		HttpServletRequest request,
		HttpServletResponse response
	) throws AuthenticationException {
		return authenticationManager.authenticate(getUsernamePasswordAuthenticationToken(getAdminLoginDto(request)));
	}

	@Override
	protected void successfulAuthentication(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain chain,
		Authentication authResult
	) throws IOException, ServletException {
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		response.addHeader(JwtProperties.JWT_ACCESS_HEADER, JwtUtils.createAccessToken(principalDetails.getUser()));
		userRepository.updateUserRefreshTokenByUserId(principalDetails.getUser().getUserId(),
			JwtUtils.makeRefreshTokenCookie(response, principalDetails.getUser().getUserId())
		);
	}

	@Override
	protected void unsuccessfulAuthentication(
		HttpServletRequest request,
		HttpServletResponse response,
		AuthenticationException failed
	) throws IOException {
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, failed.getMessage());
	}

	private UserLoginRequest getAdminLoginDto(HttpServletRequest request) {
		try {
			return objectMapper.readValue(request.getInputStream(), UserLoginRequest.class);
		} catch (IOException exception) {
			throw new AuthenticationCredentialsNotFoundException(ErrorCode.BAD_REQUEST.getMessage());
		}
	}

	private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(
		UserLoginRequest userLoginRequest
	) {
		return new UsernamePasswordAuthenticationToken(userLoginRequest.getUsername(), userLoginRequest.getPassword(),
			new ArrayList<>()
		);
	}
}
