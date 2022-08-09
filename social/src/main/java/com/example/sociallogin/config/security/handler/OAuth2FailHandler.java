package com.example.sociallogin.config.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import com.example.sociallogin.constants.ErrorCode;

public class OAuth2FailHandler extends SimpleUrlAuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(
		HttpServletRequest request,
		HttpServletResponse response,
		AuthenticationException exception
	) throws IOException, ServletException {
		System.out.println("------------------- OAuth2FailHandler -------------------");
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ErrorCode.BAD_REQUEST.getMessage());
	}
}
