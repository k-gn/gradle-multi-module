package com.example.sociallogin.config.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import com.example.sociallogin.config.security.auth.PrincipalDetails;
import com.example.sociallogin.config.security.jwt.JwtProperties;
import com.example.sociallogin.config.security.jwt.JwtUtils;
import com.example.sociallogin.repository.user.UserRepository;

public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private final UserRepository userRepository;

	public OAuth2SuccessHandler(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication
	) throws IOException, ServletException {
		System.out.println("--------------- oauth2 success handler ---------------");
		PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
		setTokenResponse(response, principalDetails);
		getRedirectStrategy().sendRedirect(request, response, "http://localhost:8080");
	}

	private void setTokenResponse(
		HttpServletResponse response,
		PrincipalDetails principalDetails
	) {
		String accessToken = JwtUtils.createAccessToken(principalDetails.getUser());
		response.setHeader(JwtProperties.JWT_ACCESS_HEADER, accessToken);
		JwtUtils.makeRefreshTokenCookie(response, principalDetails.getUser().getUserId());
	}
}

/*
	TODO
		- 회원가입 x
			1. oauth2 과정을 거친 후 가져온 정보들로 간편가입 (이때 쿠키와 헤더 반환)
			2. 이 후 추가정보 입력페이지로 관련 정보가 필요한 요청 시 유도
		- 회원가입 o
			1. oauth2 과정을 거친 후 회원가입 url로 리다이렉트
			2. 리다이렉트 시 header 같은 곳에 가져온 사용자 고유 id와 email 정보를 담는다.
			3. 해당 정보와 추가 입력 정보를 통해 사용자는 회원가입 진행
			4. 이 후 db에 사용자 있을 시 리다이렉트 주소를 회원가입 페이지에서 다른 곳으로 변경 후 로그인 처리 (이때 쿠키와 헤더 반환)
 */