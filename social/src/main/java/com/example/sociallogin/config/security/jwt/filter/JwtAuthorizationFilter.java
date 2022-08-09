package com.example.sociallogin.config.security.jwt.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import com.example.sociallogin.config.security.jwt.JwtProperties;
import com.example.sociallogin.config.security.jwt.JwtUtils;
import com.example.sociallogin.entity.user.User;
import com.example.sociallogin.repository.user.UserRepository;

/*
    # 인가를 위한 필터
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private final UserRepository userRepository;

	private final List<String> nonAuthUrl = List.of("/user/login", "/winners", "/user-verify");

	private final List<String> bothAuthUrl = List.of("/posts", "/comments", "/best-comments");

	public JwtAuthorizationFilter(
		AuthenticationManager authenticationManager,
		UserRepository userRepository
	) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	@Override
	protected void doFilterInternal(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain chain
	) throws IOException, ServletException {
		String requestUrl = request.getRequestURI();
		String method = request.getMethod();
		if (!nonAuthUrl.contains(requestUrl)) {
			String accessToken = getAccessToken(request);
			String refreshToken = getRefreshToken(request);
			if (idValidAccessToken(accessToken)) {
				logger.info("accessToken : " + accessToken);
				addAuthenticationTokenInSecurityContext(accessToken);
			} else if (isValidRefreshToken(refreshToken)) {
				logger.info("refreshToken : " + refreshToken);
				addAuthenticationAfterRefreshTokenValidation(response, requestUrl, method, refreshToken);
			}
		}

		chain.doFilter(request, response);
	}

	private void addAuthenticationAfterRefreshTokenValidation(
		HttpServletResponse response,
		String requestUrl,
		String method,
		String refreshToken
	) {
		User user = userRepository.findUserByRefreshToken(refreshToken).orElse(null);
		if (user != null) {
			String newAccessToken = getNewAccessToken(response, requestUrl, method, user);
			logger.info("newAccessToken : " + newAccessToken);
			addAuthenticationTokenInSecurityContext(newAccessToken);
			// String newRefreshToken = JwtUtils.makeRefreshTokenCookie(response, user.getUserId());
			// userRepository.updateUserRefreshTokenByUserId(user.getUserId(), newRefreshToken);
			/*
				- 리프레시 토큰 탈취
					- 악의적인 사용자가 리프레시 토큰 탈취 시 access token 을 만료시간까지 계속 발급받을 수 있다.
				- 대응방안
					1. refresh token 을 access token 과 같이 갱신 후 refresh token 이 다르면 폐기
					2. access token 도 같이 1대1로 저장 후 다를 경우 폐기 (redis)
			*/
		} /*else {
			logger.info("remove refresh token cookie");
			Long userId = JwtUtils.getUserId(refreshToken);
			userRepository.updateUserRefreshTokenByUserId(userId, null);
			removeRefreshTokenCookie(response);
		}*/
	}

	private String getNewAccessToken(
		HttpServletResponse response,
		String requestUrl,
		String method,
		User user
	) {
		if (method.equals("GET") && bothAuthUrl.contains(requestUrl))
			return createNewAccessTokenWithOutHeader(user);
		else
			return createNewAccessToken(response, user);
	}

	private void removeRefreshTokenCookie(HttpServletResponse response) {
		Cookie refreshTokenCookie = new Cookie(JwtProperties.JWT_REFRESH_HEADER, null);
		refreshTokenCookie.setMaxAge(0);
		response.addCookie(refreshTokenCookie);
	}

	private String createNewAccessToken(
		HttpServletResponse response,
		User user
	) {
		String newAccessToken = JwtUtils.createAccessToken(user);
		response.addHeader(JwtProperties.JWT_ACCESS_HEADER, newAccessToken);
		return newAccessToken;
	}

	private String createNewAccessTokenWithOutHeader(User user) {
		return JwtUtils.createAccessToken(user);
	}

	private void addAuthenticationTokenInSecurityContext(String accessToken) {
		Long userId = JwtUtils.getUserId(accessToken);
		String role = JwtUtils.getUserRole(accessToken);
		logger.info("role : " + role);
		logger.info("userId : " + userId);
		SecurityContextHolder.getContext().setAuthentication(getAuthenticationToken(userId, role));
	}

	private UsernamePasswordAuthenticationToken getAuthenticationToken(
		Long userId,
		String role
	) {
		if (userId != null) {
			logger.info("add auth token");
			return new UsernamePasswordAuthenticationToken(userId, null, List.of(new SimpleGrantedAuthority(role)));
		}
		return null;
	}

	private String getRefreshToken(HttpServletRequest request) {
		try {
			return Arrays.stream(request.getCookies())
				.filter(cookie -> cookie.getName().equals(JwtProperties.JWT_REFRESH_HEADER))
				.findFirst()
				.map(Cookie::getValue)
				.orElse(null);
		} catch (Exception e) {
			return null;
		}
	}

	private String getAccessToken(HttpServletRequest request) {
		String bearerToken = request.getHeader(JwtProperties.JWT_ACCESS_HEADER);
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(JwtProperties.TOKEN_PREFIX))
			return bearerToken.substring(7);
		else
			return null;
	}

	private boolean isValidRefreshToken(String refreshToken) {
		return refreshToken != null && JwtUtils.validateToken(refreshToken);
	}

	private boolean idValidAccessToken(String accessToken) {
		return accessToken != null && JwtUtils.validateToken(accessToken);
	}
}
