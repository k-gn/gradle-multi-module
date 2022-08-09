package com.example.sociallogin.config.security.oauth;

import java.util.Map;
import java.util.Objects;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.example.sociallogin.config.security.auth.PrincipalDetails;
import com.example.sociallogin.config.security.oauth.provider.FacebookUserInfo;
import com.example.sociallogin.config.security.oauth.provider.GoogleUserInfo;
import com.example.sociallogin.config.security.oauth.provider.KakaoUserInfo;
import com.example.sociallogin.config.security.oauth.provider.NaverUserInfo;
import com.example.sociallogin.config.security.oauth.provider.OAuth2UserInfo;
import com.example.sociallogin.constants.Auth;
import com.example.sociallogin.constants.LoginType;
import com.example.sociallogin.entity.user.User;
import com.example.sociallogin.repository.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	private final UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("userRequest : " + userRequest);
		OAuth2User oAuth2User = super.loadUser(userRequest);
		System.out.println("oAuth2User.getAttributes() : " + oAuth2User.getAttributes());
		LoginType type = null;
		OAuth2UserInfo oAuth2UserInfo = null;
		switch (userRequest.getClientRegistration().getRegistrationId()) {
			case "google":
				oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
				type = LoginType.GOOGLE;
				break;
			case "kakao":
				oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
				type = LoginType.KAKAO;
				break;
			case "naver":
				oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
				type = LoginType.NAVER;
				break;
			case "facebook":
				oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
				type = LoginType.FACEBOOK;
				break;
		}

		try {
			User user = getUser(type, Objects.requireNonNull(oAuth2UserInfo));
			return new PrincipalDetails(user, oAuth2User.getAttributes());
		} catch (Exception ex) {
			throw new OAuth2AuthenticationException("OAuth2 auth is fail");
		}
	}

	private User getUser(
		LoginType type,
		OAuth2UserInfo oAuth2UserInfo
	) {
		String providerId = oAuth2UserInfo.getProviderId();
		String email = oAuth2UserInfo.getEmail();
		String username = oAuth2UserInfo.getName();
		// String phone = oAuth2UserInfo.getPhone();

		User user = userRepository.findUserByUsername(providerId + "_" + email).orElse(null);
		if (user == null)
			user = registerUser(type, providerId, email);
		return user;
	}

	private User registerUser(
		LoginType type,
		String providerId,
		String email
	) {
		User user = User.builder().username(providerId + "_" + email).loginType(type).role(Auth.ROLE_USER).build();
		userRepository.save(user);
		return user;
	}
}
