package com.example.sociallogin.config.security.oauth.provider;

public interface OAuth2UserInfo {

	String getProviderId();

	String getProvider();

	String getEmail();

	String getName();
	// String getPhone();
}
