package com.example.sociallogin.config.security.oauth.provider;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo {

	private Map<String, Object> attributes;

	public NaverUserInfo(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	@Override
	public String getProviderId() {
		return (String)attributes.get("id");
	}

	@Override
	public String getProvider() {
		return "naver";
	}

	@Override
	public String getEmail() {
		return (String)attributes.get("email");
	}

	@Override
	public String getName() {
		return (String)attributes.get("name");
	}

    /*
    @Override
    public String getPhone() {
    	String temp = (String) attributes.get("mobile");
    	List<String> list = Arrays.asList(temp.split("-"));
    	String phone = "";
    	for(String str : list) phone = phone.concat(str);
    	return phone;
    }
    */
}
