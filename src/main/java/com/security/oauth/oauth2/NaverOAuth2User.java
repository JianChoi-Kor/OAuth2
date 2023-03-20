package com.security.oauth.oauth2;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public class NaverOAuth2User extends OAuth2UserInfo {

    public NaverOAuth2User(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getOAuth2Id() {
        return (String) attributes.get("response");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
