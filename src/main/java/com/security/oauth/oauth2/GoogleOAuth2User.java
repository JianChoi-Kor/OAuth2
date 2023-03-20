package com.security.oauth.oauth2;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public class GoogleOAuth2User implements CustomOAuth2User {

    @Override
    public String getOAuth2Id() {
        return null;
    }

    @Override
    public String getEmail() {
        return null;
    }

    @Override
    public String getNickname() {
        return null;
    }

    @Override
    public String getNameAttributeKey() {
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }
}
