package com.security.oauth.oauth2;

import com.security.oauth.entity.User;
import com.security.oauth.enums.AuthProvider;
import com.security.oauth.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

@Getter
@AllArgsConstructor
public abstract class OAuth2UserInfo {

    protected Map<String, Object> attributes;

    public abstract String getOAuth2Id();
    public abstract String getEmail();
    public abstract String getName();
}
