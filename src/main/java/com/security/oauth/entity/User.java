package com.security.oauth.entity;

import com.security.oauth.enums.AuthProvider;
import com.security.oauth.enums.Role;
import com.security.oauth.oauth2.OAuth2UserInfo;
import lombok.*;

import javax.persistence.*;
import java.security.Provider;

@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class User extends BaseDateEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;

    private String name;

    private String oAuth2Id;

    @Enumerated(EnumType.STRING)
    private AuthProvider authProvider;

    @Enumerated(EnumType.STRING)
    private Role role;

    public User updateUser(OAuth2UserInfo oAuth2UserInfo) {
        this.name = oAuth2UserInfo.getName();
        this.oAuth2Id = oAuth2UserInfo.getOAuth2Id();

        return this;
    }
}
