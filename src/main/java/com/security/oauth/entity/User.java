package com.security.oauth.entity;

import com.security.oauth.enums.Role;
import lombok.*;

import javax.persistence.*;

@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String oAuth2Id;

    private String name;

    private String email;

    private String profileImageUrl;

    @Enumerated(EnumType.STRING)
    private Role role;
}
