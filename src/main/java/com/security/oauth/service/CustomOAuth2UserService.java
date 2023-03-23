package com.security.oauth.service;

import com.security.oauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

        //OAuth2 로그인 진행중인 서비스 구분
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        //nameAttributeKey OAuth2 로그인 진행 시 키가 되는 필드를 가리킨다.
        //구글의 경우 기본적으로 'sub' 로 지원하지만, 네이버와 카카오는 기본 지원을 하지 않는다.
        //OAuth2 로그인 시 키 값(google: "sub", naver: "response", kakao: "id")
        String userNameAttributeName = oAuth2UserRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();




        return null;
    }
}
