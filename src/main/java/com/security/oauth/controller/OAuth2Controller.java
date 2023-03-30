package com.security.oauth.controller;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.sun.istack.Nullable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
public class OAuth2Controller {

    @GetMapping("/redirect")
    public String getToken(@Nullable String token, @Nullable String error) {
        if (StringUtils.isNotBlank(error)) {
            return error;
        } else {

            System.out.println("token : " + token);
            return token;
        }
    }
}
