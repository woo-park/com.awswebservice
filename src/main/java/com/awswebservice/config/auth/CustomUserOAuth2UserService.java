package com.awswebservice.config.auth;


import com.awswebservice.config.auth.dto.OAuthAttributes;
import com.awswebservice.config.auth.dto.SessionUser;
import com.awswebservice.domain.user.Account;
import com.awswebservice.domain.user.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomUserOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final AccountRepository accountRepository;
    private final HttpSession httpSession;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService delagate = new DefaultOAuth2UserService();

        OAuth2User oAuth2User = delagate.loadUser(userRequest);         // userRequest from argument

        String registrationId = userRequest
                                        .getClientRegistration()
                                        .getRegistrationId();    // to figure out/ differentiate from naver, or google login

        String userNameAttributeName = userRequest
                                                .getClientRegistration()
                                                .getProviderDetails()
                                                .getUserInfoEndpoint()
                                                .getUserNameAttributeName();    // naver vs google

        OAuthAttributes attributes = OAuthAttributes.
                                        of(registrationId, userNameAttributeName, oAuth2User.getAttributes()); //   OAuth2UserService 를 통해 가져온 data 를 담는 class입니다

        Account user = saveOrUpdate(attributes);   // saveOrUpdate method needs to be defined here

        httpSession.setAttribute("user", new SessionUser(user));    //  session 에 사용자 정보를 저장하기 위한 dto class

        return new DefaultOAuth2User(
                Collections.singleton(
//                        new SimpleGrantedAuthority(user.getRoleKey())), // userRole 이 class일적에
                        new SimpleGrantedAuthority(user.getUserRole())),
                        attributes.getAttributes(),
                        attributes.getNameAttributeKey()
        );
    }

    private Account saveOrUpdate(OAuthAttributes attributes) {
        Account user = accountRepository.findByEmail(attributes.getEmail())
                .map(entity -> entity.update(attributes.getName(), attributes.getPicture()))    //update takes in two args
                .orElse(attributes.toEntity()); // if findByEmail fails

        // User user Entity made
        return accountRepository.save(user);   // now saved to repo
    }

}
