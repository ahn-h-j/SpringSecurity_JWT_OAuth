package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

//Oauth 후처리
//해당 메서드 종료시 @Authentication 이 만들어짐
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    UserRepository userRepository;
    //구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code 리턴 -> access token 요청
    //userRequest 정보 -> loadUser 함수 호출 -> 구글로 부터 회원 프로필 받음
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //registrationId로 어떤 OAuth로 로그인 했는지 확인가능
        OAuth2User oAuth2User = super.loadUser(userRequest);

        OAuth2UserInfo oAuth2UserInfo = null;
        if(userRequest.getClientRegistration().getRegistrationId().equalsIgnoreCase("google")){
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equalsIgnoreCase("facebook")){
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if(userRequest.getClientRegistration().getRegistrationId().equalsIgnoreCase("naver")){
            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        }else {
            System.out.println("구글, 페이스북, 네이버 외에 로그인은 지원하지 않습니다");
        }


        //회원가입
        String provider = oAuth2UserInfo.getProvider();//google
        String providerId = oAuth2UserInfo.getProviderId();//10974285618296427686
        String username = provider + "_" + providerId;//google_10974285618296427686
        String password = bCryptPasswordEncoder.encode("겟인데어");//의미는 없음
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if(userEntity == null){
            System.out.println("구글 로그인이 최초입니다");
            userEntity = User.builder()
                            .username(username)
                            .password(password)
                            .email(email)
                            .role(role)
                            .provider(provider)
                            .providerId(providerId)
                            .build();
            userRepository.save(userEntity);
        }else{
            System.out.println("이전에 구글 로그인 기록이 있습니다. 회원가입 이미 완료");
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
