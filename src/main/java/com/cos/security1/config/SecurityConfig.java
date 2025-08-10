package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 필터 체인 관리 시작 어노테이션
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig { // WebSecurityConfigurerAdapter 상속 제거

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 1. CSRF 보호 비활성화 (최신 방식)
        http.csrf(AbstractHttpConfigurer::disable);

        // 2. URL 인가(Authorization) 규칙 설정 (최신 방식)
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").authenticated() // "/user/**" 경로는 인증 필요
                .requestMatchers("/admin/**").hasRole("ADMIN") // "/admin/**" 경로는 ADMIN 역할 필요
                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                .anyRequest().permitAll() // 나머지 모든 요청은 허용
        );

        // 3. 폼 로그인 설정 (최신 방식)
        http.formLogin(form -> form
                .loginPage("/loginForm") // 커스텀 로그인 페이지 경로
                .loginProcessingUrl("/login") // 로그인 처리 URL (이 URL로 오는 요청을 시큐리티가 가로채서 로그인 처리) 컨트롤러를 만들 필요가 없어짐
                .defaultSuccessUrl("/") // loginForm에서 로그인 하면 /로 보내줌 but 다른 페이지에서 로그인 시도하면 해당 페이지로 이동함
        );

        // 4. OAuth2 로그인 설정 추가
        http.oauth2Login(oauth2 -> oauth2
                .loginPage("/loginForm") // 폼 로그인과 동일한 로그인 페이지 사용
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(principalOauth2UserService) // 이 부분이 핵심! OAuth2 로그인 성공 시, 유저 정보를 가지고 우리가 만든 서비스 클래스의 loadUser 메소드를 호출
                )
                //1. 코드 받기
                //2. 액세스 토큰 받기
                //3. 사용자 프로필 가져옴
                //4-1. 그 정보를 토대로 회원가입 자동 진행
                //4-2. 부족한 정보를 추가하여 회원가입
        );

        return http.build();
    }
}