package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


// Google 인증
// 1. 코드받기 (인증)
// 2. 엑세스토큰 (사용자정보에 접근할 권한)
// 3. 사용자프로필 조회
// 4. 사용자프로필을 토대로 회원가입, 로그인 (후처리)
@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(
        securedEnabled = true, //secured 어노테이션으로 메소드별 권한설정이 가능하도록 함
        prePostEnabled = true //preAuthorize 어노테이션
)
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                // user 로 접근시 인증필요
                .antMatchers("/user/**").authenticated()
                //manager, admin 으로 접근시 접근 권한 필요
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN' or hasRole('ROLE_MANAGER'))")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll() //권한 허용
                .and()
                .formLogin()//권한없는 접근 시 로그인 페이지로 이동
                .loginPage("/loginForm") //로그인 페이지 설정
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행
                .defaultSuccessUrl("/") //로그인 성공시 이동할 페이지
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
        return http.build();
    }
}
