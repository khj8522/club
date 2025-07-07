package org.zerock.club.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.club.security.filter.ApiCheckFilter;
import org.zerock.club.security.filter.ApiLoginFilter;
import org.zerock.club.security.handler.ClubLoginSuccessHandler;

@Configuration
@EnableWebSecurity
@Log4j2
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 사용 안함
//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails user = User.builder()
//                .username("user1")
//                .password(passwordEncoder().encode("1111"))
//                .roles("USER")
//                .build();
//        return new  InMemoryUserDetailsManager(user);
//    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {

        log.info("-----------------------filterChain---------------------------");

//        http.authorizeHttpRequests(auth ->
//                        auth.requestMatchers("/sample/all").permitAll()
//                            .requestMatchers("/sample/member").hasRole("USER")
//
//
//        )
        http.formLogin(Customizer.withDefaults()); // 폼 로그인 기능을 기본설정으로 활성화
        http.logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
        )
        .csrf(csrf -> csrf.disable()); // csrf 비활성화(API 테스트) (외부 REST 방식 사용 예제 프로젝트)

        http.oauth2Login(oauth2 ->
                oauth2.successHandler(successHandler())
        );

        http.rememberMe().tokenValiditySeconds(60*60*24*7); // 빨간줄 무시? 해도 댐

        http.addFilterBefore(apiCheckFilter(), UsernamePasswordAuthenticationFilter.class);

        // Spring이 자동으로 만든 인증기를 가져옴
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        // 가져온 인증기를 Manager에 빌드해줌
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        //필수 ( 인증방법 설정)
        http.authenticationManager(authenticationManager);

        //ApiLoginFilter
        ApiLoginFilter apiLoginFilter = new ApiLoginFilter("/api/login");
        apiLoginFilter.setAuthenticationManager(authenticationManager);
        // ApiLoginFilter의 인증 방법 설정


        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public ClubLoginSuccessHandler successHandler() {
        return new ClubLoginSuccessHandler(passwordEncoder());
    }

    @Bean
    public ApiCheckFilter apiCheckFilter() {
        return new ApiCheckFilter("/notes/**/*");
    }

}
