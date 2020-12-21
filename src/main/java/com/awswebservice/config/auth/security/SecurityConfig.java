package com.awswebservice.config.auth.security;


//import com.wavestoked.domain.user.Role;
//import com.awswebservice.config.auth.CustomUserOAuth2UserService;
import com.awswebservice.domain.user.Role;
//import com.awswebservice.service.UserDetailServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
//@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {



//    private final CustomUserOAuth2UserService customUserOAuth2UserService;


//    @Autowired
//    UserDetailServiceImpl userDetailsService;

//    @Autowired
//    JwtAuthenticationService jwtAuthenticationService;

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.antMatcher("/**")
//                .authorizeRequests()
//                .antMatchers("/", "/security_test",  "/h2-console/**", "/login**", "/favicon.ico").permitAll()
//                .anyRequest().authenticated()
//                .and().logout().logoutSuccessUrl("/").permitAll()
//                .and().headers().frameOptions().sameOrigin()
//                .and().csrf().disable();
//    }
//

//    @Bean
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .headers().frameOptions().sameOrigin()
//                .and()
//                .authorizeRequests()
//                .antMatchers("/","/**", "/css/**", "/images/**",
//                        "/js/**", "/h2-console/**").permitAll()
//
//                .antMatchers("/oauth2/**").permitAll()
//                .antMatchers("/login/**").permitAll()
//                .antMatchers("/api/v1/**").hasRole(Role.USER.name())
//
////                .antMatchers("/api/v1/**").hasRole(Role.USER.name())
//
//                .anyRequest().authenticated()
//                .and()
//                .logout()
//                .logoutSuccessUrl("/")
//                .and()
//                .oauth2Login()
//                .userInfoEndpoint()
//                .userService(customUserOAuth2UserService);
////        super.configure(http);
//    }



    // 강의 2) 사용자 정의 보안 기능 구현

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()            // 요청의 대한 보안검색
            .anyRequest().authenticated();
        http
            .formLogin()                   // 인증방식은 기본적인 form 방식으로 username & password
//            .loginPage("/loginPage")       // 간편하지만 밑에 loginProcessingUrl이 더 활용성이 좋다    <- / 로들어왔을때, loginpage로 돌린다
            .defaultSuccessUrl("/")
            .failureUrl("/login")
//            .usernameParameter("userId")    // custom userid & passwd param
//            .passwordParameter("passwd")
            .loginProcessingUrl("/login_proc")      //customizing
            .successHandler(new AuthenticationSuccessHandler() {
                @Override
                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    System.out.println("authentication" + authentication.getName());

                    response.sendRedirect("/");
                }

            }).failureHandler(new AuthenticationFailureHandler() {
                @Override
                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                    System.out.println("authentication" + exception.getMessage());

                    response.sendRedirect("/login");
                }
            })
            .permitAll();

    }



//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .headers().frameOptions().sameOrigin()
//                .and()
//                .authorizeRequests()
//                .antMatchers("/","/**", "/css/**", "/images/**",
//                        "/js/**", "/h2-console/**","/login/**").permitAll()
//                .antMatchers("/oauth2/**").permitAll()
//                .antMatchers("/login/**").permitAll()
//                .antMatchers(HttpMethod.POST, "/auth/login").permitAll()
////                .anyRequest().authenticated()
//                .and()
//                .apply(new JwtAuthenticationConfigurer(jwtAuthenticationService))
//                .and()
//
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .logout()
//                .logoutSuccessUrl("/")
//                .and()
//                .oauth2Login()
//                .userInfoEndpoint()
//                .userService(customUserOAuth2UserService);
//    }

//    @Autowired
//    public void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService)
//                .passwordEncoder(new BCryptPasswordEncoder());
//    }

}


/*
*
* 지금은 oauth2로 인증한 유저값은 Account 테이블로 들어가고
*
* localhost:8080/login/auth post방법으로 username와 userpassword를 보낼시,
* User table의 bcrypt로 hash된 password와 비교한후
* 맞으면, jwt token을 유저에게 return해준다
*
* 근데 여기서 궁금증은 oauth2로 인증한 유저들은 password column이 있나?
* 없으면, 뭐랑 비교를해서, jwt값을 돌려보내주지?
*
*
*
*
* */