package com.awswebservice.config.auth.security.configs;

import com.awswebservice.config.auth.CustomUserOAuth2UserService;
import com.awswebservice.config.auth.security.commons.FormAuthenticationDetailsSource;
import com.awswebservice.config.auth.security.filter.AjaxLoginProcessingFilter;
import com.awswebservice.config.auth.security.handler.FormAccessDeniedHandler;
import com.awswebservice.config.auth.security.provider.FormAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
//@RequiredArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;
//    @Autowired
//    private SecurityResourceService securityResourceService;

    private String[] permitAllResources = {"/", "/login", "/user/login/**"};


    @Autowired
    UserDetailsService userDetailsService;

    private final CustomUserOAuth2UserService customUserOAuth2UserService;

    public WebSecurityConfig(CustomUserOAuth2UserService customUserOAuth2UserService) {
        this.customUserOAuth2UserService = customUserOAuth2UserService;
    }

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


    @Autowired
    private FormAuthenticationDetailsSource authenticationDetailsSource;

    // 필터 건더뛰기
    @Override
    public void configure(WebSecurity web) throws Exception{
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    // db 연동방식
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService); //customAuthenticationProvider가 없었을때 이렇게
        auth.authenticationProvider(authenticationProvider());
    }


    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider () {
        return new FormAuthenticationProvider(passwordEncoder());
    }

    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler commonAccessDeniedHandler = new FormAccessDeniedHandler();
        commonAccessDeniedHandler.setErrorPage("/denied");
        return commonAccessDeniedHandler;
    }



    // 강의 2) 사용자 정의 보안 기능 구현
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
//                .antMatchers("/","/**","/users","/users/**").permitAll()
                .antMatchers("/oauth2/**").permitAll()
                .antMatchers("/login/**").permitAll()
                .antMatchers(HttpMethod.POST, "/auth/login").permitAll()
                .antMatchers("/","/users","/user/login/**").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/login").permitAll()  //강의 12)
//                .antMatchers("/user").hasRole("USER")        // antMatchers가 authorizeRequests()후에 오면, 모든 url을 인가 정책에 따르게 하는것이다     //"모든 요청에 대해서 인가 정책에 따르게 하겠습니다."
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();


        http
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(accessDeniedHandler());

        http
                .oauth2Login()
                .loginPage("/login")
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("authentication" + exception.getMessage());

                        response.sendRedirect("/login");
                    }
                })
                .userInfoEndpoint()     // 이것과 밑 userService는 연결되어있다
                .userService(customUserOAuth2UserService);


        http
            .sessionManagement()
            .sessionFixation().changeSessionId()    // servlet 3.1 이상은 기본으로 changeSessionId invoked되지만, custom할수있다 ( none, migrateSession <- 3.1이하 , newSession 으로  // 세션 고정 공격을 막기위해 cookie session id값을 바꿔줘야한다
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false) //default는 false    // true는 login을 아예 못하게 만드는 전략   // false는 이전session에서 더이상 활동못하게 막는 전략
            ;

        http.csrf().disable();

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
//
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