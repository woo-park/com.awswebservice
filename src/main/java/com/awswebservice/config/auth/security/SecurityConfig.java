package com.awswebservice.config.auth.security;


//import com.wavestoked.domain.user.Role;
//import com.awswebservice.config.auth.CustomUserOAuth2UserService;
import com.awswebservice.config.auth.CustomUserOAuth2UserService;
import com.awswebservice.config.auth.security.commons.FormAuthenticationDetailsSource;
//import com.awswebservice.service.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
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
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
//@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    private final CustomUserOAuth2UserService customUserOAuth2UserService;

    public SecurityConfig(CustomUserOAuth2UserService customUserOAuth2UserService) {
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


    /*
    *
    인증이란?
        유저가 누구인지 확인하는 절차, 회원가입하고 로그인 하는 것.

    인가란?
        유저에 대한 권한을 허락하는 것.
    *
    * */


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

    @Bean
    public AuthenticationProvider authenticationProvider () {
        return new CustomAuthenticationProvider();
    }

    //메모리 방식
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//        /*
//        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");        // 인가를 미리 등록 (메모리방식) // 사실은 유저를 동적으로 추가하고, 권한도 동적으로 생성하고
////        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
////        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");          // 이렇게하면 admin이 user 페이지 권한이없다
//        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS","USER");
//        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");          // 이것보다 좋은 방법은 role hierarchy 를 통해 인가 정책을 짜는것입니다.
//        */
//
//
//        //실전
//        String password = passwordEncoder().encode("1111");
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");        // 인가를 미리 등록 (메모리방식) // 사실은 유저를 동적으로 추가하고, 권한도 동적으로 생성하고
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER","USER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN","MANAGER","USER");          // 이것보다 좋은 방법은 role hierarchy 를 통해 인가 정책을 짜는것입니다.
//
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // 강의 2) 사용자 정의 보안 기능 구현
    @Override
    protected void configure(HttpSecurity http) throws Exception {



        http    .csrf().disable()
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
//                .and()
//                .formLogin();


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


        /*
        http
//            .antMatcher("/")       //강의 11)     // authorizeRequests()전에 antMatchers를 하면 부분부분 인가 정책을 하는것이고        // "특정한 요청에 인가정책에 따르게... vs 모든요청에 인가정책..."
            .authorizeRequests()            // 요청의 대한 보안검색
                .antMatchers("/login").permitAll()  //강의 12)
            .antMatchers("/user").hasRole("USER")        // antMatchers가 authorizeRequests()후에 오면, 모든 url을 인가 정책에 따르게 하는것이다     //"모든 요청에 대해서 인가 정책에 따르게 하겠습니다."
            .antMatchers("/admin/pay").hasRole("ADMIN")
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated();
*/



        http
            .formLogin()                   // 인증방식은 기본적인 form 방식으로 username & password
//            .loginPage("/loginPage")       // 간편하지만 밑에 loginProcessingUrl이 더 활용성이 좋다    <- / 로들어왔을때, loginpage로 돌린다
            .failureUrl("/login")
//            .usernameParameter("userId")    // custom userid & passwd param
//            .passwordParameter("passwd")
            .loginPage("/login")
            .authenticationDetailsSource(authenticationDetailsSource) // 인증 부가 기능
            .loginProcessingUrl("/login_proc")      //customizing
            .defaultSuccessUrl("/")

                //밑과 같으나, 밑 밑 successHandler는 redirect시 cache에서 가고자하던 url을 꺼내서 보내준다
//            .successHandler(new AuthenticationSuccessHandler() {
//                @Override
//                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                    System.out.println("authentication" + authentication.getName());
//
//                    response.sendRedirect("/");
//                }
//
//            })
            .successHandler(new AuthenticationSuccessHandler() {        // 강의 12)
                @Override
                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    RequestCache requestCache = new HttpSessionRequestCache();       // 이 class를 활용해서
                    RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
//                    setDefaultTargetUrl("/");
                    SavedRequest savedRequest = requestCache.getRequest(request, response); // 원래 사용자가 가고자하던 그 url정보를 가지고있습니다.

                    if(savedRequest != null) {
                        String targetUrl = savedRequest.getRedirectUrl();
                        redirectStrategy.sendRedirect(request, response, targetUrl);
                    } else {
                        redirectStrategy.sendRedirect(request, response, "/");
                    }
//                    String redirectUrl = savedRequest.getRedirectUrl();
//                    System.out.println(savedRequest + ": saved request");
//                    System.out.println("redirectUrl: " + redirectUrl);
//                    response.sendRedirect(redirectUrl);


//                    https://github.com/onjsdnjs/corespringsecurityfinal/blob/master/src/main/java/io/security/corespringsecurity/security/handler/FormAuthenticationSuccessHandler.java
                }
            })
            .failureHandler(new AuthenticationFailureHandler() {
                @Override
                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                    System.out.println("authentication" + exception.getMessage());

                    response.sendRedirect("/login");
                }
            })
            .permitAll()
            .and()
            .rememberMe()
            .rememberMeParameter("remember")
            .tokenValiditySeconds(3599)
            .userDetailsService(userDetailsService)   // 유저객채를 rememberMe 인증시 필요한 class
            ;


        // 강의 12)
        http
                .exceptionHandling()        //
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {        //로그인 하지않고 바로 접근햇을때 보여지는 페이지 <- 물론 여기 login은 커스텀 login. not spring의 login
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                }) //인증 예외
//                .accessDeniedHandler(new OAuth2AccessDeniedHandler());
                .accessDeniedHandler(new AccessDeniedHandler() {


                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });  //인가예외

        // 1.1
        // 즉 AntPathRequestMatcher(/logout) 이 성립이될시에,
        // Authentication객채를 handler에 넘기고,
        // Authentication으로부터 SecurityContext를 꺼낼수있다
        // 여기 까지 진행되면, SecurityContextLogoutHandler에 SecurityContext가 넘어가고,
        // 그 안에서 session invalidate,   cookies delete,   SecurityContextHolder.clearContext()를 할수있다

        // 1.2
        // 위의 필터가 끝나면
        // 여기(SimpleUrlLogoutSuccessHandler)에 도달한다


        http
            .logout()
            .logoutUrl("/logout")                               //원칙적으론 post방식만
            .logoutSuccessUrl("/login")
            .addLogoutHandler(new LogoutHandler() {             // 1.1
                @Override
                public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                    HttpSession session = request.getSession();
                    System.out.println("logout session invalidate");
                    session.invalidate();                       // session을 무효화 // 로그아웃된 유저의 session을 빈것으로 무효화
                }
            })
            .logoutSuccessHandler(new LogoutSuccessHandler() {      //없어도 /login으로 가네..? 그리고 debug하면 cannot find local variable logoutsuccesshandler나온다
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    System.out.println("logout");
                    response.sendRedirect("/login");
                }
            })
            .deleteCookies("remember-me")
            ;


        http
            .sessionManagement()
                .sessionFixation().changeSessionId()    // servlet 3.1 이상은 기본으로 changeSessionId invoked되지만, custom할수있다 ( none, migrateSession <- 3.1이하 , newSession 으로  // 세션 고정 공격을 막기위해 cookie session id값을 바꿔줘야한다
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false) //default는 false    // true는 login을 아예 못하게 만드는 전략   // false는 이전session에서 더이상 활동못하게 막는 전략
            ;

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