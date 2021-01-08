package com.awswebservice.config.auth.security.configs;

import com.awswebservice.config.auth.security.commons.AjaxLoginAuthenticationEntryPoint;
import com.awswebservice.config.auth.security.commons.JwtAuthenticationEntryPoint;
import com.awswebservice.config.auth.security.filter.AjaxLoginProcessingFilter;
//import com.awswebservice.config.auth.security.filter.JwtLoginProcessingFilter;
import com.awswebservice.config.auth.security.filter.JwtAuthenticationTokenFilter;
import com.awswebservice.config.auth.security.handler.*;
import com.awswebservice.config.auth.security.provider.JwtAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
@Order(0)
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        auth.authenticationProvider(jwtAuthenticationProvider());
    }

    public AuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider();
    }

    @Bean
    public AuthenticationSuccessHandler jwtAuthenticationSuccessHandler(){
        return new JwtAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler jwtAuthenticationFailureHandler(){
        return new JwtAuthenticationFailureHandler();
    }

    @Bean
    public AccessDeniedHandler jwtAccessDeniedHandler(){
        return new JwtAccessDeniedHandler();
    }

    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // cassiomolin

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter(authenticationManagerBean(), authenticationEntryPoint);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    @Autowired
    private JwtAuthenticationEntryPoint authenticationEntryPoint;






//    @Bean
//    public JwtLoginProcessingFilter jwtLoginProcessingFilter() throws Exception {
//        JwtLoginProcessingFilter filter = new JwtLoginProcessingFilter();
//        filter.setAuthenticationManager(authenticationManagerBean());
//        filter.setAuthenticationSuccessHandler(jwtAuthenticationSuccessHandler());
//        filter.setAuthenticationFailureHandler(jwtAuthenticationFailureHandler());
//        return filter;
//    }


//    @Autowired
//    private JwtAuthenticationEntryPoint unauthorizedHandler;

//    @Autowired
//    private JwtUserDetailsService jwtUserDetailsService;

    // Custom JWT based security filter
//    @Autowired
//    JwtAuthorizationTokenFilter authenticationTokenFilter;

//    @Value("${jwt.header}")
//    private String tokenHeader;
//
//    @Value("${jwt.route.authentication.path}")
//    private String authenticationPath;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // we don't need CSRF because our token is invulnerable
                .csrf().disable()

                .exceptionHandling().authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .and()
                // don't create session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()

                // Un-secure H2 Database
                .antMatchers("/h2-console/**/**").permitAll()
                .antMatchers("/auth/signin").permitAll()
                .antMatchers("/auth/**").permitAll()
                .anyRequest().authenticated();
        http
                .exceptionHandling()
//                .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .accessDeniedHandler(jwtAccessDeniedHandler());

        http
//                .addFilterBefore(jwtLoginProcessingFilter(), AjaxLoginProcessingFilter.class);
//                .apply(new JwtConfigurer(jwtTokenProvider));      // we're trying with jwtAuthenticationProvider instead
                .addFilterBefore(authenticationTokenFilterBean(), AjaxLoginProcessingFilter.class);
        // disable page caching
        http
                .headers()
                .frameOptions().sameOrigin()  // required to set for H2 else H2 Console will be blank.
                .cacheControl();

        http.csrf().disable();


    }


}