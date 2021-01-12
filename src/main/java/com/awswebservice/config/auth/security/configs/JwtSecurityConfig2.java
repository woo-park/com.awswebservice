//package com.awswebservice.config.auth.security.configs;
//
//import com.awswebservice.config.auth.JwtAuthenticationService;
//import com.awswebservice.config.auth.security.commons.JwtAuthenticationEntryPoint;
//import com.awswebservice.config.auth.security.filter.AjaxLoginProcessingFilter;
//import com.awswebservice.config.auth.security.service.UserDetailsServiceImpl;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//
//@Configuration
//@EnableWebSecurity
//@Order(0)
//public class JwtSecurityConfig2 extends WebSecurityConfigurerAdapter {
//
//    @Autowired
//    UserDetailsServiceImpl userDetailsService;
//
//    @Autowired
//    JwtAuthenticationService jwtAuthenticationService;
//
//    @Bean
////    @Override
//    public AuthenticationManager authenticationManager() throws Exception {
//        return super.authenticationManagerBean();
//    }
//
////    @Autowired
////    public void configure(AuthenticationManagerBuilder auth) throws Exception {
////        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
////    }
//
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                // we don't need CSRF because our token is invulnerable
//                .csrf().disable();
//
////                .exceptionHandling().authenticationEntryPoint(new JwtAuthenticationEntryPoint())
////                .and()
//                // don't create session
////                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//
//     http
//                .authorizeRequests()
//                .antMatchers(HttpMethod.POST, "/auth/loginjwt").permitAll()
////                .antMatchers("/api/login").permitAll()
//                // Un-secure H2 Database
////                .antMatchers("/h2-console/**/**").permitAll()
////                .antMatchers("/auth/signin").permitAll()
////                .antMatchers("/auth/**").permitAll()
//                .anyRequest().authenticated()
//                .and().apply(new JwtAuthenticationConfigurer(jwtAuthenticationService));
////
////        http
////                .exceptionHandling()
//////                .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
////                .accessDeniedHandler(jwtAccessDeniedHandler());
////
////        http
//////                .addFilterBefore(jwtLoginProcessingFilter(), AjaxLoginProcessingFilter.class);
//////                .apply(new JwtConfigurer(jwtTokenProvider));      // we're trying with jwtAuthenticationProvider instead
////                .addFilterBefore(authenticationTokenFilterBean(), AjaxLoginProcessingFilter.class);
////        // disable page caching
////        http
////                .headers()
////                .frameOptions().sameOrigin()  // required to set for H2 else H2 Console will be blank.
////                .cacheControl();
////
////        http.csrf().disable();
//
//
//    }
//}
