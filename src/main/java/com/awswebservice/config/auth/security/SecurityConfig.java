package com.awswebservice.config.auth.security;


//import com.wavestoked.domain.user.Role;
import com.awswebservice.config.auth.CustomUserOAuth2UserService;
import com.awswebservice.domain.user.Role;
import com.awswebservice.service.UserDetailServiceImpl;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {



//    private final CustomUserOAuth2UserService customUserOAuth2UserService;


    @Autowired
    UserDetailServiceImpl userDetailsService;

    @Autowired
    JwtAuthenticationService jwtAuthenticationService;

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

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
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



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().sameOrigin()
                .and()
                .authorizeRequests()
                .antMatchers("/","/**", "/css/**", "/images/**",
                        "/js/**", "/h2-console/**","/login/**").permitAll()
                .antMatchers(HttpMethod.POST, "/auth/login").permitAll()
//                .anyRequest().authenticated()
                .and()
                .apply(new JwtAuthenticationConfigurer(jwtAuthenticationService))
                .and()

                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(new BCryptPasswordEncoder());
    }
}