package com.awswebservice.config.auth;


//import com.wavestoked.domain.user.Role;
import com.awswebservice.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserOAuth2UserService customUserOAuth2UserService;

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
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().sameOrigin()
                .and()
                .authorizeRequests()
                .antMatchers("/","/**", "/css/**", "/images/**",
                        "/js/**", "/h2-console/**").permitAll()

                .antMatchers("/oauth2/**").permitAll()
                .antMatchers("/login/**").permitAll()
                .antMatchers("/api/v1/**").hasRole(Role.USER.name())

//                .antMatchers("/api/v1/**").hasRole(Role.USER.name())

                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutSuccessUrl("/")
                .and()
                .oauth2Login()
                .userInfoEndpoint()
                .userService(customUserOAuth2UserService);
//        super.configure(http);
    }
}