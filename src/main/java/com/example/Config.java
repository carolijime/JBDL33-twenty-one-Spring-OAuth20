package com.example;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class Config extends WebSecurityConfigurerAdapter {

    static{
        /*
        dsasfsadfsd
        asdfsdf
        ddadsf
        deeeee
         */
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
//        http
//                .authorizeRequests(a -> a
//                        .antMatchers("/", "/error", "/webjars/**").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .exceptionHandling(e -> e
//                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//                )
//                .csrf(c -> c
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                )
//                .logout(l -> l
//                        .logoutSuccessUrl("/").permitAll()
//                )
//                .oauth2Login();
        // @formatter:on

        http.authorizeRequests()
                .antMatchers("/", "/webjars/**").permitAll() //if they are blocked, the authentication might not work
//                .antMatchers("testcode").hasAnyAuthority()
                .anyRequest().authenticated() //except for the antmatchers above, the rest, the should be authenticated
                .and()
                .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)) //you can put any kind of exception code
                .and()
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) //disabling csrf from http requests
                .and()
                .logout()
                .logoutSuccessUrl("/").permitAll()
                .and()
                .oauth2Login();

    }
}
