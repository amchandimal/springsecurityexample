package com.chandimal.springsecurityexample.config;

import com.chandimal.springsecurityexample.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final CustomUserDetailsService customUserDetailsService;
  private final JwtRequestFilter jwtRequestFilter;

  public SecurityConfig(
      CustomUserDetailsService customUserDetailsService,
      JwtRequestFilter jwtRequestFilter) {
    this.customUserDetailsService = customUserDetailsService;
    this.jwtRequestFilter = jwtRequestFilter;
  }

  //Adding Security Config
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(customUserDetailsService);
  }

  //Adding Authorization
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable().authorizeRequests().antMatchers("/auth").permitAll() // Allow All to /auth Endpoint
        .anyRequest().authenticated() //Any Other requests should be authenticated
        .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //Setting Stateless Policy

    http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class); //Adding our filter before UserNamePasswordAuthenticationFilter
  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return NoOpPasswordEncoder.getInstance();
  }

  //Defining Bean for Authorization Manager
  @Bean
  public AuthenticationManager getAuthorizationManager() throws Exception{
    return super.authenticationManagerBean();
  }
}
