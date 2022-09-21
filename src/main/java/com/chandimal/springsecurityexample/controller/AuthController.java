package com.chandimal.springsecurityexample.controller;

import com.chandimal.springsecurityexample.model.AuthenticationResponse;
import com.chandimal.springsecurityexample.model.UserNamePasswordRequest;
import com.chandimal.springsecurityexample.service.CustomUserDetailsService;
import com.chandimal.springsecurityexample.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final CustomUserDetailsService userDetailsService;
  private final JwtUtil jwtUtil;

  public AuthController(
      AuthenticationManager authenticationManager,
      CustomUserDetailsService userDetailsService,
      JwtUtil jwtUtil) {
    this.authenticationManager = authenticationManager;
    this.userDetailsService = userDetailsService;
    this.jwtUtil = jwtUtil;
  }

  @PostMapping("")
  public ResponseEntity<?> login(@RequestBody UserNamePasswordRequest loginRequest){
    //Authenticating with UserName and Password Authentication
    //This is the standard token Spring MVC uses for authenticate username & Password
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
    }catch (BadCredentialsException badCredentialsException){
      throw new RuntimeException("Incorrect Username or Password");
    }

    //Assigning username to JWT
    UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
    String jwt = jwtUtil.generateToken(userDetails);

    return ResponseEntity.ok(new AuthenticationResponse(jwt));

  }

}
