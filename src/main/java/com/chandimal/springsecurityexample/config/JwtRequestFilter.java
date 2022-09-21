package com.chandimal.springsecurityexample.config;

import com.chandimal.springsecurityexample.service.CustomUserDetailsService;
import com.chandimal.springsecurityexample.util.JwtUtil;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
//This filter intercept every request once
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

  private final CustomUserDetailsService customUserDetailsService;
  private final JwtUtil jwtUtil;

  public JwtRequestFilter(
      CustomUserDetailsService customUserDetailsService,
      JwtUtil jwtUtil) {
    this.customUserDetailsService = customUserDetailsService;
    this.jwtUtil = jwtUtil;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

      String authHeader = request.getHeader("Authorization");
      String userName = null;
      String jwt = null;

      if(authHeader!=null && authHeader.startsWith("Bearer ")){
        jwt = authHeader.substring(7);
        userName = jwtUtil.extractUsername(jwt);
      }

      if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null){
        UserDetails  userDetails = this.customUserDetailsService.loadUserByUsername(userName);
        if(jwtUtil.validateToken(jwt,userDetails)){
          UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
          token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
          SecurityContextHolder.getContext().setAuthentication(token);
        }
      }
    filterChain.doFilter(request,response);

  }
}
