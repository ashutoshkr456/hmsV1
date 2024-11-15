package com.hms.Configuration;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
public class SecurityConfiguration {

    private JWTFilter jwtFilter;

    public SecurityConfiguration(JWTFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
            throws Exception
    {

        http.csrf().disable().cors().disable();
        http.addFilterBefore(jwtFilter, AuthorizationFilter.class);

        http.authorizeHttpRequests().requestMatchers("/api/v1/users/login","/api/v1/users/signUp","/api/v1/users/signUpOwner")
               .permitAll()
                .requestMatchers("/api/v1/country/addCountry").hasAnyRole("OWNER","ADMIN")
              .anyRequest().authenticated();
       return http.build();
    }
}
