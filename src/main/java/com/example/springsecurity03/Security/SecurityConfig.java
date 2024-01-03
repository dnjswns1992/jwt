package com.example.springsecurity03.Security;


import com.example.springsecurity03.Filter.JwtCheckFilter;
import com.example.springsecurity03.Filter.UserCheckFilter;
import com.example.springsecurity03.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationSuccessHandler handler;
    private final AccessDeniedHandler deniedHandler;
    private final UserDetailsService service;
    private final AuthenticationDetailsSource detailsSource;
    private final UserRepository repository;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security,AuthenticationConfiguration configuration) throws Exception {
        security.csrf(csrf ->csrf.disable());


        security.addFilterBefore(new UserCheckFilter(manager(configuration),repository),UsernamePasswordAuthenticationFilter.class);
        security.addFilterBefore(new JwtCheckFilter(repository), UsernamePasswordAuthenticationFilter.class);
        security.formLogin(AbstractAuthenticationFilterConfigurer::permitAll);

        security.formLogin(login -> login.authenticationDetailsSource(detailsSource).successHandler(handler)
                ).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        security.authorizeHttpRequests(auth ->
                auth.requestMatchers("/join").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/manager/**").hasRole("MANAGER")
                        .requestMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated());



        return security.build();

    }
    @Bean
    AuthenticationManager manager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }



    @Bean
    public PasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }
}
