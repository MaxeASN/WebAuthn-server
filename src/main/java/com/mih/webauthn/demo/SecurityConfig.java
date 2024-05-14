package com.mih.webauthn.demo;

import com.mih.webauthn.demo.domain.Account;
import com.mih.webauthn.demo.domain.AccountRepo;
import io.github.webauthn.EnableWebAuthn;
import io.github.webauthn.config.WebAuthnConfigurer;
import io.github.webauthn.domain.DefaultWebAuthnUser;
import io.github.webauthn.domain.WebAuthnUser;
import io.github.webauthn.domain.WebAuthnUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableJpaRepositories
@EntityScan("com.mih.webauthn.demo")
@EnableWebAuthn
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    MyUserDetailsService userDetailsService;
    @Autowired
    AccountRepo accountRepo;
    @Autowired
    WebAuthnUserRepository<WebAuthnUser> webAuthnUserRepository;

    // 忽略一些静态资源
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/index.html", "/login.html","/home.html",
                "/h2-console/**",
                "/register.html", "/recovery.html", "/node_modules/**", "/error", "/transaction.html", "/transactionInfo.html",
                "/static/**", "/js/**", "/css/**", "/cdn-cgi/**", "/fonts/**", "/img/**", "/*.js", "/*.wasm", "/register");
                //"/*.css","/*.js","/*.html","/*.svg","/*.ico","/*.ttf","/*."
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // 认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //关闭csrf
                .csrf().disable()
                .headers().frameOptions().sameOrigin().and()
                .authorizeRequests()
                // 允许访问 "/api/**" 路径的请求
                .antMatchers("/api/diyLogin/**", "/api/diyRegister/**").permitAll()  // 允许访问的路径，无需登录
                .antMatchers("/api/**").permitAll()  // 允许访问的路径，无需登录
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().loginPage("/login.html")
//                .and()
//                .apply(
//                        new WebAuthnConfigurer()     // 应用 WebAuthnConfigurer 配置
//                        .registerSuccessHandler(user -> { // 注册成功的处理逻辑
//                            // 创建一个 Account 对象并保存到数据库
//                            Account account = new Account();
//                            account.setUsername(user.getUsername());
//                            account.setName("account-" + System.currentTimeMillis());
//                            accountRepo.save(account);
//                        })
//                        .userSupplier(() -> {  // 用户供应器，用于获取当前认证的用户信息
//                            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//                            if (authentication == null) {
//                                return null;
//                            }
//                            return webAuthnUserRepository.findByUsername(authentication.getName())
//                                    .orElseGet(() -> {
//                                        DefaultWebAuthnUser newUser = new DefaultWebAuthnUser();
//                                        newUser.setUsername(authentication.getName());
//                                        newUser.setEnabled(true);
//                                        return webAuthnUserRepository.save(newUser);
//                                    });
//                        })
//                )
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login.html")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID");
    }
}
