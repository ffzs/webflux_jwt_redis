package com.ffzs.webflux.security_demo.controller;

import com.ffzs.webflux.security_demo.model.HttpResult;
import com.ffzs.webflux.security_demo.model.LoginResponse;
import com.ffzs.webflux.security_demo.model.MyUser;
import com.ffzs.webflux.security_demo.repository.MyUserDetailsRepository;
import com.ffzs.webflux.security_demo.service.JwtSigner;
import com.ffzs.webflux.security_demo.service.MyUserService;
import com.ffzs.webflux.security_demo.service.RedisService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * @author: ffzs
 * @Date: 2020/8/16 下午8:52
 */

@RestController
@AllArgsConstructor
@RequestMapping("auth")
@Slf4j
public class LoginController {

    private final MyUserDetailsRepository myUserRepository;
    private final MyUserService myUserService;
    private final JwtSigner jwtSigner;
    private final RedisService redisService;

    private final PasswordEncoder password = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @PostMapping("login")
    public Mono<HttpResult> login (@RequestBody Map<String, String> user) {

        return Mono.justOrEmpty(user.get("username"))
                .flatMap(myUserRepository::findByUsername)
                .filter(it -> password.matches(user.get("password"), it.getPassword()))
                .map(it -> {
                        List<String> roles = it.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
                        String token = jwtSigner.generateToken(it);
                        redisService.saveToken(token);
                        return new HttpResult(HttpStatus.OK.value(), "成功登录", new LoginResponse(it.getUsername(), roles.toString(), token));
                    }
                )
                .onErrorResume(e -> Mono.empty())
                .switchIfEmpty(Mono.just(new HttpResult(HttpStatus.UNAUTHORIZED.value(), "登录失败", null)));
    }


    @PostMapping("signup")
    public Mono<HttpResult> signUp (@RequestBody MyUser user) {

        return Mono.just(user)
                .map(myUserService::save)
                .map(it -> new HttpResult(HttpStatus.OK.value(), "注册成功", null))
                .onErrorResume(e -> Mono.just(new HttpResult(HttpStatus.UNAUTHORIZED.value(), "注册失败", e)));
    }

}
