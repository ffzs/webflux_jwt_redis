package com.ffzs.webflux.security_demo.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;


/**
 * @author: ffzs
 * @Date: 2020/8/20 下午3:30
 */

@Service
@AllArgsConstructor
@Slf4j
public class RedisService {
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public void saveToken (String token) {
        redisTemplate.opsForSet().add("token_set", token)
                .subscribe();
    }
}
