package com.zhph.security.common;

import lombok.Getter;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Value;

/**
 * JWT 令牌配置
 *
 * @author zb 2017/10/18
 */
@Getter
@ToString
public class JwtAuthenticationConfig {

    @Value("${zhph.security.jwt.url:/login}")
    private String url;

    @Value("${zhph.security.jwt.header:Authorization}")
    private String header;

    @Value("${zhph.security.jwt.prefix:Bearer}")
    private String prefix;

    // default 24 hours
    @Value("${zhph.security.jwt.expiration:#{24*60*60}}")
    private int expiration;

    @Value("${zhph.security.jwt.secret}")
    private String secret;

}
