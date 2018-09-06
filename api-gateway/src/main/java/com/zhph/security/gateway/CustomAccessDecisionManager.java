package com.zhph.security.gateway;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Iterator;

/**
 * @ProjectName: zuul-auth-example-parent
 * @Package: com.zhph.security.gateway
 * @ClassName: ${CustomAccessDecisionManager}
 * @Description: 自定义权限决策类
 * @Author: zb
 * @CreateDate: 2018/9/6 10:34
 * @Version: 1.0
 * <p>
 * Copyright: Copyright (c) 2018
 */
public class CustomAccessDecisionManager implements AccessDecisionManager{
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException {
        Iterator<ConfigAttribute> iterator = configAttributes.iterator();
        while(iterator.hasNext()) {
            if (authentication == null) {
                throw new AccessDeniedException("Access is denied");
            }
            ConfigAttribute configAttribute = iterator.next();
            String needCode = configAttribute.getAttribute();
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if (StringUtils.equals(authority.getAuthority(), "ROLE_" + needCode)) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("Access is denied");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return false;
    }
}
