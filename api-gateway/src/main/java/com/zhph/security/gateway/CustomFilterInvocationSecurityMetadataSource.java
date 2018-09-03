package com.zhph.security.gateway;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.util.*;

/**
 * @ProjectName: zuul-auth-example-parent
 * @Package: com.zhph.security.gateway
 * @ClassName: ${CustomFilterInvocationSecurityMetadataSource}
 * @Description: 自定义权限资源 SecurityMetadataSource
 * @Author: zb
 * @CreateDate: 2018/9/3 9:59
 * @Version: 1.0
 * <p>
 * Copyright: Copyright (c) 2018
 */
public class CustomFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource  {


    private  Map<String, Collection<ConfigAttribute>> metadataSourceMap =new HashMap<>();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation fi = (FilterInvocation) object;
        Map<String, Collection<ConfigAttribute>> metadataSource = null;
        try {
            metadataSource = this.getMetadataSource();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if(metadataSource!=null){
            for (Map.Entry<String, Collection<ConfigAttribute>> entry : metadataSource.entrySet()) {
                String uri = entry.getKey();
                RequestMatcher requestMatcher = new AntPathRequestMatcher(uri);
                if (requestMatcher.matches(fi.getHttpRequest())) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    /**
     * 加载properties文件
     */
    private Map<String, Collection<ConfigAttribute>> getMetadataSource() throws IOException {
        ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver();
        Resource[] resources = resourcePatternResolver.getResources("classpath*:/security/*.properties");
        if (ArrayUtils.isEmpty(resources)) {
            return null;
        }
        Properties properties = new Properties();
        for (Resource resource : resources) {
            properties.load(resource.getInputStream());
        }
        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            String key = (String) entry.getKey();
            String value = (String) entry.getValue();
            String[] values = StringUtils.split(value, ",");
            Collection<ConfigAttribute> configAttributes = new ArrayList<>();
            ConfigAttribute configAttribute = new SecurityConfig(key);
            configAttributes.add(configAttribute);
            for (String v : values) {
                metadataSourceMap.put(StringUtils.trim(v), configAttributes);
            }
        }
        return metadataSourceMap;
    }
}
