package com.zbph.security.auth;

import javax.servlet.http.HttpServletResponse;

import com.zbph.security.auth.sevice.CustomUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.zhph.security.common.JwtAuthenticationConfig;
import com.zhph.security.common.JwtUsernamePasswordAuthenticationFilter;

/**
 * 登录验证配置
 *
 * @author zb
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired JwtAuthenticationConfig config;

    @Bean
    public JwtAuthenticationConfig jwtConfig() {
        return new JwtAuthenticationConfig();
    }


    @Bean
    UserDetailsService customUserService(){
        return new CustomUserService();
    }

    /**
     * 配置认证
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        
        // TODO: 2018/8/24 配置一个内存中的用户认证器，zb/zb作为auth.inMemoryAuthentication()
//                .withUser("admin").password("admin").roles("ADMIN", "USER").and()
//                .withUser("zb").password("zb").roles("USER");用户名和密码，具有USER角色
//
        // TODO: 2018/8/24 真实环境可以选择数据库方式配置用户认证器,也可以自定义认证
       auth.userDetailsService(customUserService());

    }

    /**
     * 授权配置
     * 对每个请求进行细粒度安全性控制的关键在于重写一下方法
     * @param httpSecurity
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                //禁用防跨站伪请求CSRF攻击
                .csrf().disable()
                //禁用用户退出操作
                .logout().disable()
                .formLogin().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .anonymous()
                .and()
                    .exceptionHandling().authenticationEntryPoint(
                            (req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                    .addFilterAfter(new JwtUsernamePasswordAuthenticationFilter(config, authenticationManager()),
                            UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                    //登录不进行拦截
                    .antMatchers(config.getUrl()).permitAll()
                    .anyRequest().authenticated();
    }
}

