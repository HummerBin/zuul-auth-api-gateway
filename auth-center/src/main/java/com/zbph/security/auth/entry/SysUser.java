package com.zbph.security.auth.entry;

import lombok.Data;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户实体类 实现security UserDetails
 * @author zb
 */
@Entity
@Data
public class SysUser  implements UserDetails {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String password;

    private String state;

    private String name;
    private String gender;
    private String birth;
    @ManyToMany(cascade = {CascadeType.REFRESH},fetch = FetchType.EAGER)
    private List<SysRole> roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> auths = new ArrayList<>();
        List<SysRole> roles = this.getRoles();
        roles.forEach(c->auths.add(new SimpleGrantedAuthority(c.getName())));
        return auths;
    }

    /**
     *
     *指示用户的帐户是否已过期。过期的帐户无法通过身份验证
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     *
     *指示用户是锁定还是解锁。锁定的用户无法进行身份验证
     * 后期可以做用户锁定校验 返回true 未锁定
     * 源码 AccountStatusUserDetailsChecker check方法
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     *
     *指示用户的凭据（密码）是否已过期。过期的凭据会阻止身份验证
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     *
     *指示用户是启用还是禁用。禁用的用户不能经过身份验证
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
