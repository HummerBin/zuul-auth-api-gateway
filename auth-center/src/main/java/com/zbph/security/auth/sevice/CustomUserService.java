package com.zbph.security.auth.sevice;

import com.zbph.security.auth.entry.SysUser;
import com.zbph.security.auth.repository.SysUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 自定义认证器
 * @author zb
 */
public class CustomUserService implements UserDetailsService {
    @Autowired
    private SysUserRepository sysUserRepository;
    @Override
    public UserDetails loadUserByUsername(String u) throws UsernameNotFoundException {
       SysUser sysUser =  sysUserRepository.findByUsername(u);
       if(sysUser==null){
           throw new UsernameNotFoundException("User does not exist！");
       }
        return sysUser;
    }

}
