package com.zbph.security.auth.repository;

import com.zbph.security.auth.entry.SysUser;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 *
 * jpa
 * @author zb
 *
 */
public interface  SysUserRepository extends JpaRepository<SysUser,Long> {


    SysUser findByUsername(String username);
}
