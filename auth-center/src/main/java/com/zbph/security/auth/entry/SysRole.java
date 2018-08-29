package com.zbph.security.auth.entry;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.io.Serializable;

/**
 *  角色实体类
 * @author zb
 */
@Entity
public class SysRole  {
    @Id
    @GeneratedValue
    @Getter@Setter
    private Long id;
    @Getter@Setter
    private String name;
}
