package com.daniel.springsecurity.jwt;

import lombok.Data;

/**
 * @author Daniel Tamang
 * @since 10/18/2022
 */
@Data
public class UsernameAndPasswordAuthenticationRequest {

    private String username;
    private String password;

}
