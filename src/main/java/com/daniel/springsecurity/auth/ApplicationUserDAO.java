package com.daniel.springsecurity.auth;

import java.util.Optional;

/**
 * @author Daniel Tamang
 * @since 10/18/2022
 */
public interface ApplicationUserDAO {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
