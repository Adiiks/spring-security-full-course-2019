package pl.adrian.springsecurity.auth;

import java.util.Optional;

public interface UserDao {

    Optional<User> selectUserByUsername(String username);
}
