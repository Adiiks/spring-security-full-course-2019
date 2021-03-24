package pl.adrian.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static pl.adrian.springsecurity.security.UserRole.*;

@Repository("fake")
public class FakeUserDaoService implements UserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> selectUserByUsername(String username) {
        return getUsers().stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst();
    }

    private List<User> getUsers() {
        return Lists.newArrayList(
                new User(passwordEncoder.encode("password"), "annasmith",
                    STUDENT.getGrantedAuthorities(), true, true,
                    true, true),
                new User(passwordEncoder.encode("password"), "linda",
                        ADMIN.getGrantedAuthorities(), true, true,
                        true, true),
                new User(passwordEncoder.encode("password"), "tom",
                        ADMINTRAINEE.getGrantedAuthorities(), true, true,
                        true, true)
        );
    }
}
