package web.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import web.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);

    User findByEmail(String email);

    User getUserById(long id);
}
