package com.bahadircolak.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.bahadircolak.authservice.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}
