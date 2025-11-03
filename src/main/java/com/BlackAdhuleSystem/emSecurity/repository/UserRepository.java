package com.BlackAdhuleSystem.emSecurity.repository;

import com.BlackAdhuleSystem.emSecurity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository <User,Long> {
    User findByUserName(String userName);
}
