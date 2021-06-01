package com.tolulope.securyandjwt.repository;

import com.tolulope.securyandjwt.models.ERole;
import com.tolulope.securyandjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
