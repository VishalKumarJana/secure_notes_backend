package com.sn.secure_notes.repository;

import com.sn.secure_notes.entity.Role;
import com.sn.secure_notes.utils.AppRoles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepo extends JpaRepository<Role, String> {

    Optional<Role> findByRoleName(AppRoles appRoles);

}
