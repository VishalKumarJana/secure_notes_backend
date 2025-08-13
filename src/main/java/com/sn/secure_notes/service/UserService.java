package com.sn.secure_notes.service;

import com.sn.secure_notes.dtos.UserDTO;
import com.sn.secure_notes.entity.Role;
import com.sn.secure_notes.entity.User;

import java.util.List;
import java.util.Optional;

public interface UserService {

     List<User> getAllUsers();

     UserDTO getUserById(String userId);

     void updateUserRole(String userId, String roleName);

     User findByUsername(String username);

     void updateAccountLockStatus(String userId, boolean lockStatus);

     List<Role> getAllRoles();

     void updateAccountExpiryStatus(String userId, boolean expiryStatus);

     void updateAccountEnabledStatus(String userId, boolean enabledStatus);

     void updateCredentialsExpiryStatus(String userId, boolean expiryStatus);

     void updatePassword(String userId, String newPassword);

     void generatePasswordResetToken(String email);

     void resetPassword(String token, String newPassword);

     Optional<User> findByEmail(String email);

     User registerUser(User newUser);
}
