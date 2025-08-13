package com.sn.secure_notes.serviceimpl;

import com.sn.secure_notes.dtos.UserDTO;
import com.sn.secure_notes.entity.PasswordResetToken;
import com.sn.secure_notes.entity.Role;
import com.sn.secure_notes.entity.User;
import com.sn.secure_notes.repository.PasswordResetTokenRepo;
import com.sn.secure_notes.service.UserService;
import com.sn.secure_notes.repository.RoleRepo;
import com.sn.secure_notes.repository.UserRepo;
import com.sn.secure_notes.utils.AppRoles;
import com.sn.secure_notes.utils.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;


@Service
public class UserServiceImpl implements UserService{

    @Value("${frontend.url}")
    String frontendUrl;

    @Autowired
    private UserRepo userRepo;
    
    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordResetTokenRepo passwordResetTokenRepo;

    @Autowired
    private EmailService emailService;


    @Override
    public List<User> getAllUsers() {
        return userRepo.findAll();
    }

    @Override
    public UserDTO getUserById(String userId) {
        User user = userRepo.findById(userId).orElseThrow();
        return convertToDto(user);
    }

    private UserDTO convertToDto(User user) {
        UserDTO userDTO = UserDTO.builder()
                .userId(user.getUserId())
                .username(user.getUsername())
                .email(user.getEmail())
                .password(user.getPassword())
                .accountNonLocked(user.isAccountNonLocked())
                .accountNonExpired(user.isAccountNonExpired())
                .credentialsNonExpired(user.isCredentialsNonExpired())
                .enabled(user.isEnabled())
                .credentialsExpiryDate(user.getCredentialsExpiryDate())
                .accountExpiryDate(user.getAccountExpiryDate())
                .twoFactorSecret(user.getTwoFactorSecret())
                .isTwoFactorEnabled(user.isTwoFactorEnabled())
                .signUpMethod(user.getSignUpMethod())
                .role(user.getRole())
                .createdDate(user.getCreatedDate())
                .updatedDate(user.getUpdatedDate())
                .build();
        return userDTO;
    }

    @Override
    public void updateUserRole(String userId, String roleName) {
        User user = userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        AppRoles appRoles = AppRoles.valueOf(roleName);
        user.setRole(roleRepo.findByRoleName(appRoles).orElseThrow(() -> new RuntimeException("Role not found")));
        userRepo.save(user);
    }

    @Override
    public User findByUsername(String username) {
        Optional<User> byUsername = userRepo.findByUsername(username);
        return byUsername.orElseThrow(()-> new UsernameNotFoundException("User not found with username: " + username));
    }

    @Override
    public void updateAccountLockStatus(String userId, boolean lockStatus) {
        User userNotFound = userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        userNotFound.setAccountNonLocked(!lockStatus);
        userRepo.save(userNotFound);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepo.findAll();
    }

    @Override
    public void updateAccountExpiryStatus(String userId, boolean expiryStatus) {
        User userNotFound = userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        userNotFound.setAccountNonExpired(!expiryStatus);
        userRepo.save(userNotFound);
    }

    @Override
    public void updateAccountEnabledStatus(String userId, boolean enabledStatus) {
        User userNotFound = userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        userNotFound.setEnabled(enabledStatus);
        userRepo.save(userNotFound);
    }

    @Override
    public void updateCredentialsExpiryStatus(String userId, boolean expiryStatus) {
        User userNotFound = userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        userNotFound.setCredentialsNonExpired(!expiryStatus);
        userRepo.save(userNotFound);
    }

    @Override
    public void updatePassword(String userId, String newPassword) {
        try {
            User userNotFound = userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
            userNotFound.setPassword(passwordEncoder.encode(newPassword));
            userRepo.save(userNotFound);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }

    @Override
    public void generatePasswordResetToken(String email){
        User user = userRepo.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
        String token = UUID.randomUUID().toString();
        Instant plus = Instant.now().plus(24, ChronoUnit.HOURS);
        PasswordResetToken resetToken = new PasswordResetToken(token, plus, user);
        passwordResetTokenRepo.save(resetToken);
        String resetUrl = frontendUrl + "/reset-password?token=" + token;
        //Send email to user
        emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepo.findByToken(token).orElseThrow(() -> new RuntimeException("Invalid password reset token"));
        if(resetToken.isUsed())
            throw new RuntimeException("Token is already in use");
        if(resetToken.getExpiryDate().isBefore(Instant.now()))
            throw new RuntimeException("Password reset token has expired");

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);
        resetToken.setUsed(true);
        passwordResetTokenRepo.save(resetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    @Override
    public User registerUser(User user) {
        if(user.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        return userRepo.save(user);
    }

}
