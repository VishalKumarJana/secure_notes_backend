package com.sn.secure_notes.controller;

import com.sn.secure_notes.dtos.UserDTO;
import com.sn.secure_notes.entity.Role;
import com.sn.secure_notes.entity.User;
import com.sn.secure_notes.repository.UserRepo;
import com.sn.secure_notes.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/secure-note/api/admin")
public class AdminController {

    @Autowired
    private UserService userService;
    @Autowired
    private UserRepo userRepo;

    @GetMapping("/getUsers")
    public ResponseEntity<List<User>> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<UserDTO> getUser(@PathVariable String userId) {
        return new ResponseEntity<>(userService.getUserById(userId), HttpStatus.OK);
    }

    @PutMapping("/update-roles")
    public ResponseEntity<String> updateUserRole(@RequestParam String userId, @RequestParam String roleName) {
        userService.updateUserRole(userId, roleName);
        return ResponseEntity.ok("User_role successfully updated");
    }

    @PutMapping("/update-account-status")
    public ResponseEntity<String> updateAccountStatus(@RequestParam String userId, @RequestParam boolean status) {
        userService.updateAccountLockStatus(userId, status);
        return ResponseEntity.ok("Account Lock Status successfully updated");
    }

    @GetMapping("/getRoles")
    public List<Role> getAllRoles() {
        return userService.getAllRoles();
    }

    @PutMapping("/update-account-expiry-status")
    public ResponseEntity<String> updateAccountExpiryStatus(@RequestParam String userId, @RequestParam boolean status) {
        userService.updateAccountExpiryStatus(userId, status);
        return ResponseEntity.ok("Account Expiry Status successfully updated");
    }

    @PutMapping("/update-account-enabled-status")
    public ResponseEntity<String> updateAccountEnabledStatus(@RequestParam String userId, @RequestParam boolean status) {
        userService.updateAccountEnabledStatus(userId, status);
        return ResponseEntity.ok("Account Enable Status successfully updated");
    }

    @PutMapping("/update-credentials-expiry-status")
    public ResponseEntity<String> updateCredentialsExpiryStatus(@RequestParam String userId, @RequestParam boolean status) {
        userService.updateCredentialsExpiryStatus(userId, status);
        return ResponseEntity.ok("Credentials Expiry Status successfully updated");
    }

    @PutMapping("/update-password")
    public ResponseEntity<String> updatePassword(@RequestParam String userId, @RequestParam String password) {
        try {
            userService.updatePassword(userId, password);
            return ResponseEntity.ok("Password updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

}
