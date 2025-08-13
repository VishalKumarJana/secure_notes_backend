package com.sn.secure_notes.controller;

import com.sn.secure_notes.entity.Role;
import com.sn.secure_notes.entity.User;
import com.sn.secure_notes.repository.RoleRepo;
import com.sn.secure_notes.repository.UserRepo;
import com.sn.secure_notes.security.jwt.JwtUtils;
import com.sn.secure_notes.security.request.LoginRequest;
import com.sn.secure_notes.security.request.SignUpRequest;
import com.sn.secure_notes.security.response.LoginResponse;
import com.sn.secure_notes.security.response.MessageResponse;
import com.sn.secure_notes.security.response.UserInfoResponse;
import com.sn.secure_notes.service.UserService;
import com.sn.secure_notes.utils.AppRoles;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


import java.time.LocalDate;
import java.util.*;

@RestController
@RequestMapping("/secure-note/api/auth")
public class AuthController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private UserService userService;

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            LoginResponse loginResponse = new LoginResponse(userDetails.getUsername(), jwtToken, roles);

            return ResponseEntity.ok(loginResponse);
        }
        catch (AuthenticationException exception) {
            Map<String, String> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", "false");
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

    }

    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepo.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken!"));
        }
        if(userRepo.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email is already in use!"));
        }
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
        Set<String> strRoles = signUpRequest.getRoles();
        Role role;
        if(strRoles == null || strRoles.isEmpty()) {
            role = roleRepo.findByRoleName(AppRoles.ROLE_CUSTOMER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        }else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepo.findByRoleName(AppRoles.ROLE_DELEGATE)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepo.findByRoleName(AppRoles.ROLE_CUSTOMER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }
            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusMonths(6));
            user.setAccountExpiryDate(LocalDate.now().plusMonths(6));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepo.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @GetMapping("/private/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        User byUsername = userService.findByUsername(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream().map(
                item -> item.getAuthority()).toList();

        UserInfoResponse response = new UserInfoResponse(
                byUsername.getUserId(),
                byUsername.getUsername(),
                byUsername.getEmail(),
                byUsername.isAccountNonLocked(),
                byUsername.isAccountNonExpired(),
                byUsername.isCredentialsNonExpired(),
                byUsername.isEnabled(),
                byUsername.getCredentialsExpiryDate(),
                byUsername.getAccountExpiryDate(),
                byUsername.isTwoFactorEnabled(),
                roles
        );
        return ResponseEntity.ok().body(response);
    }

    @GetMapping("/current-username")
    public String currentUsername(@AuthenticationPrincipal UserDetails userDetails) {
        return (userDetails != null) ? userDetails.getUsername() : "Anonymous request" ;
    }

    @PostMapping("/public/forget-password")
    public ResponseEntity<?> forgetPassword(@RequestParam String email){
        try{
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse("Password Reset email sent!..."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("Error sending password reset email!..."));
        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword ){
        try{
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok(new MessageResponse("Password Reset Successfully!..."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse(e.getMessage()));
        }
    }

}
