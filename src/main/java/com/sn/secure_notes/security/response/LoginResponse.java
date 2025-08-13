package com.sn.secure_notes.security.response;

import jdk.jfr.Name;
import lombok.*;

import java.util.List;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginResponse {

    private String username;
    private String jwtToken;
    private List<String> roles;
}
