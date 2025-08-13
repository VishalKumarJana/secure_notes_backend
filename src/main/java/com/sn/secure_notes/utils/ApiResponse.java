package com.sn.secure_notes.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.sn.secure_notes.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse {
    private String status;
    private User user;
    private String message;
}