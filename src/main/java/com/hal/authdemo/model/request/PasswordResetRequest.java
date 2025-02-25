package com.hal.authdemo.model.request;

import lombok.Data;

@Data
public class PasswordResetRequest {
    private String email;
}