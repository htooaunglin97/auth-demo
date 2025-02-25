package com.hal.authdemo.model.request;

import jakarta.validation.constraints.NotBlank;
import com.hal.authdemo.validator.StrongPassword;
import lombok.Data;

@Data
public class NewPasswordRequest {
    @NotBlank
    @StrongPassword
    private String newPassword;
}