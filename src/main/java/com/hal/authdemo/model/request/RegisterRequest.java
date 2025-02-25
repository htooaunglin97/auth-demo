package com.hal.authdemo.model.request;

import com.hal.authdemo.validator.StrongPassword;
import jakarta.validation.constraints.*;
import lombok.Data;


@Data
public class RegisterRequest {
    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Email
    private String email;

    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$")
    private String phoneNumber;

    @StrongPassword
    @NotBlank
    @Size(min = 8, max = 120)
    private String password;
}
