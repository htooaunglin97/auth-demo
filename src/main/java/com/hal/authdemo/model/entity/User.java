package com.hal.authdemo.model.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Email
    @Column(unique = true)
    private String email;

    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$")
    private String phoneNumber;

    @NotBlank
    @Size(min = 8, max = 120)
    private String password;

    private boolean enabled = false;
    private String verificationToken;
    private LocalDateTime verificationTokenExpiry;
    private String refreshToken;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles;
}
