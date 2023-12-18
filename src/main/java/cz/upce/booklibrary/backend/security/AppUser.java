package cz.upce.booklibrary.backend.security;

import lombok.With;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

@With
public record AppUser(
        String id,
        @NotBlank(message = "User's name cannot be empty.")
        String username,
        @NotBlank(message = "User's password cannot be empty.")
        String rawPassword,
        String passwordBcrypt,
        AppUserRole role
) {
}
