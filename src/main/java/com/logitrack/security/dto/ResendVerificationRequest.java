package com.logitrack.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Dirección de la cuenta cuyo enlace se desea renovar. */
public record ResendVerificationRequest(@NotBlank @Email @Size(max = 254) String email) {}
