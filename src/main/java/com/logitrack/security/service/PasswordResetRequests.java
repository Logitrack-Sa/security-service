package com.logitrack.security.service;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/** La respuesta HTTP no espera a la consulta de la cuenta ni al envío del correo. */
@Service
public class PasswordResetRequests {
    private final PasswordResetService resets;
    public PasswordResetRequests(PasswordResetService resets) { this.resets = resets; }

    @Async
    public void submit(String email) { resets.request(email); }
}
