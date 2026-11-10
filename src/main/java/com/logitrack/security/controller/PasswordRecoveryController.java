package com.logitrack.security.controller;

import com.logitrack.security.dto.PasswordResetRequest;
import com.logitrack.security.dto.ResendVerificationRequest;
import com.logitrack.security.service.PasswordResetRequests;
import com.logitrack.security.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Recuperación de contraseña")
public class PasswordRecoveryController {
    private final PasswordResetRequests requests;
    private final PasswordResetService resets;
    private long window = System.currentTimeMillis();
    private int requested;
    private int attempts;

    public PasswordRecoveryController(PasswordResetRequests requests, PasswordResetService resets) {
        this.requests = requests;
        this.resets = resets;
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Solicitar recuperación por correo", description = "Respuesta uniforme. Enlace de un uso, válido durante 15 minutos.")
    public ResponseEntity<Map<String, String>> forgot(@Valid @RequestBody ResendVerificationRequest body) {
        limit(true);
        requests.submit(body.email());
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore()).body(Map.of("message",
                "Si la cuenta está activa, recibirás un enlace para restablecer tu contraseña."));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Elegir una nueva contraseña con el enlace recibido")
    public ResponseEntity<Void> reset(@Valid @RequestBody PasswordResetRequest body) {
        limit(false);
        resets.reset(body.token(), body.password());
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    private synchronized void limit(boolean request) {
        long now = System.currentTimeMillis();
        if (now - window >= 60_000) { window = now; requested = 0; attempts = 0; }
        if ((request ? ++requested > 30 : ++attempts > 60))
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Demasiadas solicitudes. Esperá un minuto.");
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ProblemDetail> failure(ResponseStatusException error) {
        return ResponseEntity.status(error.getStatusCode()).cacheControl(CacheControl.noStore())
                .body(ProblemDetail.forStatusAndDetail(error.getStatusCode(), error.getReason()));
    }
}
