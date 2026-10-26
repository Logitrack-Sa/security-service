package com.logitrack.security.dto;

import java.time.Instant;
public record ErrorResponse(Instant timestamp, int status, String error, String code, String message, String path) { }
