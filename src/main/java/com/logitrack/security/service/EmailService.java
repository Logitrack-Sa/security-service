package com.logitrack.security.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Servicio de envío asíncrono de correos electrónicos transaccionales.
 *
 * <p>Despacha correos mediante JavaMailSender en un hilo independiente (@Async)
 * para no bloquear las solicitudes HTTP de registro ni las transacciones de base de datos.
 * Registra métricas de observabilidad mediante Micrometer Counter ante éxitos y fallos
 * de entrega SMTP.</p>
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final String verificationBaseUrl;
    private final String fromEmail;
    private final String smtpHost;
    private final String smtpUsername;
    private final String smtpPassword;

    private final Counter emailFailureCounter;
    private final Counter emailSuccessCounter;

    @Value("${logitrack.frontend.password-reset-url:http://localhost:3000/reset-password}")
    private String passwordResetUrl;

    @Value("${spring.mail.properties.mail.smtp.auth:true}")
    private boolean smtpAuthenticationRequired = true;

    /**
     * Construye el servicio inyectando el emisor de correo, el registro de métricas y las propiedades de configuración.
     *
     * @param mailSender componente de envío de correos de Spring.
     * @param meterRegistry registro de métricas de Micrometer.
     * @param verificationBaseUrl URL base del frontend para el enlace de verificación.
     * @param fromEmail dirección de correo de origen.
     * @param smtpHost host del servidor SMTP.
     * @param smtpPassword credencial o token de aplicación SMTP.
     */
    @Autowired
    public EmailService(
            JavaMailSender mailSender,
            MeterRegistry meterRegistry,
            @Value("${logitrack.frontend.verification-url:http://localhost:3000/verify-email}") String verificationBaseUrl,
            @Value("${spring.mail.username:}") String fromEmail,
            @Value("${spring.mail.host:smtp.gmail.com}") String smtpHost,
            @Value("${spring.mail.password:}") String smtpPassword
    ) {
        this.mailSender = mailSender;
        this.verificationBaseUrl = verificationBaseUrl;
        this.fromEmail = fromEmail;
        this.smtpHost = smtpHost;
        this.smtpUsername = fromEmail;
        this.smtpPassword = smtpPassword;

        MeterRegistry registry = meterRegistry != null ? meterRegistry : new SimpleMeterRegistry();
        this.emailFailureCounter = Counter.builder("email.delivery.failure")
                .description("Contador de fallos en la entrega de correos de verificación")
                .register(registry);
        this.emailSuccessCounter = Counter.builder("email.delivery.success")
                .description("Contador de entregas exitosas de correos de verificación")
                .register(registry);
    }

    /**
     * Constructor secundario para compatibilidad y pruebas unitarias aisladas.
     *
     * @param mailSender componente de envío de correos.
     * @param verificationBaseUrl URL base de verificación.
     * @param fromEmail dirección de correo de origen.
     */
    public EmailService(
            JavaMailSender mailSender,
            String verificationBaseUrl,
            String fromEmail
    ) {
        this(mailSender, new SimpleMeterRegistry(), verificationBaseUrl, fromEmail, "smtp.gmail.com", "");
    }

    /**
     * Envía asíncronamente un correo electrónico con el enlace de activación de cuenta.
     *
     * @param toEmail dirección del destinatario.
     * @param token identificador UUID v4 del token de verificación.
     */
    @Async
    public void sendVerificationEmail(String toEmail, String token) {
        if (!hasValidSmtpProperties()) {
            emailFailureCounter.increment();
            log.error("Propiedades SMTP requeridas (host, username, password) incompletas o vacías para envío de verificación a '{}'", toEmail);
            return;
        }

        String verificationLink = verificationBaseUrl + "?token=" + token;
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Verifica tu cuenta en LogiTrack");
            message.setText("Bienvenido a LogiTrack.\n\n"
                    + "Para verificar tu correo electrónico y activar tu cuenta, accede al siguiente enlace:\n"
                    + verificationLink + "\n\n"
                    + "Este enlace tiene una validez de 24 horas. Si no has creado esta cuenta, puedes desestimar este mensaje.\n\n"
                    + "Atentamente,\nEquipo de LogiTrack");

            mailSender.send(message);
            emailSuccessCounter.increment();
            log.info("Correo de verificación enviado exitosamente a '{}'", toEmail);
        } catch (Exception ex) {
            emailFailureCounter.increment();
            log.error("Fallo al enviar el correo de verificación a '{}': {}", toEmail, ex.getMessage(), ex);
        }
    }

    /**
     * Valida explícitamente si las propiedades SMTP requeridas están configuradas y no están en blanco.
     *
     * @return true si host, username y password están presentes y no vacíos; false en caso contrario.
     */
    public boolean hasValidSmtpProperties() {
        return smtpHost != null && !smtpHost.isBlank()
                && smtpUsername != null && !smtpUsername.isBlank()
                && (!smtpAuthenticationRequired || (smtpPassword != null && !smtpPassword.isBlank()));
    }

    @Async
    public void sendPasswordResetEmail(String recipient, String token) {
        if (!hasValidSmtpProperties()) {
            emailFailureCounter.increment();
            log.error("Configuración SMTP incompleta para recuperación de contraseña");
            return;
        }
        var message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(recipient);
        message.setSubject("Restablecé tu contraseña de LogiTrack");
        message.setText("Recibimos una solicitud para restablecer tu contraseña.\n\n"
                    + passwordResetUrl + "#token=" + token + "\n\n"
                    + "El enlace vence en 15 minutos y se puede usar una sola vez.\n"
                    + "Si no lo solicitaste, ignorá este correo. Tu contraseña no cambió.\n\nEquipo de LogiTrack");
        for (int attempt = 0; attempt < 2; attempt++) {
            try {
                mailSender.send(message);
                emailSuccessCounter.increment();
                return;
            } catch (Exception failure) {
                if (attempt == 0 && failure instanceof org.springframework.mail.MailSendException) {
                    try {
                        Thread.sleep(1000);
                        continue;
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }
                emailFailureCounter.increment();
                log.error("No se pudo entregar el correo de recuperación ({})", failure.getClass().getSimpleName());
                return;
            }
        }
    }

    /**
     * Valida explícitamente la configuración SMTP, rechazando valores vacíos o en blanco.
     *
     * @throws IllegalStateException si alguna de las credenciales o propiedades requeridas está vacía o en blanco.
     */
    public void validateSmtpConfiguration() {
        if (!hasValidSmtpProperties()) {
            throw new IllegalStateException("Configuración SMTP inválida: host, username y password son requeridos y no pueden estar vacíos ni en blanco");
        }
    }

    public double getFailureCount() {
        return emailFailureCounter.count();
    }

    public double getSuccessCount() {
        return emailSuccessCounter.count();
    }
}
