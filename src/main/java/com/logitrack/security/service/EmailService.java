package com.logitrack.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * Captura excepciones de red o de autenticación SMTP para asegurar la resiliencia en entornos
 * de prueba o desarrollo sin conectividad saliente.</p>
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;
    private final String verificationBaseUrl;
    private final String fromEmail;

    /**
     * Construye el servicio inyectando el emisor de correo y las propiedades de configuración.
     *
     * @param mailSender componente de envío de correos de Spring.
     * @param verificationBaseUrl URL base del frontend para el enlace de verificación.
     * @param fromEmail dirección de correo de origen.
     */
    public EmailService(
            JavaMailSender mailSender,
            @Value("${logitrack.frontend.verification-url:http://localhost:3000/verify-email}") String verificationBaseUrl,
            @Value("${spring.mail.username:noreply@logitrack.com}") String fromEmail
    ) {
        this.mailSender = mailSender;
        this.verificationBaseUrl = verificationBaseUrl;
        this.fromEmail = fromEmail;
    }

    /**
     * Envía asíncronamente un correo electrónico con el enlace de activación de cuenta.
     *
     * @param toEmail dirección del destinatario.
     * @param token identificador UUID v4 del token de verificación.
     */
    @Async
    public void sendVerificationEmail(String toEmail, String token) {
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
            log.info("Correo de verificación enviado exitosamente a '{}'", toEmail);
        } catch (Exception ex) {
            log.warn("No se pudo enviar el correo de verificación a '{}': {}", toEmail, ex.getMessage());
        }
    }
}
