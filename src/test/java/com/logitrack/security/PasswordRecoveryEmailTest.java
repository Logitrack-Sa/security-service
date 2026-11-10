package com.logitrack.security;

import com.logitrack.security.service.EmailService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class PasswordRecoveryEmailTest {
    @Test void usesConfiguredUrlAndFragmentWithoutSendingThePassword() {
        var sender = mock(JavaMailSender.class);
        var service = new EmailService(sender,new SimpleMeterRegistry(),"https://example.test/verify-email",
                "sender@example.test","smtp.example.test","test-only");
        ReflectionTestUtils.setField(service,"passwordResetUrl","https://example.test/logitrack/reset-password");
        service.sendPasswordResetEmail("recipient@example.test","a".repeat(43));
        var message = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(sender).send(message.capture());
        assertThat(message.getValue().getTo()).containsExactly("recipient@example.test");
        assertThat(message.getValue().getText()).contains("https://example.test/logitrack/reset-password#token="+"a".repeat(43))
                .contains("15 minutos").doesNotContain("?token=");
        assertThat(service.getSuccessCount()).isEqualTo(1);
    }

    @Test void deliveryFailureIsCountedWithoutFailingTheRequest() {
        var sender = mock(JavaMailSender.class);
        doThrow(new org.springframework.mail.MailSendException("test-only")).when(sender).send(any(SimpleMailMessage.class));
        var service = new EmailService(sender,new SimpleMeterRegistry(),"https://example.test/verify-email",
                "sender@example.test","smtp.example.test","test-only");
        ReflectionTestUtils.setField(service,"passwordResetUrl","https://example.test/reset-password");
        service.sendPasswordResetEmail("recipient@example.test","a".repeat(43));
        assertThat(service.getFailureCount()).isEqualTo(1);
    }
}
