package com.logitrack.security;

import com.logitrack.security.controller.PasswordRecoveryController;
import com.logitrack.security.dto.ResendVerificationRequest;
import com.logitrack.security.service.PasswordResetRequests;
import com.logitrack.security.service.PasswordResetService;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PasswordRecoveryLimitTest {
    @Test void throttlesBeforeQueueingMoreEmails() {
        var worker = mock(PasswordResetRequests.class);
        var controller = new PasswordRecoveryController(worker,mock(PasswordResetService.class));
        for(int i=0;i<30;i++) controller.forgot(new ResendVerificationRequest("someone@example.test"));
        assertThatThrownBy(() -> controller.forgot(new ResendVerificationRequest("someone@example.test")))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(429));
        verify(worker,times(30)).submit(anyString());
    }
}
