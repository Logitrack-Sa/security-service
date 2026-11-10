package com.logitrack.security;

import com.logitrack.security.bootstrap.AdminBootstrap;
import com.logitrack.security.config.AdminProperties;
import com.logitrack.security.entity.PasswordResetToken;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.repository.PasswordResetTokenRepository;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.repository.VerificationTokenRepository;
import com.logitrack.security.service.EmailService;
import com.logitrack.security.service.PasswordResetService;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PasswordRecoveryTest {
    @Autowired MockMvc http;
    @Autowired UserRepository users;
    @Autowired PasswordResetTokenRepository tokens;
    @Autowired VerificationTokenRepository verification;
    @Autowired PasswordResetService resets;
    @Autowired PasswordEncoder encoder;
    @Autowired PlatformTransactionManager transactions;
    @MockBean EmailService email;

    @AfterEach void cleanup() {
        tokens.deleteAll(); verification.deleteAll(); users.deleteAll();
    }

    User account(Role role) {
        var user = new User(UUID.randomUUID()+"@example.test", encoder.encode("previous-password"), Set.of(role));
        user.setEmailVerified(true);
        return users.saveAndFlush(user);
    }

    String request(User user) {
        clearInvocations(email);
        resets.request(user.getEmail().toUpperCase(java.util.Locale.ROOT));
        var value = ArgumentCaptor.forClass(String.class);
        verify(email).sendPasswordResetEmail(eq(user.getEmail()), value.capture());
        return value.getValue();
    }

    @ParameterizedTest @EnumSource(Role.class)
    void changesPasswordForEveryRoleWithoutChangingIdentityAndRejectsReplay(Role role) throws Exception {
        var user = account(role);
        String token = request(user);
        assertThat(token).matches("[A-Za-z0-9_-]{43}");
        var saved = tokens.findById(user.getId()).orElseThrow();
        assertThat(saved.getTokenHash()).hasSize(64).doesNotContain(token);
        assertThat(saved.getExpiresAt()).isAfter(Instant.now().plusSeconds(850));
        http.perform(post("/api/v1/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\""+token+"\",\"password\":\"new-password-123\"}"))
                .andExpect(status().isNoContent()).andExpect(header().string("Cache-Control","no-store"));
        var changed = users.findById(user.getId()).orElseThrow();
        assertThat(encoder.matches("new-password-123",changed.getPasswordHash())).isTrue();
        assertThat(encoder.matches("previous-password",changed.getPasswordHash())).isFalse();
        Set<Role> roles = new TransactionTemplate(transactions).execute(tx ->
                users.findById(user.getId()).orElseThrow().getRoles());
        assertThat(roles).containsExactly(role);
        http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\""+user.getEmail()+"\",\"password\":\"previous-password\"}"))
                .andExpect(status().isUnauthorized());
        http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\""+user.getEmail()+"\",\"password\":\"new-password-123\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isString());
        assertThat(tokens.existsById(user.getId())).isFalse();
        assertThatThrownBy(() -> resets.reset(token,"another-password")).isInstanceOf(ResponseStatusException.class);
    }

    @Test void genericRequestDoesNotExposeAccountOrToken() throws Exception {
        http.perform(post("/api/v1/auth/forgot-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"missing@example.test\"}"))
                .andExpect(status().isAccepted()).andExpect(header().string("Cache-Control","no-store"))
                .andExpect(jsonPath("$.message").value("Si la cuenta está activa, recibirás un enlace para restablecer tu contraseña."))
                .andExpect(jsonPath("$.token").doesNotExist());
        http.perform(post("/api/v1/auth/forgot-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"not-an-email\"}")).andExpect(status().isBadRequest());
        http.perform(get("/api/v1/auth/reset-password")).andExpect(status().is4xxClientError());
    }

    @Test void requestCooldownDoesNotInvalidateWorkingLink() {
        var user = account(Role.CLIENTE);
        String token = request(user);
        resets.request(user.getEmail());
        verify(email,times(1)).sendPasswordResetEmail(anyString(),anyString());
        resets.reset(token,"new-password-123");
    }

    @Test void replacementInvalidatesPreviousLinkAndRejectsExpiry() {
        var user = account(Role.REPARTIDOR);
        String first = request(user);
        var saved = tokens.findById(user.getId()).orElseThrow();
        tokens.saveAndFlush(new PasswordResetToken(user.getId(),saved.getTokenHash(),Instant.now().minusSeconds(65)));
        String next = request(user);
        assertThatThrownBy(() -> resets.reset(first,"new-password-123")).isInstanceOf(ResponseStatusException.class);
        saved = tokens.findById(user.getId()).orElseThrow();
        tokens.saveAndFlush(new PasswordResetToken(user.getId(),saved.getTokenHash(),Instant.now().minusSeconds(1000)));
        assertThatThrownBy(() -> resets.reset(next,"new-password-123")).isInstanceOf(ResponseStatusException.class);
        assertThat(encoder.matches("previous-password",users.findById(user.getId()).orElseThrow().getPasswordHash())).isTrue();
    }

    @Test void disabledAndUnverifiedAccountsCannotRecover() {
        var disabled = account(Role.CLIENTE); disabled.setEnabled(false); users.saveAndFlush(disabled);
        var unverified = account(Role.REPARTIDOR); unverified.setEmailVerified(false); users.saveAndFlush(unverified);
        resets.request(disabled.getEmail()); resets.request(unverified.getEmail());
        verifyNoInteractions(email);
        assertThat(tokens.count()).isZero();
    }

    @Test void rollbackNeverSendsRecoveryEmail() {
        var user = account(Role.CLIENTE);
        new TransactionTemplate(transactions).executeWithoutResult(tx -> {
            resets.request(user.getEmail());
            verifyNoInteractions(email);
            tx.setRollbackOnly();
        });
        verifyNoInteractions(email);
        assertThat(tokens.count()).isZero();
    }

    @Test void concurrentConsumptionHasExactlyOneWinner() throws Exception {
        var user = account(Role.REPARTIDOR);
        String token = request(user);
        var start = new CountDownLatch(1);
        try(var executor = Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Boolean> consume = () -> {
                start.await();
                try { resets.reset(token,"new-password-123"); return true; }
                catch(ResponseStatusException expected) { return false; }
            };
            var first = executor.submit(consume); var second = executor.submit(consume); start.countDown();
            assertThat(first.get(15,TimeUnit.SECONDS) ^ second.get(15,TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test void passwordValidationAndAdminRestartPreserveRecovery() throws Exception {
        var user = account(Role.ADMIN);
        String token = request(user);
        http.perform(post("/api/v1/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\""+token+"\",\"password\":\"short\"}")).andExpect(status().isBadRequest());
        assertThatThrownBy(() -> resets.reset(token,"á".repeat(50))).isInstanceOf(ResponseStatusException.class);
        resets.reset(token,"new-password-123");
        new AdminBootstrap(users,encoder,new AdminProperties(true,"admin",user.getEmail(),"bootstrap-password"))
                .run(new org.springframework.boot.DefaultApplicationArguments());
        assertThat(encoder.matches("new-password-123",users.findById(user.getId()).orElseThrow().getPasswordHash())).isTrue();
    }
}
