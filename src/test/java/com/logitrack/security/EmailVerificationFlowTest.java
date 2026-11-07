package com.logitrack.security;

import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.entity.VerificationToken;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.repository.VerificationTokenRepository;
import com.logitrack.security.service.EmailService;
import com.logitrack.security.service.EmailVerificationService;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailVerificationFlowTest {
    @Autowired MockMvc http;
    @Autowired UserRepository users;
    @Autowired VerificationTokenRepository tokens;
    @Autowired PasswordEncoder encoder;
    @Autowired EmailVerificationService verification;
    @Autowired PlatformTransactionManager transactions;
    @MockBean EmailService email;

    @AfterEach
    void cleanup() {
        tokens.deleteAll();
        users.deleteAll();
    }

    private VerificationToken pending() {
        var user = new User(UUID.randomUUID() + "@example.test", encoder.encode("Password123!"), Set.of(Role.CLIENTE));
        user.setEnabled(false);
        user.setEmailVerified(false);
        return tokens.saveAndFlush(new VerificationToken(users.saveAndFlush(user), 24));
    }

    @Test
    void confirmEnablesLoginWithVerifiedClaimAndRejectsReplay() throws Exception {
        var token = pending();
        http.perform(post("/api/v1/auth/verify-email").param("token", token.getToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.verified").value(true));
        var user = users.findById(token.getUser().getId()).orElseThrow();
        assertThat(user.isEnabled()).isTrue();
        assertThat(user.isEmailVerified()).isTrue();
        assertThat(tokens.findByToken(token.getToken()).orElseThrow().isRevoked()).isTrue();
        var login = http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + user.getEmail() + "\",\"password\":\"Password123!\"}"))
                .andExpect(status().isOk()).andReturn();
        var json = new com.fasterxml.jackson.databind.ObjectMapper().readTree(login.getResponse().getContentAsString());
        assertThat(com.nimbusds.jwt.SignedJWT.parse(json.get("accessToken").asText())
                .getJWTClaimsSet().getBooleanClaim("email_verified")).isTrue();
        http.perform(post("/api/v1/auth/verify-email").param("token", token.getToken()))
                .andExpect(status().isNotFound()).andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("INVALID_VERIFICATION_TOKEN"));
    }

    @Test
    void expiredAndUnknownTokensUseProblemDetailWithoutChangingUser() throws Exception {
        var token = pending();
        token.setExpiryDate(Instant.now().minusSeconds(1));
        tokens.saveAndFlush(token);
        http.perform(post("/api/v1/auth/verify-email").param("token", token.getToken()))
                .andExpect(status().isBadRequest()).andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(400)).andExpect(jsonPath("$.code").value("VERIFICATION_TOKEN_EXPIRED"))
                .andExpect(jsonPath("$.instance").value("/api/v1/auth/verify-email"));
        assertThat(users.findById(token.getUser().getId()).orElseThrow().isEnabled()).isFalse();
        assertThat(tokens.findByToken(token.getToken()).orElseThrow().isRevoked()).isFalse();
        http.perform(post("/api/v1/auth/verify-email").param("token", "unknown"))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("INVALID_VERIFICATION_TOKEN"));
    }

    @Test
    void resendRevokesOldLinkAndDispatchesNewLink() throws Exception {
        var old = pending();
        String address = old.getUser().getEmail();
        http.perform(post("/api/v1/auth/resend-verification").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + address.toUpperCase(java.util.Locale.ROOT) + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.sent").value(true));
        assertThat(tokens.findByToken(old.getToken()).orElseThrow().isRevoked()).isTrue();
        var active = tokens.findAllByUserAndRevokedFalse(old.getUser());
        assertThat(active).hasSize(1);
        assertThat(active.getFirst().getToken()).isNotEqualTo(old.getToken());
        verify(email).sendVerificationEmail(address, active.getFirst().getToken());
        http.perform(post("/api/v1/auth/verify-email").param("token", old.getToken()))
                .andExpect(status().isNotFound());
        http.perform(post("/api/v1/auth/verify-email").param("token", active.getFirst().getToken()))
                .andExpect(status().isOk());
    }

    @Test
    void resendRollbackPreservesOldLinkAndDoesNotSend() {
        var old = pending();
        new TransactionTemplate(transactions).executeWithoutResult(tx -> {
            verification.resend(old.getUser().getEmail());
            verify(email, never()).sendVerificationEmail(anyString(), anyString());
            tx.setRollbackOnly();
        });
        assertThat(tokens.findAllByUser(old.getUser())).hasSize(1);
        assertThat(tokens.findByToken(old.getToken()).orElseThrow().isRevoked()).isFalse();
        verifyNoInteractions(email);
    }

    @Test
    void resendIsGenericForUnknownOrVerifiedAccountsAndValidatesBody() throws Exception {
        var old = pending();
        verification.verify(old.getToken());
        for (String address : new String[]{"unknown@example.test", old.getUser().getEmail()}) {
            http.perform(post("/api/v1/auth/resend-verification").contentType(MediaType.APPLICATION_JSON)
                    .content("{\"email\":\"" + address + "\"}"))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.sent").value(true));
        }
        verifyNoInteractions(email);
        http.perform(post("/api/v1/auth/resend-verification").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"invalid\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void simultaneousResendsLeaveOnlyOneActiveLink() throws Exception {
        var old = pending();
        String address = old.getUser().getEmail();
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Void> call = () -> {
                start.await();
                verification.resend(address);
                return null;
            };
            var first = executor.submit(call);
            var second = executor.submit(call);
            start.countDown();
            first.get(15, TimeUnit.SECONDS);
            second.get(15, TimeUnit.SECONDS);
        }
        assertThat(tokens.findAllByUser(old.getUser())).hasSize(3);
        assertThat(tokens.findAllByUserAndRevokedFalse(old.getUser())).hasSize(1);
        verify(email, times(2)).sendVerificationEmail(eq(address), anyString());
    }

    @Test
    void simultaneousConfirmationsConsumeTokenOnlyOnce() throws Exception {
        var token = pending();
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Integer> call = () -> {
                start.await();
                return http.perform(post("/api/v1/auth/verify-email").param("token", token.getToken()))
                        .andReturn().getResponse().getStatus();
            };
            var first = executor.submit(call);
            var second = executor.submit(call);
            start.countDown();
            assertThat(java.util.List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(200, 404);
        }
    }
}
