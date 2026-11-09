package com.logitrack.security;

import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.service.AuthService;
import com.logitrack.security.service.CustomerProvisioner;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AutomaticCustomerLoginTest {
    @Test void loginEmitsFinalTokenOnlyAfterTrustedProfileWasLinked() {
        var users = mock(UserRepository.class); var passwords = mock(PasswordEncoder.class);
        var tokens = mock(JwtTokenService.class); var profiles = mock(CustomerProvisioner.class);
        var user = new User("ana@example.test", "ana", "Ana", "hash", Set.of(Role.CLIENTE), null, null);
        user.setEmailVerified(true); UUID id = UUID.randomUUID(), customerId = UUID.randomUUID();
        ReflectionTestUtils.setField(user, "id", id);
        when(users.findLockedByIdentifier("ana")).thenReturn(Optional.of(user));
        when(passwords.matches("password", "hash")).thenReturn(true);
        when(profiles.required(user)).thenReturn(true);
        doAnswer(inv -> { user.linkCustomer(customerId); return null; }).when(profiles).ensureLinked(user);
        when(tokens.generateToken(user)).thenAnswer(inv -> { assertThat(user.getCustomerId()).isEqualTo(customerId); return "final-token"; });
        var auth = new AuthService(users, passwords, tokens, profiles);
        assertThat(auth.login(new LoginRequest("ana", null, "password")).accessToken()).isEqualTo("final-token");
        clearInvocations(profiles, tokens);
        assertThatThrownBy(() -> auth.login(new LoginRequest("ana", null, "wrong"))).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(profiles, tokens);
    }
}
