package com.logitrack.security;

import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.service.AuthService;
import com.logitrack.security.service.CustomerProvisioner;
import com.nimbusds.jwt.SignedJWT;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
class ConcurrentCustomerLoginTest {
    @Autowired AuthService auth;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @MockitoBean CustomerProvisioner profiles;

    @Test void concurrentFirstLoginsPersistOneLinkAndAllReceiveTheSameCustomer() throws Exception {
        var username = "parallel-" + UUID.randomUUID();
        var user = new User(username + "@example.test", username, "Cliente", passwords.encode("Password123!"), Set.of(Role.CLIENTE), null, null);
        user.setEmailVerified(true); users.saveAndFlush(user);
        var customer = UUID.randomUUID();
        when(profiles.required(any())).thenAnswer(inv -> ((User) inv.getArgument(0)).getCustomerId() == null);
        doAnswer(inv -> { Thread.sleep(100); ((User) inv.getArgument(0)).linkCustomer(customer); return null; })
                .when(profiles).ensureLinked(any());
        Callable<String> login = () -> SignedJWT.parse(auth.login(new LoginRequest(username, null, "Password123!")).accessToken())
                .getJWTClaimsSet().getStringClaim("customerId");
        try (var pool = Executors.newFixedThreadPool(4)) {
            for (var result : pool.invokeAll(List.of(login, login, login, login))) {
                assertThat(result.get()).isEqualTo(customer.toString());
            }
            verify(profiles, times(1)).ensureLinked(any());
            assertThat(users.findById(user.getId()).orElseThrow().getCustomerId()).isEqualTo(customer);
        } finally {
            users.deleteById(user.getId());
        }
    }
}
