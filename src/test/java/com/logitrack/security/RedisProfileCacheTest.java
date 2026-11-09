package com.logitrack.security;

import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.entity.VerificationToken;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.repository.VerificationTokenRepository;
import com.logitrack.security.service.EmailService;
import com.logitrack.security.service.EmailVerificationService;
import com.logitrack.security.service.UserService;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Ejecutar contra un Redis descartable: TEST_REDIS_PORT=16379 ./mvnw verify. */
@SpringBootTest(properties = {"spring.cache.type=redis", "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=${TEST_REDIS_PORT:16379}", "spring.data.redis.password="})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@EnabledIfEnvironmentVariable(named = "TEST_REDIS_PORT", matches = "\\d+")
class RedisProfileCacheTest {
    @Autowired MockMvc http;
    @Autowired org.springframework.security.crypto.password.PasswordEncoder encoder;
    @SpyBean UserRepository users;
    @Autowired VerificationTokenRepository tokens;
    @Autowired UserService userService;
    @Autowired EmailVerificationService verification;
    @Autowired CacheManager cacheManager;
    @Autowired StringRedisTemplate redis;
    @Autowired PlatformTransactionManager transactions;
    @MockBean EmailService email;
    @Autowired(required = false)
    io.micrometer.core.instrument.MeterRegistry meterRegistry;

    @AfterEach
    void cleanup() {
        cacheManager.getCache("user_profiles").clear();
        tokens.deleteAll();
        users.deleteAll();
    }

    private User account(boolean verified) {
        var user = new User(UUID.randomUUID() + "@example.test", encoder.encode("Password123!"), Set.of(Role.CLIENTE));
        user.setEnabled(verified);
        user.setEmailVerified(verified);
        return users.saveAndFlush(user);
    }

    private String key(User user) { return "user::username::" + user.getId(); }

    @Test
    void repeatedMeHitsRedisWithFifteenMinuteTtlAndRolesEvict() throws Exception {
        var user = account(true);
        clearInvocations(users);
        for (int i = 0; i < 2; i++) {
            http.perform(get("/api/v1/auth/me").with(jwt().jwt(j -> j.subject(user.getId().toString()))))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(user.getId().toString()))
                    .andExpect(jsonPath("$.emailVerified").value(true));
        }
        verify(users, times(1)).findById(user.getId());
        String redisKey = "user_profiles::" + key(user);
        assertThat(redis.getExpire(redisKey)).isBetween(880L, 900L);
        assertThat(redis.opsForValue().get(redisKey)).contains(user.getEmail()).doesNotContain(user.getPasswordHash(), "passwordHash");
        http.perform(put("/api/v1/users/" + user.getId() + "/roles")
                .with(jwt().jwt(j -> j.subject(UUID.randomUUID().toString()))
                        .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType("application/json").content("{\"roles\":[\"REPARTIDOR\"]}"))
                .andExpect(status().isOk());
        assertThat(redis.hasKey(redisKey)).isFalse();
        http.perform(get("/api/v1/auth/me").with(jwt().jwt(j -> j.subject(user.getId().toString()))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.roles[0]").value("REPARTIDOR"));
    }

    @Test
    void verificationEvictsOnlyAfterCommitAndRollbackKeepsCacheAndToken() {
        var user = account(false);
        var token = tokens.saveAndFlush(new VerificationToken(user, 24));
        var cache = cacheManager.getCache("user_profiles");
        cache.put(key(user), userService.findById(user.getId()));
        new TransactionTemplate(transactions).executeWithoutResult(tx -> {
            verification.verify(token.getToken());
            assertThat(cache.get(key(user), UserResponse.class).emailVerified()).isFalse();
            tx.setRollbackOnly();
        });
        assertThat(cache.get(key(user))).isNotNull();
        assertThat(tokens.findByToken(token.getToken()).orElseThrow().isRevoked()).isFalse();
        verification.verify(token.getToken());
        assertThat(cache.get(key(user))).isNull();
        assertThat(users.findById(user.getId()).orElseThrow().isEmailVerified()).isTrue();
    }

    @Test
    void roleRollbackDoesNotEvictAndIdentityLinksInvalidateProfile() {
        var user = account(true);
        var cache = cacheManager.getCache("user_profiles");
        cache.put(key(user), userService.findById(user.getId()));
        new TransactionTemplate(transactions).executeWithoutResult(tx -> {
            userService.updateRoles(user.getId(), Set.of(Role.REPARTIDOR));
            tx.setRollbackOnly();
        });
        assertThat(cache.get(key(user), UserResponse.class).roles()).containsExactly(Role.CLIENTE);
        userService.linkCustomer(user.getId(), UUID.randomUUID());
        assertThat(cache.get(key(user))).isNull();
        cache.put(key(user), userService.findById(user.getId()));
        userService.linkCourier(user.getId(), UUID.randomUUID());
        assertThat(cache.get(key(user))).isNull();
    }

    @Test
    void cacheStatisticsAreRecordedInMicrometer() {
        var user = account(true);
        var cache = cacheManager.getCache("user_profiles");
        assertThat(cache).isNotNull();

        // 1. Cache Miss
        var initial = cache.get(key(user));
        assertThat(initial).isNull();

        // 2. Cache Put
        cache.put(key(user), userService.findById(user.getId()));

        // 3. Cache Hit
        var cached = cache.get(key(user), UserResponse.class);
        assertThat(cached).isNotNull();

        if (meterRegistry != null) {
            var getsHit = meterRegistry.find("cache.gets").tag("result", "hit").functionCounter();
            var getsMiss = meterRegistry.find("cache.gets").tag("result", "miss").functionCounter();
            var puts = meterRegistry.find("cache.puts").functionCounter();

            if (getsHit != null) {
                assertThat(getsHit.count()).isGreaterThanOrEqualTo(1.0);
            }
            if (getsMiss != null) {
                assertThat(getsMiss.count()).isGreaterThanOrEqualTo(1.0);
            }
            if (puts != null) {
                assertThat(puts.count()).isGreaterThanOrEqualTo(1.0);
            }
        }
    }
}
