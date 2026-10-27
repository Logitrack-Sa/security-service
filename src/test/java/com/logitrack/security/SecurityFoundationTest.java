package com.logitrack.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.exception.ResourceNotFoundException;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.service.UserService;
import jakarta.persistence.EntityManager;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class SecurityFoundationTest {
    @Autowired UserRepository users;
    @Autowired UserService service;
    @Autowired PasswordEncoder encoder;
    @Autowired EntityManager entities;
    @Autowired ObjectMapper json;
    @Autowired MockMvc http;

    @Test void persistsUuidHashAndRoles() {
        var user = users.saveAndFlush(new User(" TEST@example.test ", encoder.encode("test-password"), Set.of(Role.CLIENTE, Role.REPARTIDOR)));
        var id = user.getId();
        entities.clear();
        var stored = users.findById(id).orElseThrow();
        assertThat(id).isNotNull();
        assertThat(stored.getEmail()).isEqualTo("test@example.test");
        assertThat(encoder.matches("test-password", stored.getPasswordHash())).isTrue();
        assertThat(stored.getRoles()).containsExactlyInAnyOrder(Role.CLIENTE, Role.REPARTIDOR);
        assertThat(stored.isEnabled()).isTrue();
    }
    @Test void emailIsUniqueAfterNormalization() {
        users.saveAndFlush(new User("same@example.test", encoder.encode("test"), Set.of(Role.CLIENTE)));
        assertThatThrownBy(() -> users.saveAndFlush(new User("SAME@example.test", encoder.encode("other"), Set.of(Role.ADMIN))))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
    @Test void emptyRolesCannotBePersisted() {
        assertThatThrownBy(() -> users.saveAndFlush(new User("empty@example.test", encoder.encode("test"), Set.of())))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);
    }
    @Test void plaintextCannotBeStoredAsPasswordHash() {
        assertThatThrownBy(() -> users.saveAndFlush(new User("plain@example.test", "plaintext", Set.of(Role.CLIENTE))))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);
    }
    @Test void responseNeverContainsHash() throws Exception {
        var user = users.saveAndFlush(new User("dto@example.test", encoder.encode("test"), Set.of(Role.ADMIN)));
        var output = json.writeValueAsString(service.findById(user.getId()));
        assertThat(output).contains("dto@example.test", "ADMIN").doesNotContain("password", user.getPasswordHash());
        assertThat(json.writeValueAsString(user)).doesNotContain("password", user.getPasswordHash());
    }
    @Test void missingUserIsExplicit() {
        assertThatThrownBy(() -> service.findById(UUID.randomUUID())).isInstanceOf(ResourceNotFoundException.class);
    }
    @Test void healthIsPublicAndMinimal() throws Exception {
        http.perform(get("/actuator/health")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP")).andExpect(jsonPath("$.components").doesNotExist());
    }
    @Test void businessEndpointsAreNotPublic() throws Exception {
        http.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());
        http.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
    }
}
