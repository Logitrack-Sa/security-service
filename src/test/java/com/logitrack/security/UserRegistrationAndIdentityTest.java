package com.logitrack.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.bootstrap.AdminBootstrap;
import com.logitrack.security.config.AdminProperties;
import com.logitrack.security.dto.CourierLinkRequest;
import com.logitrack.security.dto.CreateUserRequest;
import com.logitrack.security.dto.CustomerLinkRequest;
import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.dto.UpdateRolesRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.service.UserService;
import jakarta.persistence.EntityManager;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Suite completa de pruebas de integración para la issue S2-12:
 * Registrar usuarios y vincular identidades sin elevar privilegios.
 *
 * <p>Verifica:
 * <ul>
 *   <li>Registro público exclusivamente con rol CLIENTE y contraseña hasheada.</li>
 *   <li>Rechazo de intentos de escalación de privilegios (roles ADMIN/REPARTIDOR o identidades en payload).</li>
 *   <li>Respuestas 400 para payloads inválidos y 409 para duplicidad de emails, usernames, customerId y courierId.</li>
 *   <li>Provisión segura de ADMIN inicial por variables de entorno de forma idempotente.</li>
 *   <li>Altas privilegiadas y vinculación confiable de customerId y courierId reservadas para ADMIN autenticado.</li>
 *   <li>Ausencia absoluta de contraseñas y hashes criptográficos en respuestas JSON.</li>
 * </ul>
 * </p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class UserRegistrationAndIdentityTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EntityManager entityManager;

    @Nested
    @DisplayName("Criterio 1: Registro público solo CLIENTE y prevención de escalación")
    class PublicRegistrationTests {

        /**
         * Verifica que un registro público válido cree exitosamente un usuario con rol CLIENTE
         * y contraseña hasheada con PasswordEncoder (BCrypt).
         */
        @Test
        @DisplayName("POST /api/v1/auth/register exitoso asigna exclusivamente rol CLIENTE")
        void publicRegistrationSuccessCreatesClienteOnly() throws Exception {
            var request = new RegisterRequest(
                    "cliente.valido@logitrack.com",
                    "PasswordSeguro123!",
                    "cliente_valido",
                    "Juan Pérez",
                    null,
                    null,
                    null,
                    null
            );

            var result = http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(header().string("Location", containsString("/api/v1/users/")))
                    .andExpect(jsonPath("$.id").isNotEmpty())
                    .andExpect(jsonPath("$.email", is("cliente.valido@logitrack.com")))
                    .andExpect(jsonPath("$.username", is("cliente_valido")))
                    .andExpect(jsonPath("$.name", is("Juan Pérez")))
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.roles.length()", is(1)))
                    .andExpect(jsonPath("$.enabled", is(true)))
                    .andExpect(jsonPath("$.customerId").doesNotExist())
                    .andExpect(jsonPath("$.courierId").doesNotExist())
                    .andExpect(jsonPath("$.password").doesNotExist())
                    .andExpect(jsonPath("$.passwordHash").doesNotExist())
                    .andReturn();

            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody)
                    .doesNotContain("password")
                    .doesNotContain("PasswordSeguro123!")
                    .doesNotContain("$2a$")
                    .doesNotContain("$2b$");

            var storedUser = userRepository.findByEmail("cliente.valido@logitrack.com").orElseThrow();
            assertThat(passwordEncoder.matches("PasswordSeguro123!", storedUser.getPasswordHash())).isTrue();
            assertThat(storedUser.getRoles()).containsExactly(Role.CLIENTE);
            assertThat(storedUser.getCustomerId()).isNull();
            assertThat(storedUser.getCourierId()).isNull();
        }

        /**
         * Verifica que especificar explícitamente el rol CLIENTE en el payload sea aceptado.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con role 'CLIENTE' explícito es aceptado")
        void publicRegistrationWithExplicitClienteRoleSucceeds() throws Exception {
            var request = new RegisterRequest(
                    "cliente.explicito@logitrack.com",
                    "PasswordSeguro123!",
                    "cliente_exp",
                    "Cliente Explícito",
                    "CLIENTE",
                    Set.of(Role.CLIENTE),
                    null,
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.roles.length()", is(1)));
        }

        /**
         * Verifica que el intento de solicitar rol ADMIN en el campo role sea rechazado con 400 Bad Request.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con role 'ADMIN' es rechazado con 400 Bad Request")
        void publicRegistrationRejectsRoleAdmin() throws Exception {
            var request = new RegisterRequest(
                    "hacker.admin@logitrack.com",
                    "PasswordSeguro123!",
                    "hacker_admin",
                    "Intento Admin",
                    "ADMIN",
                    null,
                    null,
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")))
                    .andExpect(jsonPath("$.message", containsString("No está permitido solicitar roles privilegiados")));

            assertThat(userRepository.findByEmail("hacker.admin@logitrack.com")).isEmpty();
        }

        /**
         * Verifica que el intento de solicitar rol REPARTIDOR en el campo role sea rechazado con 400 Bad Request.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con role 'REPARTIDOR' es rechazado con 400 Bad Request")
        void publicRegistrationRejectsRoleRepartidor() throws Exception {
            var request = new RegisterRequest(
                    "hacker.courier@logitrack.com",
                    "PasswordSeguro123!",
                    "hacker_courier",
                    "Intento Courier",
                    "REPARTIDOR",
                    null,
                    null,
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")));

            assertThat(userRepository.findByEmail("hacker.courier@logitrack.com")).isEmpty();
        }

        /**
         * Verifica que el intento de solicitar roles privilegiados a través de la lista roles sea rechazado con 400.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con roles conteniendo ADMIN o REPARTIDOR es rechazado con 400")
        void publicRegistrationRejectsPrivilegedRolesCollection() throws Exception {
            var request = new RegisterRequest(
                    "hacker.multi@logitrack.com",
                    "PasswordSeguro123!",
                    "hacker_multi",
                    "Intento Multi",
                    null,
                    Set.of(Role.CLIENTE, Role.ADMIN),
                    null,
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")));

            assertThat(userRepository.findByEmail("hacker.multi@logitrack.com")).isEmpty();
        }

        /**
         * Verifica que el intento de autoasignar un customerId en el registro público sea rechazado con 400.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con customerId en payload es rechazado con 400 Bad Request")
        void publicRegistrationRejectsCustomerIdInPayload() throws Exception {
            var request = new RegisterRequest(
                    "hacker.customer@logitrack.com",
                    "PasswordSeguro123!",
                    "hacker_cust",
                    "Intento Customer",
                    null,
                    null,
                    UUID.randomUUID(),
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")))
                    .andExpect(jsonPath("$.message", containsString("customerId")));

            assertThat(userRepository.findByEmail("hacker.customer@logitrack.com")).isEmpty();
        }

        /**
         * Verifica que el intento de autoasignar un courierId en el registro público sea rechazado con 400.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con courierId en payload es rechazado con 400 Bad Request")
        void publicRegistrationRejectsCourierIdInPayload() throws Exception {
            var request = new RegisterRequest(
                    "hacker.courierid@logitrack.com",
                    "PasswordSeguro123!",
                    "hacker_courid",
                    "Intento CourierId",
                    null,
                    null,
                    null,
                    UUID.randomUUID()
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("PRIVILEGE_ESCALATION")))
                    .andExpect(jsonPath("$.message", containsString("courierId")));

            assertThat(userRepository.findByEmail("hacker.courierid@logitrack.com")).isEmpty();
        }
    }

    @Nested
    @DisplayName("Criterio 4: Duplicidad (409) y Validación (400)")
    class ValidationAndDuplicityTests {

        /**
         * Verifica que registrar un usuario con email duplicado responda 409 Conflict.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con email duplicado devuelve 409 Conflict")
        void duplicateEmailReturns409Conflict() throws Exception {
            userRepository.saveAndFlush(new User("existente@logitrack.com", passwordEncoder.encode("Password123!"), Set.of(Role.CLIENTE)));

            var duplicateRequest = new RegisterRequest(
                    " EXISTENTE@logitrack.com ",
                    "PasswordSeguro123!",
                    "otro_username",
                    "Usuario Duplicado",
                    null,
                    null,
                    null,
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(duplicateRequest)))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code", is("DUPLICATE_RESOURCE")))
                    .andExpect(jsonPath("$.message", containsString("ya se encuentra registrado")));
        }

        /**
         * Verifica que registrar un usuario con username duplicado responda 409 Conflict.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con username duplicado devuelve 409 Conflict")
        void duplicateUsernameReturns409Conflict() throws Exception {
            var existing = new User("primero@logitrack.com", "usuario_comun", "Nombre", passwordEncoder.encode("Password123!"), Set.of(Role.CLIENTE), null, null);
            userRepository.saveAndFlush(existing);

            var duplicateRequest = new RegisterRequest(
                    "segundo@logitrack.com",
                    "PasswordSeguro123!",
                    "USUARIO_COMUN",
                    "Otro Usuario",
                    null,
                    null,
                    null,
                    null
            );

            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(duplicateRequest)))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code", is("DUPLICATE_RESOURCE")))
                    .andExpect(jsonPath("$.message", containsString("nombre de usuario")));
        }

        /**
         * Verifica que un payload con datos inválidos o incompletos responda 400 Bad Request.
         */
        @Test
        @DisplayName("POST /api/v1/auth/register con payload inválido responde 400 Bad Request")
        void invalidPayloadReturns400BadRequest() throws Exception {
            // Email inválido
            var invalidEmail = new RegisterRequest("email-no-valido", "Password123!", null, null, null, null, null, null);
            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(invalidEmail)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("VALIDATION_ERROR")));

            // Contraseña demasiado corta (< 8 caracteres)
            var shortPassword = new RegisterRequest("valido@logitrack.com", "12345", null, null, null, null, null, null);
            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(shortPassword)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("VALIDATION_ERROR")));

            // Body vacío o mal formado
            http.perform(post("/api/v1/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code", is("VALIDATION_ERROR")));
        }
    }

    @Nested
    @DisplayName("Criterio 2: Provisión de ADMIN por entorno y operaciones administrativas protegidas")
    class AdminProvisioningAndProtectedOperationsTests {

        /**
         * Verifica que AdminBootstrap aprovisione de forma segura el usuario ADMIN inicial
         * a partir de las propiedades de entorno configuradas.
         */
        @Test
        @DisplayName("AdminBootstrap provisiona ADMIN inicial con contraseña hasheada e idempotencia")
        void adminBootstrapProvisionsAdminSecurely() {
            var properties = new AdminProperties(true, "admin_boot", "admin_boot@logitrack.com", "AdminPassword123!");
            var bootstrap = new AdminBootstrap(userRepository, passwordEncoder, properties);

            bootstrap.run(new DefaultApplicationArguments());

            var adminUser = userRepository.findByEmail("admin_boot@logitrack.com").orElseThrow();
            assertThat(adminUser.getUsername()).isEqualTo("admin_boot");
            assertThat(adminUser.getRoles()).containsExactly(Role.ADMIN);
            assertThat(passwordEncoder.matches("AdminPassword123!", adminUser.getPasswordHash())).isTrue();
            assertThat(adminUser.isEnabled()).isTrue();

            // Ejecución posterior idempotente: no duplica ni falla
            bootstrap.run(new DefaultApplicationArguments());
            assertThat(userRepository.findAll().stream().filter(u -> "admin_boot@logitrack.com".equals(u.getEmail())).count()).isEqualTo(1);
        }

        /**
         * Verifica que cuando la provisión de ADMIN está desactivada o sin contraseña, no se cree ningún usuario.
         */
        @Test
        @DisplayName("AdminBootstrap no crea usuario si está deshabilitado o sin contraseña")
        void adminBootstrapDisabledDoesNotCreateUser() {
            var disabledProps = new AdminProperties(false, "disabled", "disabled@logitrack.com", "somePassword");
            new AdminBootstrap(userRepository, passwordEncoder, disabledProps).run(new DefaultApplicationArguments());
            assertThat(userRepository.findByEmail("disabled@logitrack.com")).isEmpty();

            var emptyPassProps = new AdminProperties(true, "nopass", "nopass@logitrack.com", "   ");
            new AdminBootstrap(userRepository, passwordEncoder, emptyPassProps).run(new DefaultApplicationArguments());
            assertThat(userRepository.findByEmail("nopass@logitrack.com")).isEmpty();
        }

        /**
         * Verifica que un usuario con rol ADMIN pueda dar de alta un usuario REPARTIDOR con courierId.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("ADMIN autenticado puede crear REPARTIDOR con courierId (POST /api/v1/users)")
        void adminCanCreateRepartidorWithCourierId() throws Exception {
            var courierId = UUID.randomUUID();
            var createRequest = new CreateUserRequest(
                    "repartidor.nuevo@logitrack.com",
                    "CourierPass123!",
                    "repartidor_nuevo",
                    "Carlos Repartidor",
                    Set.of(Role.REPARTIDOR),
                    null,
                    courierId
            );

            http.perform(post("/api/v1/users")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(createRequest)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").isNotEmpty())
                    .andExpect(jsonPath("$.email", is("repartidor.nuevo@logitrack.com")))
                    .andExpect(jsonPath("$.roles", hasItem("REPARTIDOR")))
                    .andExpect(jsonPath("$.courierId", is(courierId.toString())))
                    .andExpect(jsonPath("$.password").doesNotExist())
                    .andExpect(jsonPath("$.passwordHash").doesNotExist());

            var saved = userRepository.findByCourierId(courierId).orElseThrow();
            assertThat(saved.getEmail()).isEqualTo("repartidor.nuevo@logitrack.com");
            assertThat(saved.getRoles()).containsExactly(Role.REPARTIDOR);
        }

        /**
         * Verifica que un usuario no autenticado o con rol no ADMIN no pueda acceder a POST /api/v1/users.
         */
        @Test
        @DisplayName("Usuarios no autenticados o no ADMIN reciben 403 en POST /api/v1/users")
        void nonAdminForbiddenOnUserCreation() throws Exception {
            var request = new CreateUserRequest("otro@logitrack.com", "Password123!", null, null, Set.of(Role.ADMIN), null, null);

            // Sin autenticación -> 403
            http.perform(post("/api/v1/users")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isForbidden());
        }

        /**
         * Verifica que un usuario con rol CLIENTE reciba 403 Forbidden al intentar acceder a rutas de administración.
         */
        @Test
        @WithMockUser(username = "cliente", roles = {"CLIENTE"})
        @DisplayName("Usuario con rol CLIENTE recibe 403 en rutas de /api/v1/users/**")
        void clienteForbiddenOnAdminEndpoints() throws Exception {
            var request = new CreateUserRequest("otro2@logitrack.com", "Password123!", null, null, Set.of(Role.ADMIN), null, null);

            http.perform(post("/api/v1/users")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(request)))
                    .andExpect(status().isForbidden());

            http.perform(get("/api/v1/users/" + UUID.randomUUID()))
                    .andExpect(status().isForbidden());
        }

        /**
         * Verifica que ADMIN autenticado pueda actualizar los roles de un usuario existente.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("ADMIN autenticado puede actualizar roles de usuario (PUT /api/v1/users/{id}/roles)")
        void adminCanUpdateUserRoles() throws Exception {
            var user = userRepository.saveAndFlush(new User("promover@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE)));

            var updateRequest = new UpdateRolesRequest(Set.of(Role.CLIENTE, Role.REPARTIDOR));

            http.perform(put("/api/v1/users/" + user.getId() + "/roles")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(updateRequest)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.roles", hasItem("CLIENTE")))
                    .andExpect(jsonPath("$.roles", hasItem("REPARTIDOR")))
                    .andExpect(jsonPath("$.roles.length()", is(2)));

            entityManager.clear();
            var updated = userRepository.findById(user.getId()).orElseThrow();
            assertThat(updated.getRoles()).containsExactlyInAnyOrder(Role.CLIENTE, Role.REPARTIDOR);
        }
    }

    @Nested
    @DisplayName("Criterio 3: Vinculación confiable de identidades (customerId y courierId) y unicidad")
    class DomainIdentityLinkingTests {

        /**
         * Verifica que ADMIN autenticado pueda vincular un customerId a un usuario.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("ADMIN autenticado puede vincular customerId (PUT /api/v1/users/{id}/customer-link)")
        void adminCanLinkCustomerId() throws Exception {
            var user = userRepository.saveAndFlush(new User("cliente.link@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE)));
            var customerId = UUID.randomUUID();

            http.perform(put("/api/v1/users/" + user.getId() + "/customer-link")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(new CustomerLinkRequest(customerId))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(user.getId().toString())))
                    .andExpect(jsonPath("$.customerId", is(customerId.toString())));

            entityManager.clear();
            var updated = userRepository.findById(user.getId()).orElseThrow();
            assertThat(updated.getCustomerId()).isEqualTo(customerId);
        }

        /**
         * Verifica que ADMIN autenticado pueda vincular un courierId a un usuario.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("ADMIN autenticado puede vincular courierId (PUT /api/v1/users/{id}/courier-link)")
        void adminCanLinkCourierId() throws Exception {
            var user = userRepository.saveAndFlush(new User("courier.link@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.REPARTIDOR)));
            var courierId = UUID.randomUUID();

            http.perform(put("/api/v1/users/" + user.getId() + "/courier-link")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(new CourierLinkRequest(courierId))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(user.getId().toString())))
                    .andExpect(jsonPath("$.courierId", is(courierId.toString())));

            entityManager.clear();
            var updated = userRepository.findById(user.getId()).orElseThrow();
            assertThat(updated.getCourierId()).isEqualTo(courierId);
        }

        /**
         * Verifica que intentar vincular un customerId ya asignado a otro usuario devuelva 409 Conflict.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("Intentar vincular customerId duplicado devuelve 409 Conflict")
        void duplicateCustomerIdReturns409Conflict() throws Exception {
            var sharedCustomerId = UUID.randomUUID();
            var userA = new User("user.a@logitrack.com", null, null, passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE), sharedCustomerId, null);
            userRepository.saveAndFlush(userA);

            var userB = new User("user.b@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
            userRepository.saveAndFlush(userB);

            http.perform(put("/api/v1/users/" + userB.getId() + "/customer-link")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(new CustomerLinkRequest(sharedCustomerId))))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code", is("DUPLICATE_RESOURCE")))
                    .andExpect(jsonPath("$.message", containsString("ya se encuentra vinculado a otro usuario")));
        }

        /**
         * Verifica que intentar vincular un courierId ya asignado a otro usuario devuelva 409 Conflict.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("Intentar vincular courierId duplicado devuelve 409 Conflict")
        void duplicateCourierIdReturns409Conflict() throws Exception {
            var sharedCourierId = UUID.randomUUID();
            var userA = new User("courier.a@logitrack.com", null, null, passwordEncoder.encode("Pass123!"), Set.of(Role.REPARTIDOR), null, sharedCourierId);
            userRepository.saveAndFlush(userA);

            var userB = new User("courier.b@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.REPARTIDOR));
            userRepository.saveAndFlush(userB);

            http.perform(put("/api/v1/users/" + userB.getId() + "/courier-link")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(new CourierLinkRequest(sharedCourierId))))
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.code", is("DUPLICATE_RESOURCE")))
                    .andExpect(jsonPath("$.message", containsString("ya se encuentra vinculado a otro usuario")));
        }

        /**
         * Verifica que vincular el mismo customerId al mismo usuario sea idempotente y no devuelva conflicto.
         */
        @Test
        @WithMockUser(username = "admin", roles = {"ADMIN"})
        @DisplayName("Re-vincular el mismo customerId al mismo usuario es permitido")
        void relinkingSameCustomerIdToSameUserIsAllowed() throws Exception {
            var customerId = UUID.randomUUID();
            var user = new User("user.relink@logitrack.com", null, null, passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE), customerId, null);
            userRepository.saveAndFlush(user);

            http.perform(put("/api/v1/users/" + user.getId() + "/customer-link")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(new CustomerLinkRequest(customerId))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.customerId", is(customerId.toString())));
        }
    }
}
