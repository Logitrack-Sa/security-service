package com.logitrack.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.entity.VerificationToken;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.repository.VerificationTokenRepository;
import com.logitrack.security.service.EmailService;
import com.logitrack.security.service.UserService;
import com.nimbusds.jwt.SignedJWT;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VerificationTokenAndEmailTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private UserRepository userRepository;

    @SpyBean
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JavaMailSender mailSender;

    @AfterEach
    void tearDown() {
        Mockito.reset(mailSender);
        Mockito.reset(verificationTokenRepository);
        verificationTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("VerificationToken genera UUID v4 único con vigencia de 24 horas")
    void verificationTokenEntityGeneratesValidUuidAndExpiry() {
        User user = new User("token.test@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        userRepository.saveAndFlush(user);

        VerificationToken token = new VerificationToken(user, 24);
        verificationTokenRepository.saveAndFlush(token);

        assertThat(token.getToken()).isNotBlank();
        assertThat(token.getToken()).hasSize(36);
        assertThat(token.isRevoked()).isFalse();
        assertThat(token.isExpired()).isFalse();
        assertThat(token.getExpiryDate()).isCloseTo(Instant.now().plus(24, ChronoUnit.HOURS), within(1, ChronoUnit.MINUTES));
    }

    @Test
    @DisplayName("VerificationToken expira correctamente cuando supera la fecha de vencimiento")
    void verificationTokenExpiresWhenPastExpiryDate() {
        User user = new User("expired.token@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        userRepository.saveAndFlush(user);

        VerificationToken token = new VerificationToken(user, -1);
        assertThat(token.isExpired()).isTrue();
    }

    @Test
    @DisplayName("isExpired(Clock.fixed(expiryDate, ZoneOffset.UTC)) devuelve true en el instante exacto de vencimiento")
    void isExpiredReturnsTrueAtExactExpiryInstant() {
        User user = new User("clock.test@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        userRepository.saveAndFlush(user);

        VerificationToken token = new VerificationToken(user, 24);
        Instant expiryDate = token.getExpiryDate();

        // Justo antes del vencimiento (1 milisegundo antes): no debe estar vencido
        Clock justBefore = Clock.fixed(expiryDate.minusMillis(1), ZoneOffset.UTC);
        assertThat(token.isExpired(justBefore)).isFalse();

        // En el instante exacto de expiryDate: debe considerarse vencido
        Clock exactExpiry = Clock.fixed(expiryDate, ZoneOffset.UTC);
        assertThat(token.isExpired(exactExpiry)).isTrue();

        // Posterior al vencimiento (1 milisegundo después): debe estar vencido
        Clock justAfter = Clock.fixed(expiryDate.plusMillis(1), ZoneOffset.UTC);
        assertThat(token.isExpired(justAfter)).isTrue();
    }

    @Test
    @DisplayName("JwtTokenService incluye el claim email_verified reflejando el estado de la entidad")
    void jwtTokenServiceIncludesEmailVerifiedClaim() throws Exception {
        User unverifiedUser = new User("unverified@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        unverifiedUser.setEmailVerified(false);
        userRepository.saveAndFlush(unverifiedUser);

        String unverifiedJwtStr = jwtTokenService.generateToken(unverifiedUser);
        SignedJWT unverifiedJwt = SignedJWT.parse(unverifiedJwtStr);
        assertThat(unverifiedJwt.getJWTClaimsSet().getBooleanClaim("email_verified")).isFalse();

        User verifiedUser = new User("verified@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        verifiedUser.setEmailVerified(true);
        userRepository.saveAndFlush(verifiedUser);

        String verifiedJwtStr = jwtTokenService.generateToken(verifiedUser);
        SignedJWT verifiedJwt = SignedJWT.parse(verifiedJwtStr);
        assertThat(verifiedJwt.getJWTClaimsSet().getBooleanClaim("email_verified")).isTrue();
    }

    @Test
    @DisplayName("POST /api/v1/auth/register persiste usuario deshabilitado, token y despacha correo asíncrono")
    void publicRegistrationCreatesDisabledUserAndSendsEmail() throws Exception {
        var request = new RegisterRequest(
                "nuevo.correo@logitrack.com",
                "PasswordSeguro123!",
                "nuevocorreo",
                "Nuevo Correo",
                null,
                null,
                null,
                null
        );

        http.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email", is("nuevo.correo@logitrack.com")))
                .andExpect(jsonPath("$.enabled", is(false)))
                .andExpect(jsonPath("$.emailVerified", is(false)));

        User user = userRepository.findByEmail("nuevo.correo@logitrack.com").orElseThrow();
        assertThat(user.isEnabled()).isFalse();
        assertThat(user.isEmailVerified()).isFalse();

        var tokens = verificationTokenRepository.findAllByUser(user);
        assertThat(tokens).hasSize(1);
        VerificationToken token = tokens.get(0);
        assertThat(token.getToken()).hasSize(36);
        assertThat(token.isRevoked()).isFalse();

        // El usuario no debe poder loguearse mientras está deshabilitado
        var loginReq = new LoginRequest("nuevocorreo", null, "PasswordSeguro123!");
        http.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(loginReq)))
                .andExpect(status().isUnauthorized());

        // Verificar despacho de email
        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, Mockito.timeout(2000)).send(captor.capture());
        SimpleMailMessage sentMessage = captor.getValue();
        assertThat(sentMessage.getTo()).containsExactly("nuevo.correo@logitrack.com");
        assertThat(sentMessage.getSubject()).contains("Verifica tu cuenta");
        assertThat(sentMessage.getText()).contains(token.getToken());
        assertThat(sentMessage.getText()).contains("http://localhost:3000/verify-email?token=");
    }

    @Test
    @DisplayName("Fallo al persistir VerificationToken hace rollback de la creación del usuario y no envía correo")
    void tokenPersistFailureRollsBackUserAndDoesNotDispatchEmail() {
        doThrow(new RuntimeException("Simulated error saving token"))
                .when(verificationTokenRepository).save(any(VerificationToken.class));

        var request = new RegisterRequest(
                "token.fail@logitrack.com",
                "PasswordSeguro123!",
                "tokenfail",
                "Token Fail",
                null,
                null,
                null,
                null
        );

        assertThatThrownBy(() -> userService.registerPublic(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Simulated error saving token");

        // Atomicidad: el usuario no debe persistirse en la base de datos tras el rollback
        assertThat(userRepository.findByEmail("token.fail@logitrack.com")).isEmpty();

        // El correo no debe haberse enviado
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("El correo de verificación solo se dispara afterCommit")
    void emailIsOnlyDispatchedAfterCommit() {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        var request = new RegisterRequest(
                "aftercommit.user@logitrack.com",
                "PasswordSeguro123!",
                "aftercommit",
                "After Commit",
                null,
                null,
                null,
                null
        );

        template.execute(status -> {
            userService.registerPublic(request);
            // Dentro de la transacción (antes del commit): NO debe dispararse el envío de correo
            verify(mailSender, never()).send(any(SimpleMailMessage.class));
            return null;
        });

        // Una vez completado el commit de la transacción: SÍ se debe disparar el envío
        verify(mailSender, Mockito.timeout(2000)).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("UserResponse refleja emailVerified = true cuando la entidad User está verificada")
    void userResponseReflectsEmailVerifiedWhenUserIsVerified() {
        User user = new User("verified.dto@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        user.setEmailVerified(true);
        userRepository.saveAndFlush(user);

        UserResponse response = userService.findById(user.getId());

        assertThat(response.emailVerified()).isTrue();
        assertThat(response.email()).isEqualTo("verified.dto@logitrack.com");

        // Validamos también que con emailVerified = false se refleje false
        User unverifiedUser = new User("unverified.dto@logitrack.com", passwordEncoder.encode("Pass123!"), Set.of(Role.CLIENTE));
        unverifiedUser.setEmailVerified(false);
        userRepository.saveAndFlush(unverifiedUser);

        UserResponse unverifiedResponse = userService.findById(unverifiedUser.getId());
        assertThat(unverifiedResponse.emailVerified()).isFalse();

        // Constructor canónico con todos los campos
        UserResponse direct = new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getRoles(),
                user.isEnabled(),
                user.isEmailVerified(),
                user.getCustomerId(),
                user.getCourierId()
        );
        assertThat(direct.emailVerified()).isTrue();
    }

    @Test
    @DisplayName("EmailService valida propiedades SMTP requeridas e incrementa métrica de fallo si están vacías")
    void emailServiceValidatesMissingSmtpPropertiesAndIncrementsFailureMetric() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        EmailService service = new EmailService(mailSender, registry, "http://localhost:3000/verify-email", "noreply@logitrack.com", "", "password");
        service.sendVerificationEmail("test@logitrack.com", "token123");

        assertThat(service.getFailureCount()).isEqualTo(1.0);
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("EmailService es resiliente ante fallo de red SMTP y registra métrica de fallo sin propagar excepción")
    void emailServiceHandlesSmtpExceptionGracefully() {
        doThrow(new MailSendException("Conexión rechazada a smtp.gmail.com"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        EmailService service = new EmailService(mailSender, registry, "http://localhost:3000/verify-email", "noreply@logitrack.com", "smtp.gmail.com", "test-smtp-password");
        // No debe lanzar excepción
        service.sendVerificationEmail("fallo@logitrack.com", "dummy-token-uuid");

        verify(mailSender).send(any(SimpleMailMessage.class));
        assertThat(service.getFailureCount()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("EmailService rechaza explícitamente la configuración cuando spring.mail.password está vacío o en blanco")
    void emailServiceRejectsWhenPasswordIsEmptyOrBlank() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        EmailService serviceWithEmptyPassword = new EmailService(
                mailSender, registry, "http://localhost:3000/verify-email", "noreply@logitrack.com", "smtp.gmail.com", ""
        );

        assertThat(serviceWithEmptyPassword.hasValidSmtpProperties()).isFalse();
        assertThatThrownBy(serviceWithEmptyPassword::validateSmtpConfiguration)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Configuración SMTP inválida");

        serviceWithEmptyPassword.sendVerificationEmail("test@logitrack.com", "token123");
        assertThat(serviceWithEmptyPassword.getFailureCount()).isEqualTo(1.0);
        verify(mailSender, never()).send(any(SimpleMailMessage.class));

        EmailService serviceWithBlankPassword = new EmailService(
                mailSender, registry, "http://localhost:3000/verify-email", "noreply@logitrack.com", "smtp.gmail.com", "   "
        );

        assertThat(serviceWithBlankPassword.hasValidSmtpProperties()).isFalse();
        assertThatThrownBy(serviceWithBlankPassword::validateSmtpConfiguration)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Configuración SMTP inválida");

        serviceWithBlankPassword.sendVerificationEmail("test@logitrack.com", "token123");
        assertThat(serviceWithBlankPassword.getFailureCount()).isEqualTo(2.0);
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("registerPublic rechaza la operación con IllegalStateException si no hay sincronización transaccional activa y no envía correo")
    void registerPublicRejectsWhenNoTransactionalSynchronizationActive() {
        var mockUsers = Mockito.mock(UserRepository.class);
        var mockTokens = Mockito.mock(VerificationTokenRepository.class);
        var mockEmail = Mockito.mock(EmailService.class);
        var mockEncoder = Mockito.mock(PasswordEncoder.class);

        User dummySavedUser = new User("no.sync@logitrack.com", "hash", Set.of(Role.CLIENTE));
        Mockito.when(mockUsers.save(any(User.class))).thenReturn(dummySavedUser);
        Mockito.when(mockTokens.save(any(VerificationToken.class))).thenAnswer(i -> i.getArgument(0));

        UserService standaloneService = new UserService(mockUsers, mockEncoder, mockTokens, mockEmail);

        var request = new RegisterRequest(
                "no.sync@logitrack.com",
                "PasswordSeguro123!",
                "nosync",
                "No Sync User",
                null,
                null,
                null,
                null
        );

        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();

        assertThatThrownBy(() -> standaloneService.registerPublic(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("sincronización transaccional activa");

        verify(mockEmail, never()).sendVerificationEmail(any(), any());
        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }
}
