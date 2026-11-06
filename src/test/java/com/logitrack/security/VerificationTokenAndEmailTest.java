package com.logitrack.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.dto.LoginRequest;
import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.entity.VerificationToken;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.repository.UserRepository;
import com.logitrack.security.repository.VerificationTokenRepository;
import com.logitrack.security.service.EmailService;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class VerificationTokenAndEmailTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JavaMailSender mailSender;

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
        verify(mailSender).send(captor.capture());
        SimpleMailMessage sentMessage = captor.getValue();
        assertThat(sentMessage.getTo()).containsExactly("nuevo.correo@logitrack.com");
        assertThat(sentMessage.getSubject()).contains("Verifica tu cuenta");
        assertThat(sentMessage.getText()).contains(token.getToken());
        assertThat(sentMessage.getText()).contains("http://localhost:3000/verify-email?token=");
    }

    @Test
    @DisplayName("EmailService es resiliente ante fallo de red SMTP y no propaga excepción")
    void emailServiceHandlesSmtpExceptionGracefully() {
        doThrow(new MailSendException("Conexión rechazada a smtp.gmail.com"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        EmailService service = new EmailService(mailSender, "http://localhost:3000/verify-email", "noreply@logitrack.com");
        // No debe lanzar excepción
        service.sendVerificationEmail("fallo@logitrack.com", "dummy-token-uuid");

        verify(mailSender).send(any(SimpleMailMessage.class));
    }
}
