package com.logitrack.security;

import com.logitrack.security.bootstrap.AdminBootstrap;
import com.logitrack.security.config.AdminProperties;
import com.logitrack.security.config.JwtProperties;
import com.logitrack.security.jwt.RsaKeyProvider;
import com.logitrack.security.repository.UserRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class StartupSafetyTest {
    @TempDir Path directory;

    @ParameterizedTest @NullAndEmptySource @ValueSource(strings = "admin123")
    void rejectsUnsafeBootstrapBeforeWriting(String password) {
        var users = mock(UserRepository.class);
        var bootstrap = new AdminBootstrap(users, new BCryptPasswordEncoder(), new AdminProperties(true,"admin","admin@example.test",password));
        assertThatThrownBy(() -> bootstrap.run(new DefaultApplicationArguments())).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(users);
    }

    @Test void missingConfiguredKeyDoesNotBecomeAnEphemeralKey() {
        assertThatThrownBy(() -> provider(directory.resolve("missing.pem").toUri().toString(), null, "prod").init())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test void malformedConfiguredKeyFails() throws Exception {
        Path path = directory.resolve("bad.pem"); Files.writeString(path,"invalid-key");
        assertThatThrownBy(() -> provider(path.toUri().toString(), null,"prod").init()).isInstanceOf(IllegalStateException.class);
    }

    @Test void mismatchedPublicKeyFails() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        Path privateKey = directory.resolve("private.pem"), publicKey = directory.resolve("public.pem");
        Files.writeString(privateKey,"-----BEGIN PRIVATE KEY-----\n"+Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded())+"\n-----END PRIVATE KEY-----");
        Files.writeString(publicKey,RsaKeyProvider.encodePublicKeyToPem((java.security.interfaces.RSAPublicKey)generator.generateKeyPair().getPublic()));
        assertThatThrownBy(() -> provider(privateKey.toUri().toString(),publicKey.toUri().toString(),"prod").init())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test void ephemeralKeysAreRestrictedToTest() {
        assertThatThrownBy(() -> provider(null,null,"prod").init()).isInstanceOf(IllegalStateException.class);
        var fixture = provider(null,null,"test"); fixture.init();
        assertThat(fixture.getPublicKey().getModulus().bitLength()).isGreaterThanOrEqualTo(2048);
    }

    private RsaKeyProvider provider(String privateKey, String publicKey, String profile) {
        var env = new MockEnvironment(); env.setActiveProfiles(profile);
        return new RsaKeyProvider(new JwtProperties(privateKey,publicKey,"fixture","https://issuer.test",List.of("security-service"),600,null),
                new DefaultResourceLoader(),env);
    }
}
