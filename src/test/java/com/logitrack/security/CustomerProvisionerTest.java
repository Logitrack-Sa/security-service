package com.logitrack.security;

import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.exception.CustomerProvisioningException;
import com.logitrack.security.jwt.JwtTokenService;
import com.logitrack.security.service.CustomerProvisioner;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class CustomerProvisionerTest {
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final JwtTokenService tokens = mock(JwtTokenService.class);
    private final CustomerProvisioner service = new CustomerProvisioner(builder, tokens, "http://shipment", true);

    private User client() {
        var u = new User("ana@example.test", "ana", "Ana", "hash", Set.of(Role.CLIENTE), null, null);
        u.setEmailVerified(true);
        return u;
    }

    @Test void linksVerifiedIdentityAndSkipsSubsequentRequests() {
        var user = client(); var id = UUID.randomUUID();
        when(tokens.generateCustomerProvisioningToken(user)).thenReturn("signed-server-token");
        server.expect(requestTo("http://shipment/api/v1/customers/provision"))
                .andExpect(method(HttpMethod.POST)).andExpect(header("Authorization", "Bearer signed-server-token"))
                .andRespond(withSuccess("{\"id\":\"" + id + "\",\"name\":\"Ana\"}", MediaType.APPLICATION_JSON));
        service.ensureLinked(user);
        assertThat(user.getCustomerId()).isEqualTo(id);
        service.ensureLinked(user);
        server.verify();
    }

    @Test void failureDoesNotLinkAnInventedCustomerAndCanBeRetried() {
        var user = client();
        when(tokens.generateCustomerProvisioningToken(user)).thenReturn("private-token");
        server.expect(requestTo("http://shipment/api/v1/customers/provision")).andRespond(withServerError());
        assertThatThrownBy(() -> service.ensureLinked(user)).isInstanceOf(CustomerProvisioningException.class)
                .hasMessageNotContaining("private-token");
        assertThat(user.getCustomerId()).isNull();
        assertThat(service.required(user)).isTrue();
        server.verify();
    }

    @Test void unverifiedOrPrivilegedAccountsNeverCreateCustomerProfiles() {
        var unverified = client(); unverified.setEmailVerified(false);
        assertThat(service.required(unverified)).isFalse();
        var admin = new User("admin@example.test", "hash", Set.of(Role.ADMIN));
        admin.setEmailVerified(true);
        assertThat(service.required(admin)).isFalse();
        var courier = new User("courier@example.test", "hash", Set.of(Role.REPARTIDOR));
        courier.setEmailVerified(true);
        assertThat(service.required(courier)).isFalse();
        service.ensureLinked(unverified); service.ensureLinked(admin); service.ensureLinked(courier);
        verifyNoInteractions(tokens); server.verify();
    }
}
