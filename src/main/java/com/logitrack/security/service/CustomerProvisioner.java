package com.logitrack.security.service;

import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.exception.CustomerProvisioningException;
import com.logitrack.security.jwt.JwtTokenService;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class CustomerProvisioner {
    private final RestClient shipment;
    private final JwtTokenService tokens;
    private final boolean enabled;

    public CustomerProvisioner(@Qualifier("customerRestClientBuilder") RestClient.Builder builder,
            JwtTokenService tokens,
            @Value("${logitrack.customer-provisioning.url:http://shipment-service}") String url,
            @Value("${logitrack.customer-provisioning.enabled:true}") boolean enabled) {
        this.shipment = builder.baseUrl(url).build();
        this.tokens = tokens;
        this.enabled = enabled;
    }

    public boolean required(User user) {
        return enabled && user.isEmailVerified() && user.getRoles().contains(Role.CLIENTE)
                && user.getCustomerId() == null;
    }

    @CacheEvict(value = "user_profiles", key = "'user::username::' + #user.id")
    public void ensureLinked(User user) {
        if (!required(user)) return;
        try {
            var customer = shipment.post().uri("/api/v1/customers/provision")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.generateCustomerProvisioningToken(user))
                    .retrieve().body(CustomerIdentity.class);
            if (customer == null || customer.id() == null) throw new CustomerProvisioningException();
            user.linkCustomer(customer.id());
        } catch (RuntimeException failure) {
            // No publicar tokens, respuestas externas ni datos personales en el error.
            throw new CustomerProvisioningException();
        }
    }

    @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
    public record CustomerIdentity(UUID id) {}
}
