package com.logitrack.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"logitrack.metrics.anonymous-enabled=true", "management.endpoints.web.exposure.include=health,prometheus"})
@AutoConfigureMockMvc
@AutoConfigureObservability
@ActiveProfiles("test")
class MetricsAccessIntegrationTest {
    @Autowired MockMvc http;

    @Test void exposesMetricsWithoutOpeningBusinessOrConfiguration() throws Exception {
        http.perform(get("/actuator/prometheus")).andExpect(status().isOk());
        http.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());
        http.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
    }
}
