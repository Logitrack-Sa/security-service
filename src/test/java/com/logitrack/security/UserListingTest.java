package com.logitrack.security;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class UserListingTest {
 @Autowired MockMvc http;
 @Test void anonymousCannotList() throws Exception {http.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());}
 @Test @WithMockUser(roles="CLIENTE") void clientCannotList() throws Exception {http.perform(get("/api/v1/users")).andExpect(status().isForbidden());}
 @Test @WithMockUser(roles="ADMIN") void adminGetsBoundedPage() throws Exception {http.perform(get("/api/v1/users?size=5")).andExpect(status().isOk()).andExpect(jsonPath("$.size").value(5)).andExpect(jsonPath("$.content").isArray()).andExpect(jsonPath("$.content[*].passwordHash").doesNotExist());}
 @Test @WithMockUser(roles="ADMIN") void rejectsInvalidPagination() throws Exception {http.perform(get("/api/v1/users?size=101")).andExpect(status().isBadRequest());http.perform(get("/api/v1/users?page=-1")).andExpect(status().isBadRequest());}
}
