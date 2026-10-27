package com.logitrack.security.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Entidad de persistencia de usuario y seguridad.
 *
 * <p>Representa las credenciales autenticables y los roles autorizados de un usuario en el sistema.
 * Mantiene la separación de identidades: el identificador del usuario ({@code id}) no equivale a
 * los identificadores de dominio ({@code customerId} o {@code courierId}), los cuales se almacenan
 * como vínculos confiables únicos administrados exclusivamente por ADMIN.</p>
 */
@Getter
@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Email
    @NotBlank
    @Size(max = 254)
    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Size(max = 100)
    @Column(unique = true, length = 100)
    private String username;

    @Size(max = 200)
    @Column(length = 200)
    private String name;

    @JsonIgnore
    @NotBlank
    @Size(max = 100)
    @Pattern(regexp = "\\$2[aby]\\$\\d{2}\\$[./A-Za-z0-9]{53}")
    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @NotEmpty
    @ElementCollection
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role", nullable = false, length = 20)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "customer_id", unique = true)
    private UUID customerId;

    @Column(name = "courier_id", unique = true)
    private UUID courierId;

    @Version
    private Long version;

    /**
     * Constructor base para creación de usuarios con email, contraseña hasheada y roles.
     *
     * @param email dirección de correo electrónico única.
     * @param passwordHash hash BCrypt de la contraseña.
     * @param roles conjunto de roles autorizados.
     */
    public User(String email, String passwordHash, Set<Role> roles) {
        this(email, null, null, passwordHash, roles, null, null);
    }

    /**
     * Constructor completo para creación de usuarios con datos de perfil y vínculos de dominio opcionales.
     *
     * @param email dirección de correo electrónico única.
     * @param username nombre de usuario opcional (normalizado a minúsculas).
     * @param name nombre descriptivo opcional.
     * @param passwordHash hash BCrypt de la contraseña.
     * @param roles conjunto de roles autorizados.
     * @param customerId identificador único de cliente vinculado opcional.
     * @param courierId identificador único de repartidor vinculado opcional.
     */
    public User(String email, String username, String name, String passwordHash, Set<Role> roles, UUID customerId, UUID courierId) {
        this.email = email != null ? email.strip().toLowerCase(Locale.ROOT) : null;
        this.username = (username != null && !username.isBlank()) ? username.strip().toLowerCase(Locale.ROOT) : null;
        this.name = (name != null && !name.isBlank()) ? name.strip() : null;
        this.passwordHash = passwordHash;
        if (roles != null) {
            this.roles.addAll(Set.copyOf(roles));
        }
        this.customerId = customerId;
        this.courierId = courierId;
    }

    /**
     * Retorna una copia inmutable del conjunto de roles del usuario.
     *
     * @return roles asignados.
     */
    public Set<Role> getRoles() {
        return Set.copyOf(roles);
    }

    /**
     * Actualiza el conjunto de roles del usuario.
     *
     * @param newRoles nuevo conjunto no vacío de roles.
     */
    public void updateRoles(Set<Role> newRoles) {
        Objects.requireNonNull(newRoles, "El conjunto de roles no puede ser nulo");
        if (newRoles.isEmpty()) {
            throw new IllegalArgumentException("El usuario debe tener al menos un rol");
        }
        this.roles.clear();
        this.roles.addAll(Set.copyOf(newRoles));
    }

    /**
     * Establece o actualiza el vínculo confiable con el identificador de cliente.
     *
     * @param customerId UUID del cliente o {@code null} para desvincular.
     */
    public void linkCustomer(UUID customerId) {
        this.customerId = customerId;
    }

    /**
     * Establece o actualiza el vínculo confiable con el identificador de repartidor.
     *
     * @param courierId UUID del repartidor o {@code null} para desvincular.
     */
    public void linkCourier(UUID courierId) {
        this.courierId = courierId;
    }

    /**
     * Modifica el estado de habilitación del usuario.
     *
     * @param enabled {@code true} si el usuario está activo, {@code false} de lo contrario.
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Actualiza el nombre de usuario.
     *
     * @param username nuevo nombre de usuario opcional.
     */
    public void setUsername(String username) {
        this.username = (username != null && !username.isBlank()) ? username.strip().toLowerCase(Locale.ROOT) : null;
    }

    /**
     * Actualiza el nombre personal del usuario.
     *
     * @param name nuevo nombre opcional.
     */
    public void setName(String name) {
        this.name = (name != null && !name.isBlank()) ? name.strip() : null;
    }
}
