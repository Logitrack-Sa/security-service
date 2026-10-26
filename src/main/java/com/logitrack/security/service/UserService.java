package com.logitrack.security.service;

import com.logitrack.security.dto.CreateUserRequest;
import com.logitrack.security.dto.RegisterRequest;
import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.entity.Role;
import com.logitrack.security.entity.User;
import com.logitrack.security.exception.DuplicateResourceException;
import com.logitrack.security.exception.PrivilegeEscalationException;
import com.logitrack.security.exception.ResourceNotFoundException;
import com.logitrack.security.repository.UserRepository;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Servicio de gestión de usuarios, registro público y vinculación confiable de identidades.
 *
 * <p>Aplica las reglas de negocio de seguridad:</p>
 * <ul>
 *   <li>El registro público solo permite crear usuarios con rol {@link Role#CLIENTE}.</li>
 *   <li>Rechaza intentos de elegir roles privilegiados (ADMIN, REPARTIDOR) o identidades ajenas.</li>
 *   <li>Garantiza contraseñas hasheadas mediante {@link PasswordEncoder} (BCrypt).</li>
 *   <li>Nunca expone hashes ni contraseñas en los objetos de retorno ni en logs.</li>
 *   <li>Administra la asociación única y confiable de {@code customerId} y {@code courierId}.</li>
 * </ul>
 */
@Service
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    /**
     * Construye el servicio con sus dependencias requeridas.
     *
     * @param users repositorio de usuarios.
     * @param passwordEncoder codificador seguro de contraseñas.
     */
    public UserService(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Registra un nuevo usuario a través del endpoint público.
     *
     * <p>Asigna exclusivamente el rol {@link Role#CLIENTE}. Rechaza cualquier intento de
     * solicitar roles privilegiados (ADMIN o REPARTIDOR) o de autoasignar identificadores
     * de dominio ({@code customerId} o {@code courierId}).</p>
     *
     * @param request datos de registro enviados por el solicitante.
     * @return respuesta con los datos del usuario creado sin información sensible.
     * @throws PrivilegeEscalationException si el payload incluye roles no permitidos o IDs de dominio.
     * @throws DuplicateResourceException si el email o nombre de usuario ya se encuentra registrado.
     */
    @Transactional
    public UserResponse registerPublic(RegisterRequest request) {
        validatePublicRegistration(request);

        String email = normalize(request.email());
        String username = normalize(request.username());

        if (users.existsByEmailIgnoreCase(email)) {
            throw new DuplicateResourceException("El correo electrónico '" + email + "' ya se encuentra registrado");
        }
        if (username != null && users.existsByUsernameIgnoreCase(username)) {
            throw new DuplicateResourceException("El nombre de usuario '" + username + "' ya se encuentra registrado");
        }

        String passwordHash = passwordEncoder.encode(request.password());
        User user = new User(email, username, request.name(), passwordHash, Set.of(Role.CLIENTE), null, null);
        User saved = users.save(user);

        return toResponse(saved);
    }

    /**
     * Da de alta un usuario con roles privilegiados e identidades de dominio preasignadas.
     *
     * <p>Operación reservada para administradores autenticados.</p>
     *
     * @param request datos completos para la creación del usuario.
     * @return respuesta con los datos del usuario creado.
     * @throws DuplicateResourceException si el email, username, customerId o courierId ya están en uso.
     */
    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        String email = normalize(request.email());
        String username = normalize(request.username());

        if (users.existsByEmailIgnoreCase(email)) {
            throw new DuplicateResourceException("El correo electrónico '" + email + "' ya se encuentra registrado");
        }
        if (username != null && users.existsByUsernameIgnoreCase(username)) {
            throw new DuplicateResourceException("El nombre de usuario '" + username + "' ya se encuentra registrado");
        }
        if (request.customerId() != null && users.existsByCustomerId(request.customerId())) {
            throw new DuplicateResourceException("El customerId '" + request.customerId() + "' ya se encuentra vinculado a otro usuario");
        }
        if (request.courierId() != null && users.existsByCourierId(request.courierId())) {
            throw new DuplicateResourceException("El courierId '" + request.courierId() + "' ya se encuentra vinculado a otro usuario");
        }

        String passwordHash = passwordEncoder.encode(request.password());
        User user = new User(email, username, request.name(), passwordHash, request.roles(), request.customerId(), request.courierId());
        User saved = users.save(user);

        return toResponse(saved);
    }

    /**
     * Busca un usuario por su identificador UUID.
     *
     * @param id identificador del usuario.
     * @return representación en DTO del usuario encontrado.
     * @throws ResourceNotFoundException si el usuario no existe.
     */
    public UserResponse findById(UUID id) {
        var user = users.findById(id).orElseThrow(ResourceNotFoundException::new);
        return toResponse(user);
    }

    /**
     * Obtiene el perfil de un usuario para el endpoint /me comprobando que la cuenta esté activa.
     *
     * @param id identificador del usuario.
     * @return representación del perfil del usuario autenticado.
     * @throws ResourceNotFoundException si el usuario no existe.
     * @throws BadCredentialsException si la cuenta del usuario se encuentra deshabilitada.
     */
    public UserResponse findProfileById(UUID id) {
        var user = users.findById(id).orElseThrow(ResourceNotFoundException::new);
        if (!user.isEnabled()) {
            throw new BadCredentialsException("Cuenta de usuario deshabilitada");
        }
        return toResponse(user);
    }

    /**
     * Actualiza el conjunto de roles de un usuario existente.
     *
     * <p>Operación reservada exclusivamente para administradores autenticados.
     * Prohíbe de forma estricta la auto-modificación arbitraria de roles propios.</p>
     *
     * @param userId identificador del usuario.
     * @param roles nuevo conjunto no vacío de roles.
     * @return representación actualizada del usuario.
     * @throws ResourceNotFoundException si el usuario no existe.
     * @throws PrivilegeEscalationException si el usuario intenta modificar sus propios roles.
     */
    @Transactional
    public UserResponse updateRoles(UUID userId, Set<Role> roles) {
        var user = users.findById(userId).orElseThrow(ResourceNotFoundException::new);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            String currentSubject = null;
            if (auth.getPrincipal() instanceof Jwt jwt) {
                currentSubject = jwt.getSubject();
            } else if (auth.getName() != null) {
                currentSubject = auth.getName();
            }
            if (currentSubject != null && (
                    currentSubject.equalsIgnoreCase(user.getId().toString())
                    || currentSubject.equalsIgnoreCase(user.getEmail())
                    || (user.getUsername() != null && currentSubject.equalsIgnoreCase(user.getUsername())))) {
                throw new PrivilegeEscalationException("No está permitida la auto-modificación arbitraria de roles propios");
            }
        }

        user.updateRoles(roles);
        User saved = users.saveAndFlush(user);
        return toResponse(saved);
    }

    /**
     * Vincula de forma confiable un {@code customerId} a un usuario.
     *
     * <p>Verifica que el {@code customerId} no se encuentre asociado previamente a otra cuenta.
     * Operación reservada para administradores autenticados.</p>
     *
     * @param userId identificador del usuario a vincular.
     * @param customerId UUID de cliente en shipment-service.
     * @return representación actualizada del usuario.
     * @throws ResourceNotFoundException si el usuario no existe.
     * @throws DuplicateResourceException si el customerId ya pertenece a otro usuario.
     */
    @Transactional
    public UserResponse linkCustomer(UUID userId, UUID customerId) {
        var user = users.findById(userId).orElseThrow(ResourceNotFoundException::new);

        if (customerId != null) {
            users.findByCustomerId(customerId)
                    .filter(other -> !other.getId().equals(userId))
                    .ifPresent(other -> {
                        throw new DuplicateResourceException("El customerId '" + customerId + "' ya se encuentra vinculado a otro usuario");
                    });
        }

        user.linkCustomer(customerId);
        User saved = users.saveAndFlush(user);
        return toResponse(saved);
    }

    /**
     * Vincula de forma confiable un {@code courierId} a un usuario.
     *
     * <p>Verifica que el {@code courierId} no se encuentre asociado previamente a otra cuenta.
     * Operación reservada para administradores autenticados.</p>
     *
     * @param userId identificador del usuario a vincular.
     * @param courierId UUID de repartidor en courier-service.
     * @return representación actualizada del usuario.
     * @throws ResourceNotFoundException si el usuario no existe.
     * @throws DuplicateResourceException si el courierId ya pertenece a otro usuario.
     */
    @Transactional
    public UserResponse linkCourier(UUID userId, UUID courierId) {
        var user = users.findById(userId).orElseThrow(ResourceNotFoundException::new);

        if (courierId != null) {
            users.findByCourierId(courierId)
                    .filter(other -> !other.getId().equals(userId))
                    .ifPresent(other -> {
                        throw new DuplicateResourceException("El courierId '" + courierId + "' ya se encuentra vinculado a otro usuario");
                    });
        }

        user.linkCourier(courierId);
        User saved = users.saveAndFlush(user);
        return toResponse(saved);
    }

    private void validatePublicRegistration(RegisterRequest request) {
        if (request.role() != null && !request.role().trim().equalsIgnoreCase("CLIENTE")) {
            throw new PrivilegeEscalationException("No está permitido solicitar roles privilegiados ('" + request.role() + "') en el registro público");
        }
        if (request.roles() != null && !request.roles().isEmpty()) {
            boolean hasNonClientRole = request.roles().stream().anyMatch(r -> r != Role.CLIENTE);
            if (hasNonClientRole) {
                throw new PrivilegeEscalationException("El registro público solo admite el rol CLIENTE; se rechazaron roles privilegiados en el payload");
            }
        }
        if (request.customerId() != null) {
            throw new PrivilegeEscalationException("No está permitido asignar o elegir customerId en el payload del registro público");
        }
        if (request.courierId() != null) {
            throw new PrivilegeEscalationException("No está permitido asignar o elegir courierId en el payload del registro público");
        }
    }

    private String normalize(String value) {
        return (value != null && !value.isBlank()) ? value.strip().toLowerCase(Locale.ROOT) : null;
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getName(),
                user.getRoles(),
                user.isEnabled(),
                user.getCustomerId(),
                user.getCourierId()
        );
    }
}
