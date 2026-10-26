package com.logitrack.security.controller;

import com.logitrack.security.dto.CourierLinkRequest;
import com.logitrack.security.dto.CreateUserRequest;
import com.logitrack.security.dto.CustomerLinkRequest;
import com.logitrack.security.dto.UpdateRolesRequest;
import com.logitrack.security.dto.UserResponse;
import com.logitrack.security.service.UserService;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Controlador REST para la administración de usuarios, roles y vínculos de identidad.
 *
 * <p>Todas las rutas bajo este controlador están reservadas exclusivamente para usuarios autenticados
 * con rol {@code ADMIN}. Permite el alta de usuarios privilegiados (ADMIN, REPARTIDOR), la actualización
 * de roles y la asignación confiable de identificadores de dominio ({@code customerId} y {@code courierId}).</p>
 */
@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;

    /**
     * Construye el controlador inyectando el servicio de usuarios.
     *
     * @param userService servicio de gestión de usuarios.
     */
    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Obtiene el perfil de un usuario por su identificador UUID.
     *
     * @param id identificador único del usuario.
     * @return respuesta HTTP 200 OK con los datos del usuario sin contraseñas ni hashes.
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> findById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.findById(id));
    }

    /**
     * Crea un usuario administrativamente con roles privilegiados e identidades de dominio preasignadas.
     *
     * @param request datos completos para la creación del usuario.
     * @return respuesta HTTP 201 Created con los datos del usuario creado.
     */
    @PostMapping
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody CreateUserRequest request) {
        UserResponse response = userService.createUser(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(response.id())
                .toUri();
        return ResponseEntity.created(location).body(response);
    }

    /**
     * Actualiza el conjunto de roles asignados a un usuario existente.
     *
     * @param id identificador único del usuario.
     * @param request nuevo conjunto no vacío de roles.
     * @return respuesta HTTP 200 OK con los datos actualizados del usuario.
     */
    @RequestMapping(value = "/{id}/roles", method = {RequestMethod.PUT, RequestMethod.PATCH})
    public ResponseEntity<UserResponse> updateRoles(@PathVariable UUID id,
                                                    @Valid @RequestBody UpdateRolesRequest request) {
        return ResponseEntity.ok(userService.updateRoles(id, request.roles()));
    }

    /**
     * Asocia o actualiza de forma confiable un {@code customerId} a un usuario.
     *
     * @param id identificador único del usuario.
     * @param request identificador de cliente a vincular.
     * @return respuesta HTTP 200 OK con los datos actualizados del usuario.
     */
    @RequestMapping(value = "/{id}/customer-link", method = {RequestMethod.PUT, RequestMethod.PATCH})
    public ResponseEntity<UserResponse> linkCustomer(@PathVariable UUID id,
                                                     @Valid @RequestBody CustomerLinkRequest request) {
        return ResponseEntity.ok(userService.linkCustomer(id, request.customerId()));
    }

    /**
     * Asocia o actualiza de forma confiable un {@code courierId} a un usuario.
     *
     * @param id identificador único del usuario.
     * @param request identificador de repartidor a vincular.
     * @return respuesta HTTP 200 OK con los datos actualizados del usuario.
     */
    @RequestMapping(value = "/{id}/courier-link", method = {RequestMethod.PUT, RequestMethod.PATCH})
    public ResponseEntity<UserResponse> linkCourier(@PathVariable UUID id,
                                                    @Valid @RequestBody CourierLinkRequest request) {
        return ResponseEntity.ok(userService.linkCourier(id, request.courierId()));
    }
}
