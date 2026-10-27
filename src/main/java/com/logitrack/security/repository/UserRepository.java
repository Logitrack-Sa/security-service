package com.logitrack.security.repository;

import com.logitrack.security.entity.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repositorio Spring Data JPA para la entidad {@link User}.
 *
 * <p>Permite consultas seguras por identificadores de autenticación (email, username)
 * y por identificadores de dominio vinculados (customerId, courierId) garantizando unicidad.</p>
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Busca un usuario por su email normalizado.
     *
     * @param email dirección de correo electrónico.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByEmail(String email);

    /**
     * Comprueba si ya existe un usuario con el email dado.
     *
     * @param email dirección de correo electrónico.
     * @return {@code true} si existe, {@code false} de lo contrario.
     */
    boolean existsByEmail(String email);

    /**
     * Busca un usuario por su email ignorando mayúsculas/minúsculas.
     *
     * @param email dirección de correo electrónico.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByEmailIgnoreCase(String email);

    /**
     * Comprueba si ya existe un usuario con el email ignorando mayúsculas/minúsculas.
     *
     * @param email dirección de correo electrónico.
     * @return {@code true} si existe, {@code false} de lo contrario.
     */
    boolean existsByEmailIgnoreCase(String email);

    /**
     * Busca un usuario por su nombre de usuario normalizado.
     *
     * @param username nombre de usuario.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByUsername(String username);

    /**
     * Comprueba si ya existe un usuario con el nombre de usuario dado.
     *
     * @param username nombre de usuario.
     * @return {@code true} si existe, {@code false} de lo contrario.
     */
    boolean existsByUsername(String username);

    /**
     * Busca un usuario por su nombre de usuario ignorando mayúsculas/minúsculas.
     *
     * @param username nombre de usuario.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByUsernameIgnoreCase(String username);

    /**
     * Comprueba si ya existe un usuario con el nombre de usuario ignorando mayúsculas/minúsculas.
     *
     * @param username nombre de usuario.
     * @return {@code true} si existe, {@code false} de lo contrario.
     */
    boolean existsByUsernameIgnoreCase(String username);

    /**
     * Busca un usuario por email o nombre de usuario (para resolución flexible de credenciales).
     *
     * @param email email a comparar.
     * @param username username a comparar.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByEmailIgnoreCaseOrUsernameIgnoreCase(String email, String username);

    /**
     * Busca un usuario vinculado a un identificador de cliente.
     *
     * @param customerId UUID del cliente en shipment-service.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByCustomerId(UUID customerId);

    /**
     * Comprueba si un {@code customerId} ya se encuentra vinculado a algún usuario.
     *
     * @param customerId UUID del cliente en shipment-service.
     * @return {@code true} si ya está vinculado, {@code false} de lo contrario.
     */
    boolean existsByCustomerId(UUID customerId);

    /**
     * Busca un usuario vinculado a un identificador de repartidor.
     *
     * @param courierId UUID del repartidor en courier-service.
     * @return un {@link Optional} con el usuario encontrado o vacío.
     */
    Optional<User> findByCourierId(UUID courierId);

    /**
     * Comprueba si un {@code courierId} ya se encuentra vinculado a algún usuario.
     *
     * @param courierId UUID del repartidor en courier-service.
     * @return {@code true} si ya está vinculado, {@code false} de lo contrario.
     */
    boolean existsByCourierId(UUID courierId);
}
