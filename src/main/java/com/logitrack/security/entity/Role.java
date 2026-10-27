package com.logitrack.security.entity;

/**
 * Roles autorizados en el sistema de seguridad de LogiTrack según el contrato del Sprint 2.
 *
 * <ul>
 *   <li>{@link #ADMIN}: Administrador con privilegios totales de gestión de usuarios, roles y vinculaciones.</li>
 *   <li>{@link #CLIENTE}: Usuario final estándar con capacidad de gestionar y crear envíos propios.</li>
 *   <li>{@link #REPARTIDOR}: Personal de entrega asignado a envíos y actualización de su estado en ruta.</li>
 * </ul>
 */
public enum Role {
    /**
     * Rol administrativo de plataforma.
     */
    ADMIN,

    /**
     * Rol para clientes de la plataforma.
     */
    CLIENTE,

    /**
     * Rol para repartidores de logística.
     */
    REPARTIDOR
}
