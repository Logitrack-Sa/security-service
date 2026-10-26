# --- Etapa 1: Build multietapa con Java 25 ---
FROM maven:3-eclipse-temurin-25 AS builder
WORKDIR /app

# Copiar descriptores del proyecto y código fuente
COPY pom.xml ./
COPY src/ src/

# Compilar y empaquetar artefacto ejecutable omitiendo pruebas en el empaquetado de imagen
RUN mvn clean package -DskipTests -B

# --- Etapa 2: Runtime mínimo con Java 25 y usuario sin privilegios ---
FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app

LABEL org.opencontainers.image.title="security-service" \
      org.opencontainers.image.description="Servicio de autenticación, gestión de identidades y emisión de JWT para LogiTrack" \
      org.opencontainers.image.vendor="Logitrack-Sa"

# Crear usuario y grupo de sistema sin privilegios
RUN groupadd -r spring && useradd -r -g spring -s /sbin/nologin spring

# Directorios dedicados a montaje de secretos y configuraciones externas
RUN mkdir -p /secrets /config && chown -R spring:spring /app /secrets /config

# Copiar exclusivamente el artefacto final desde el constructor
COPY --from=builder --chown=spring:spring /app/target/security-service-*.jar app.jar

# Variables de entorno y puerto parametrizable (por defecto 8083)
ENV SERVER_PORT=8083 \
    SPRING_PROFILES_ACTIVE=prod \
    JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

USER spring:spring

EXPOSE 8083

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
