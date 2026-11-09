package com.logitrack.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.security.dto.UserResponse;
import java.time.Duration;
import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

/** Configura perfiles JSON sin entidades JPA ni secretos y escrituras posteriores al commit. */
@Configuration
@EnableCaching
public class ProfileCacheConfiguration {
    @Bean
    RedisCacheManagerBuilderCustomizer profileCacheCustomizer(ObjectMapper mapper) {
        var serializer = new Jackson2JsonRedisSerializer<>(mapper, UserResponse.class);
        var config = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(15))
                .disableCachingNullValues()
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(serializer));
        return builder -> builder.withCacheConfiguration("user_profiles", config).transactionAware().enableStatistics();
    }
}
