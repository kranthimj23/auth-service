package com.mobilebanking.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.availability.ApplicationAvailability;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Health", description = "Health check endpoints")
public class HealthController {

    private final ApplicationAvailability applicationAvailability;
    private final DataSource dataSource;

    @GetMapping("/health")
    @Operation(summary = "Liveness probe", description = "Check if the application is alive")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "auth-service");
        health.put("liveness", applicationAvailability.getLivenessState() == LivenessState.CORRECT ? "UP" : "DOWN");
        return ResponseEntity.ok(health);
    }

    @GetMapping("/ready")
    @Operation(summary = "Readiness probe", description = "Check if the application is ready to receive traffic")
    public ResponseEntity<Map<String, Object>> ready() {
        Map<String, Object> readiness = new HashMap<>();
        readiness.put("service", "auth-service");
        
        boolean dbHealthy = checkDatabaseConnection();
        readiness.put("database", dbHealthy ? "UP" : "DOWN");
        readiness.put("readiness", applicationAvailability.getReadinessState() == ReadinessState.ACCEPTING_TRAFFIC ? "UP" : "DOWN");
        
        boolean isReady = dbHealthy && applicationAvailability.getReadinessState() == ReadinessState.ACCEPTING_TRAFFIC;
        readiness.put("status", isReady ? "UP" : "DOWN");
        
        if (isReady) {
            return ResponseEntity.ok(readiness);
        } else {
            return ResponseEntity.status(503).body(readiness);
        }
    }

    private boolean checkDatabaseConnection() {
        try (Connection connection = dataSource.getConnection()) {
            return connection.isValid(5);
        } catch (Exception e) {
            return false;
        }
    }
}
