# Auth Service

Authentication microservice for the Mobile Banking Platform. Handles user authentication, JWT token generation, OAuth2 integration, and refresh token management.

## Technology Stack

- Java 17
- Spring Boot 3.2.0
- Spring Security
- Spring Data JPA
- PostgreSQL
- JWT (JJWT 0.12.3)
- Flyway for database migrations

## Features

- User registration and login
- JWT access token generation
- Refresh token rotation
- OAuth2 provider integration (Google, GitHub)
- Password hashing with BCrypt
- Token validation and revocation

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/v1/auth/register | Register a new user |
| POST | /api/v1/auth/login | Authenticate user and get tokens |
| POST | /api/v1/auth/logout | Logout and revoke tokens |
| POST | /api/v1/auth/refresh | Refresh access token |
| GET | /api/v1/auth/validate | Validate JWT token |
| GET | /actuator/health | Health check endpoint |
| GET | /actuator/prometheus | Prometheus metrics |

## Project Structure

```
auth-service/
├── src/
│   └── main/
│       ├── java/com/mobilebanking/auth/
│       │   ├── config/          # Security and OpenAPI configuration
│       │   ├── controller/      # REST controllers
│       │   ├── dto/             # Data transfer objects
│       │   ├── entity/          # JPA entities
│       │   ├── exception/       # Exception handling
│       │   ├── repository/      # JPA repositories
│       │   ├── security/        # JWT and security components
│       │   └── service/         # Business logic
│       └── resources/
│           ├── application.yml
│           ├── application-dev.yml
│           ├── application-prod.yml
│           └── db/migration/    # Flyway migrations
├── helm/                        # Helm chart for Kubernetes deployment
├── Dockerfile                   # Multi-stage Docker build
├── Jenkinsfile                  # CI/CD pipeline
└── pom.xml                      # Maven dependencies
```

## Local Development

### Prerequisites

- Java 17+
- Maven 3.8+
- PostgreSQL 14+
- Docker (optional)

### Running Locally

1. Start PostgreSQL:
```bash
docker run -d --name postgres-auth \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_password \
  -p 5432:5432 postgres:14
```

2. Run the application:
```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

3. Access Swagger UI: http://localhost:8081/swagger-ui.html

### Building Docker Image

```bash
docker build -t auth-service:latest .
```

## Kubernetes Deployment

### Using Helm

```bash
# Development
helm install auth-service ./helm -f ./helm/values-dev.yaml -n mobile-banking-dev

# Staging
helm install auth-service ./helm -f ./helm/values-staging.yaml -n mobile-banking-staging

# Production
helm install auth-service ./helm -f ./helm/values-prod.yaml -n mobile-banking-prod
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SPRING_DATASOURCE_URL | PostgreSQL connection URL | jdbc:postgresql://localhost:5432/auth_db |
| SPRING_DATASOURCE_USERNAME | Database username | auth_user |
| SPRING_DATASOURCE_PASSWORD | Database password | - |
| JWT_SECRET | Secret key for JWT signing | - |
| JWT_EXPIRATION | Access token expiration (ms) | 900000 (15 min) |
| JWT_REFRESH_EXPIRATION | Refresh token expiration (ms) | 604800000 (7 days) |

## Security

- Passwords are hashed using BCrypt with strength 12
- JWT tokens are signed using HS512 algorithm
- Refresh tokens are rotated on each use
- All endpoints require HTTPS in production
- Rate limiting is enforced at the API Gateway level

## Testing

```bash
# Run unit tests
./mvnw test

# Run integration tests
./mvnw verify -P integration-tests
```

## CI/CD Pipeline

The Jenkinsfile includes the following stages:
1. Build - Compile and package
2. Unit Tests - Run unit tests
3. Integration Tests - Run integration tests
4. Code Quality - SonarQube analysis
5. Docker Build - Build container image
6. Docker Push - Push to registry
7. Helm Lint - Validate Helm chart
8. Deploy - Deploy to Kubernetes
9. Smoke Tests - Verify deployment

## Related Services

- [User Service](https://github.com/kranthimj23/user-service) - User profile management
- [API Gateway](https://github.com/kranthimj23/api-gateway) - Request routing and rate limiting
- [Infrastructure](https://github.com/kranthimj23/mobile-banking-infra) - Terraform and observability
