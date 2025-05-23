export interface Architecture {
  id: string;
  name: string;
  description: string;
  content: string;
}

export const architectures: Architecture[] = [
  {
    id: "overview",
    name: "Overview",
    description: "Comprehensive overview of authentication architectures for .NET web applications",
    content: `# Scalable Authentication Architectures for .NET Web Applications

## Introduction

This comprehensive guide explores various architectural approaches for implementing scalable authentication in .NET web applications with support for multiple authentication platforms. The document addresses the specific requirements of supporting Google Suite, Google, Facebook, Apple, Azure AD, and Microsoft authentication while ensuring the application can scale effectively.

Authentication is a critical component of any web application, and its architecture significantly impacts the application's scalability, security, and maintainability. This guide presents five distinct architectural approaches, each with its own strengths, weaknesses, and ideal use cases.

## Requirements Overview

A scalable authentication system for .NET web applications should meet the following requirements:

1. **Multi-Provider Support**: Integration with Google Suite, Google, Facebook, Apple, Azure AD, and Microsoft authentication.
2. **Scalability**: Ability to handle growing user bases and authentication requests.
3. **.NET Compatibility**: Seamless integration with .NET web application frameworks.
4. **Security**: Implementation of best practices for secure authentication.

## Authentication Architectures

### 1. Centralized Authentication Architecture

The centralized authentication architecture consolidates all authentication logic into a single component within the application. This approach provides a single source of truth for authentication and authorization decisions.

### 2. Distributed Authentication Architecture

The distributed authentication architecture separates authentication concerns into dedicated services that can be independently scaled and deployed. This approach is ideal for large-scale applications with high traffic volumes.

### 3. Microservices-Based Authentication Architecture

The microservices-based authentication architecture implements authentication as a set of specialized, loosely coupled microservices that work together to provide comprehensive identity management.

### 4. Serverless Authentication Architecture

The serverless authentication architecture leverages cloud-based serverless computing services to handle authentication workflows without managing the underlying infrastructure.

### 5. Hybrid Authentication Architecture

The hybrid authentication architecture combines elements from multiple approaches to create a flexible solution that addresses diverse requirements.

## Implementation Considerations

### Provider Integration

All architectures support integration with the required authentication providers:

| Provider | Protocol | Integration Method |
|----------|----------|-------------------|
| Google Suite | OpenID Connect | \`.AddOpenIdConnect("GoogleWorkspace")\` |
| Google | OAuth 2.0 | \`.AddGoogle()\` |
| Facebook | OAuth 2.0 | \`.AddFacebook()\` |
| Apple | OAuth 2.0 | \`.AddApple()\` |
| Azure AD | OpenID Connect | \`.AddOpenIdConnect("AzureAD")\` |
| Microsoft | OAuth 2.0 | \`.AddMicrosoftAccount()\` |

### Security Best Practices

Regardless of the chosen architecture, implement these security best practices:

1. **Use HTTPS**: Secure all authentication endpoints with HTTPS
2. **Implement Rate Limiting**: Prevent brute force attacks
3. **Use Secure Password Hashing**: Implement modern algorithms (Argon2id, PBKDF2)
4. **Short-Lived Tokens**: Issue tokens with limited lifetimes
5. **Implement MFA**: Support multi-factor authentication
6. **Comprehensive Logging**: Log all authentication events
7. **Regular Security Audits**: Review authentication implementation regularly

### Scalability Best Practices

To ensure optimal scalability:

1. **Stateless Authentication**: Use token-based authentication
2. **Distributed Caching**: Implement Redis or similar for shared state
3. **Database Optimization**: Index user lookup fields
4. **Asynchronous Operations**: Offload intensive tasks
5. **Load Testing**: Regularly test authentication performance
6. **Monitoring**: Implement comprehensive monitoring of authentication services

## Recommendations by Scenario

### For Startups and Small Applications
**Recommended Architecture**: Centralized or Serverless
- Simpler implementation and management
- Lower initial development and operational costs
- Adequate scalability for early growth stages

### For Medium-Sized Applications
**Recommended Architecture**: Distributed or Hybrid
- Better scalability than centralized approach
- More flexibility for growth
- Reasonable complexity for mid-sized teams

### For Enterprise Applications
**Recommended Architecture**: Microservices-based or Hybrid
- Maximum scalability and resilience
- Support for complex authentication scenarios
- Better alignment with enterprise architecture patterns

### For Applications Transitioning from Legacy Systems
**Recommended Architecture**: Hybrid
- Supports gradual migration
- Accommodates both legacy and modern authentication
- Flexible implementation approach

## Conclusion

Selecting the right authentication architecture for your .NET web application depends on your specific requirements, team capabilities, and growth projections. Each approach offers different trade-offs between simplicity, scalability, and flexibility.

For most applications, starting with a simpler architecture (centralized or serverless) and evolving toward more distributed approaches as needed is a pragmatic strategy. The key is to implement the core security best practices regardless of the chosen architecture and ensure that all required authentication providers are properly supported.

By carefully considering the characteristics and recommendations in this guide, you can implement a scalable authentication system that meets your current needs while providing a path for future growth and evolution.`
  },
  {
    id: "centralized",
    name: "Centralized Authentication",
    description: "Authentication logic consolidated into a single component within the application",
    content: `# Centralized Authentication Architecture

## Overview
The centralized authentication architecture is a traditional approach where authentication logic is consolidated into a single component or service within the application. This architecture provides a single source of truth for authentication and authorization decisions.

## Key Components

### 1. Identity Provider Integration
- Direct integration with external identity providers (Google, Facebook, Apple, Microsoft, Azure AD)
- Uses OAuth 2.0 and OpenID Connect protocols for secure authentication
- Centralized configuration of client IDs and secrets

### 2. Authentication Service
- Core component responsible for all authentication and authorization logic
- Handles user registration, login, and account management
- Manages token issuance, validation, and revocation
- Implements security policies and password hashing

### 3. User Store
- Centralized database for storing user profiles and credentials
- Typically uses Entity Framework Core with SQL Server or other relational database
- Stores external provider tokens and user claims

### 4. Token Management
- Issues JWT (JSON Web Tokens) for authenticated sessions
- Manages token lifecycle (creation, validation, refresh, revocation)
- Implements token-based authentication for API access

## Implementation in .NET

\`\`\`csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add database context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(config.GetConnectionString("DefaultConnection")));

// Add Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure authentication
builder.Services.AddAuthentication(options => 
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options => 
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = config["JWT:Issuer"],
        ValidAudience = config["JWT:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(config["JWT:SecretKey"]))
    };
})
// Add external providers
.AddGoogle(options =>
{
    options.ClientId = config["Authentication:Google:ClientId"];
    options.ClientSecret = config["Authentication:Google:ClientSecret"];
})
.AddFacebook(options =>
{
    options.ClientId = config["Authentication:Facebook:ClientId"];
    options.ClientSecret = config["Authentication:Facebook:ClientSecret"];
})
.AddMicrosoftAccount(options =>
{
    options.ClientId = config["Authentication:Microsoft:ClientId"];
    options.ClientSecret = config["Authentication:Microsoft:ClientSecret"];
})
.AddApple(options =>
{
    options.ClientId = config["Authentication:Apple:ClientId"];
    options.KeyId = config["Authentication:Apple:KeyId"];
    options.TeamId = config["Authentication:Apple:TeamId"];
    options.PrivateKey = config["Authentication:Apple:PrivateKey"];
})
.AddOpenIdConnect("AzureAD", options =>
{
    options.Authority = $"https://login.microsoftonline.com/{config["Authentication:AzureAd:TenantId"]}";
    options.ClientId = config["Authentication:AzureAd:ClientId"];
    options.ClientSecret = config["Authentication:AzureAd:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
});
\`\`\`

## Scalability Considerations

### Vertical Scaling
- Increase resources (CPU, memory) of the authentication server
- Suitable for small to medium applications with moderate user loads

### Horizontal Scaling
- Deploy multiple instances of the authentication service behind a load balancer
- Requires session affinity or distributed caching for token validation
- Database scaling through read replicas or sharding for large user bases

### Caching Strategies
- Implement distributed caching (Redis) for session and token storage
- Cache user claims and authentication results to reduce database load
- Use sliding expiration for cached authentication data

### Performance Optimization
- Implement asynchronous processing for non-critical authentication tasks
- Optimize database queries and indexing for user lookups
- Use connection pooling for database connections

## Security Considerations
- Implement rate limiting to prevent brute force attacks
- Use secure password hashing algorithms (Argon2id, PBKDF2)
- Implement proper HTTPS configuration with certificate validation
- Regularly rotate JWT signing keys
- Implement proper token validation on all protected endpoints

## Advantages
1. Simplified management of authentication logic in a single location
2. Easier to implement and maintain for small to medium applications
3. Centralized security policy enforcement
4. Reduced complexity in the overall system architecture
5. Easier to audit and monitor authentication activities

## Disadvantages
1. Potential single point of failure
2. May become a performance bottleneck under high load
3. Scaling challenges for very large applications
4. Tightly coupled with the main application
5. Less flexibility for microservices architectures

## Best Suited For
- Monolithic applications
- Small to medium-sized web applications
- Applications with moderate authentication requirements
- Teams with limited resources for managing complex authentication infrastructure`
  },
  {
    id: "distributed",
    name: "Distributed Authentication",
    description: "Authentication concerns separated into dedicated services that can be independently scaled",
    content: `# Distributed Authentication Architecture

## Overview
The distributed authentication architecture separates authentication concerns into dedicated services that can be independently scaled and deployed. This approach is ideal for large-scale applications with high traffic volumes and complex authentication requirements.

## Key Components

### 1. Authentication Service
- Standalone service dedicated to authentication and authorization
- Exposes APIs for user registration, login, and token management
- Implements OAuth 2.0 and OpenID Connect protocols
- Manages connections to external identity providers

### 2. Identity Provider Integrations
- Dedicated components for each external provider (Google, Facebook, Apple, Microsoft, Azure AD)
- Isolated configuration and credential management
- Standardized claim mapping from various providers

### 3. Token Service
- Issues and validates JWT tokens
- Manages token lifecycle and revocation
- Implements refresh token rotation for enhanced security
- Provides token introspection endpoints

### 4. User Profile Service
- Manages user profile data independently from authentication
- Provides APIs for profile updates and management
- Handles user claims and permissions

### 5. API Gateway
- Routes authentication requests to appropriate services
- Implements token validation and authorization
- Provides rate limiting and security controls
- Handles cross-cutting concerns like logging and monitoring

## Implementation in .NET

\`\`\`csharp
// AuthService/Program.cs
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add database context for user store
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(config.GetConnectionString("AuthConnection")));

// Add Identity with distributed cache
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Add distributed cache for token storage
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = config.GetConnectionString("RedisConnection");
    options.InstanceName = "AuthService_";
});

// Configure authentication with multiple providers
builder.Services.AddAuthentication()
    .AddGoogle(options =>
    {
        options.ClientId = config["Authentication:Google:ClientId"];
        options.ClientSecret = config["Authentication:Google:ClientSecret"];
    })
    .AddFacebook(options =>
    {
        options.ClientId = config["Authentication:Facebook:ClientId"];
        options.ClientSecret = config["Authentication:Facebook:ClientSecret"];
    })
    .AddMicrosoftAccount(options =>
    {
        options.ClientId = config["Authentication:Microsoft:ClientId"];
        options.ClientSecret = config["Authentication:Microsoft:ClientSecret"];
    })
    .AddApple(options =>
    {
        options.ClientId = config["Authentication:Apple:ClientId"];
        options.KeyId = config["Authentication:Apple:KeyId"];
        options.TeamId = config["Authentication:Apple:TeamId"];
        options.PrivateKey = config["Authentication:Apple:PrivateKey"];
    })
    .AddOpenIdConnect("AzureAD", options =>
    {
        options.Authority = $"https://login.microsoftonline.com/{config["Authentication:AzureAd:TenantId"]}";
        options.ClientId = config["Authentication:AzureAd:ClientId"];
        options.ClientSecret = config["Authentication:AzureAd:ClientSecret"];
    })
    .AddOpenIdConnect("GoogleWorkspace", options =>
    {
        options.Authority = "https://accounts.google.com";
        options.ClientId = config["Authentication:GoogleWorkspace:ClientId"];
        options.ClientSecret = config["Authentication:GoogleWorkspace:ClientSecret"];
        options.CallbackPath = "/signin-google-workspace";
    });

// Add IdentityServer for token issuance
builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>()
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlServer(
            config.GetConnectionString("ConfigurationConnection"));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlServer(
            config.GetConnectionString("OperationalConnection"));
        options.EnableTokenCleanup = true;
        options.TokenCleanupInterval = 3600; // seconds
    })
    .AddDeveloperSigningCredential();

// Add health checks
builder.Services.AddHealthChecks()
    .AddSqlServer(config.GetConnectionString("AuthConnection"))
    .AddRedis(config.GetConnectionString("RedisConnection"));
\`\`\`

## Scalability Considerations

### Horizontal Scaling
- Deploy multiple instances of each authentication service component
- Use container orchestration (Kubernetes) for automated scaling
- Implement service discovery for inter-service communication

### Database Scaling
- Implement database sharding for user stores based on user ID ranges
- Use read replicas for high-volume read operations
- Consider NoSQL databases for user profile storage

### Caching Architecture
- Implement multi-level caching strategy
  - Local in-memory cache for frequently accessed data
  - Distributed cache (Redis) for shared session data
  - CDN caching for static authentication resources

### Load Balancing
- Use layer 7 load balancing for intelligent request routing
- Implement sticky sessions or token-based routing
- Configure health checks for automatic failover

### Asynchronous Processing
- Use message queues for non-critical authentication operations
- Implement event-driven architecture for authentication events
- Offload intensive operations like password hashing to background workers

## Security Considerations
- Implement defense in depth with multiple security layers
- Use mutual TLS for service-to-service communication
- Implement proper key management with rotation policies
- Deploy Web Application Firewall (WAF) for API protection
- Implement comprehensive logging and monitoring
- Use short-lived access tokens with refresh token rotation

## Advantages
1. Highly scalable architecture capable of handling millions of users
2. Independent scaling of different authentication components
3. Improved fault tolerance and resilience
4. Better separation of concerns and modularity
5. Supports complex authentication scenarios and workflows
6. Enables gradual migration and updates of authentication components

## Disadvantages
1. Increased complexity in deployment and management
2. Higher operational overhead
3. Requires more sophisticated DevOps practices
4. Potential latency in distributed transactions
5. More complex debugging and troubleshooting

## Best Suited For
- Large-scale applications with high user volumes
- Applications with complex authentication requirements
- Organizations with dedicated security and operations teams
- Multi-tenant applications
- Applications requiring high availability and geographic distribution`
  },
  {
    id: "microservices",
    name: "Microservices-Based Authentication",
    description: "Authentication implemented as specialized, loosely coupled microservices",
    content: `# Microservices-Based Authentication Architecture

## Overview
The microservices-based authentication architecture implements authentication as a set of specialized, loosely coupled microservices that work together to provide comprehensive identity management. This approach aligns with modern microservices principles of autonomy, resilience, and independent deployment.

## Key Components

### 1. Identity Management Service
- Core service for user registration and profile management
- Maintains user identity data and credentials
- Provides APIs for account creation, updates, and deletion
- Handles user profile synchronization with external providers

### 2. Authentication Gateway
- Entry point for all authentication requests
- Routes requests to appropriate authentication microservices
- Implements rate limiting and security controls
- Provides unified API for client applications

### 3. Provider Integration Services
- Separate microservices for each external provider:
  - Google/Google Workspace Authentication Service
  - Facebook Authentication Service
  - Apple Authentication Service
  - Microsoft/Azure AD Authentication Service
- Each service handles provider-specific authentication flows
- Standardizes claims and token formats

### 4. Token Service
- Issues, validates, and revokes tokens
- Implements JWT or other token standards
- Manages token lifecycle and security
- Provides token introspection and validation endpoints

### 5. Authorization Service
- Handles role-based and claims-based authorization
- Manages permissions and access control policies
- Provides policy enforcement points for applications
- Implements fine-grained authorization rules

### 6. User Federation Service
- Manages identity federation across multiple systems
- Handles single sign-on (SSO) capabilities
- Synchronizes user data across services
- Implements account linking between providers

## Implementation in .NET

\`\`\`csharp
// AuthGateway/Program.cs
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add API Gateway services
builder.Services.AddReverseProxy()
    .LoadFromConfig(config.GetSection("ReverseProxy"));

// Add authentication for the gateway
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = config["IdentityServer:Authority"];
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

// Add distributed tracing
builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddJaegerExporter());

// Add health checks
builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapReverseProxy();
app.MapHealthChecks("/health");

app.Run();
\`\`\`

\`\`\`csharp
// GoogleAuthService/Program.cs
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add Google authentication specific services
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
})
.AddCookie()
.AddGoogle(options =>
{
    options.ClientId = config["Authentication:Google:ClientId"];
    options.ClientSecret = config["Authentication:Google:ClientSecret"];
    options.SaveTokens = true;
})
.AddOpenIdConnect("GoogleWorkspace", options =>
{
    options.Authority = "https://accounts.google.com";
    options.ClientId = config["Authentication:GoogleWorkspace:ClientId"];
    options.ClientSecret = config["Authentication:GoogleWorkspace:ClientSecret"];
    options.CallbackPath = "/signin-google-workspace";
    options.SaveTokens = true;
});

// Add message broker for event publishing
builder.Services.AddMassTransit(x =>
{
    x.UsingRabbitMq((context, cfg) =>
    {
        cfg.Host(config["RabbitMQ:Host"], "/", h =>
        {
            h.Username(config["RabbitMQ:Username"]);
            h.Password(config["RabbitMQ:Password"]);
        });
    });
});

// Similar services would be implemented for other providers
\`\`\`

## Scalability Considerations

### Service Independence
- Each authentication service scales independently based on demand
- Provider-specific services can be scaled according to usage patterns
- Critical services like token validation can be prioritized for resources

### Containerization and Orchestration
- Deploy services as containers using Docker
- Orchestrate with Kubernetes for automated scaling and management
- Implement horizontal pod autoscaling based on CPU/memory metrics

### Data Partitioning
- Shard user data based on consistent hashing algorithms
- Implement event sourcing for user identity events
- Use CQRS pattern to separate read and write operations

### Resilience Patterns
- Implement circuit breaker pattern for external provider calls
- Use retry policies with exponential backoff
- Implement fallback mechanisms for degraded operation

### Event-Driven Architecture
- Use message brokers (RabbitMQ, Kafka) for asynchronous communication
- Implement event sourcing for authentication events
- Reduce inter-service dependencies through event-based communication

## Security Considerations
- Implement zero-trust security model
- Use service meshes (Istio, Linkerd) for secure service-to-service communication
- Implement proper secrets management (Azure Key Vault, HashiCorp Vault)
- Deploy security sidecar containers for consistent policy enforcement
- Implement comprehensive audit logging across services
- Use mTLS for all service communication

## Advantages
1. Extreme scalability with independent service scaling
2. High resilience with no single point of failure
3. Technology diversity - each service can use optimal tech stack
4. Independent deployment and updates of authentication components
5. Team autonomy - different teams can own different authentication services
6. Easier to implement complex authentication workflows
7. Better isolation of security concerns

## Disadvantages
1. Highest complexity among authentication architectures
2. Significant operational overhead
3. Potential performance impact from network communication
4. Requires mature DevOps practices and tooling
5. More complex testing and debugging
6. Requires careful API versioning and contract management

## Best Suited For
- Large enterprises with complex authentication requirements
- Organizations already using microservices architecture
- Applications requiring extreme scalability and resilience
- Multi-region or global deployments
- Organizations with dedicated platform teams
- Applications with varying authentication requirements across components`
  },
  {
    id: "serverless",
    name: "Serverless Authentication",
    description: "Authentication using cloud-based serverless computing services",
    content: `# Serverless Authentication Architecture

## Overview
The serverless authentication architecture leverages cloud-based serverless computing services to handle authentication workflows without managing the underlying infrastructure. This approach provides automatic scaling, reduced operational overhead, and consumption-based pricing.

## Key Components

### 1. Authentication API Functions
- Serverless functions (Azure Functions, AWS Lambda) for authentication operations
- Separate functions for different authentication flows:
  - User registration function
  - Login function
  - Token validation function
  - Password reset function
  - External provider authentication functions

### 2. Identity Provider Integrations
- Serverless functions for each external provider:
  - Google/Google Workspace authentication function
  - Facebook authentication function
  - Apple authentication function
  - Microsoft/Azure AD authentication function
- Each function handles provider-specific OAuth/OIDC flows

### 3. Managed Identity Service
- Cloud-provided identity service (Azure AD B2C, AWS Cognito, Auth0)
- Handles user storage, authentication, and session management
- Provides built-in support for multiple identity providers
- Manages token issuance and validation

### 4. API Gateway
- Routes authentication requests to appropriate functions
- Handles request validation and rate limiting
- Provides unified API for client applications
- Implements caching for token validation

### 5. Serverless Database
- Managed database service for user profile storage
- Automatically scales with demand
- Examples: Azure Cosmos DB, Amazon DynamoDB
- Stores user profiles, preferences, and custom claims

## Implementation in .NET

### Using Azure Functions with Azure AD B2C

\`\`\`csharp
// LoginTrigger.cs
public static class LoginTrigger
{
    [FunctionName("LoginTrigger")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "login")] HttpRequest req,
        ILogger log)
    {
        log.LogInformation("Login request received");

        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        var data = JsonConvert.DeserializeObject<LoginModel>(requestBody);

        // Validate input
        if (string.IsNullOrEmpty(data.Username) || string.IsNullOrEmpty(data.Password))
        {
            return new BadRequestObjectResult("Username and password are required");
        }

        try
        {
            // Acquire token for accessing Microsoft Graph API
            var confidentialClientApp = ConfidentialClientApplicationBuilder
                .Create(Environment.GetEnvironmentVariable("AzureAD:ClientId"))
                .WithClientSecret(Environment.GetEnvironmentVariable("AzureAD:ClientSecret"))
                .WithAuthority(new Uri($"https://login.microsoftonline.com/{Environment.GetEnvironmentVariable("AzureAD:TenantId")}"))
                .Build();

            var scopes = new[] { "https://graph.microsoft.com/.default" };
            var authResult = await confidentialClientApp.AcquireTokenForClient(scopes).ExecuteAsync();

            // Use Microsoft Graph to authenticate user
            var graphClient = new GraphServiceClient(
                new DelegateAuthenticationProvider(requestMessage =>
                {
                    requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);
                    return Task.CompletedTask;
                }));

            // Perform authentication logic
            // ...

            // Generate JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWT:SecretKey"));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, data.Username),
                    // Add additional claims as needed
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return new OkObjectResult(new
            {
                token = tokenHandler.WriteToken(token)
            });
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Error during login");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }
}
\`\`\`

### Using Azure AD B2C for External Providers

\`\`\`csharp
// Startup.cs for a .NET Web App that uses Azure AD B2C
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options =>
    {
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{Configuration["AzureAdB2C:Domain"]}/{Configuration["AzureAdB2C:TenantId"]}/v2.0/";
        options.Audience = Configuration["AzureAdB2C:ClientId"];
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = AuthenticationFailed
        };
    })
    .AddOpenIdConnect("AzureADB2C", options =>
    {
        options.Authority = $"https://{Configuration["AzureAdB2C:Domain"]}/{Configuration["AzureAdB2C:TenantId"]}/v2.0";
        options.ClientId = Configuration["AzureAdB2C:ClientId"];
        options.ClientSecret = Configuration["AzureAdB2C:ClientSecret"];
        options.CallbackPath = Configuration["AzureAdB2C:CallbackPath"];
        options.SignedOutCallbackPath = Configuration["AzureAdB2C:SignedOutCallbackPath"];
        options.SignInScheme = "Cookies";
        options.ResponseType = "code";
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
    });

    // Azure AD B2C is configured to support Google, Facebook, Apple, Microsoft, and Azure AD
    // through the Azure portal configuration
}
\`\`\`

## Scalability Considerations

### Automatic Scaling
- Serverless functions automatically scale based on demand
- No need to provision or manage servers
- Scales to zero when not in use, reducing costs
- Handles traffic spikes without manual intervention

### Consumption-Based Pricing
- Pay only for actual authentication operations
- Cost scales linearly with usage
- Optimized for variable workloads
- No idle capacity costs

### Global Distribution
- Deploy functions to multiple regions for low-latency access
- Use traffic manager or front door services for global routing
- Implement geo-redundant database replication
- Leverage CDN for static authentication resources

### Stateless Design
- Design functions to be stateless for better scaling
- Use managed services for state management
- Implement idempotent operations for reliability
- Use distributed caching for session management

## Security Considerations
- Implement proper function-level authorization
- Use managed identities for secure service-to-service communication
- Store secrets in secure key vaults
- Implement IP restrictions and network security groups
- Enable advanced threat protection on managed services
- Use short-lived tokens with proper validation
- Implement comprehensive logging and monitoring

## Advantages
1. Automatic scaling without infrastructure management
2. Reduced operational overhead and maintenance
3. Pay-per-use cost model optimized for variable workloads
4. Built-in high availability and fault tolerance
5. Simplified deployment and CI/CD integration
6. Leverages cloud provider's security capabilities
7. Rapid development and iteration

## Disadvantages
1. Potential cold start latency for infrequently used functions
2. Limited execution duration for long-running operations
3. Vendor lock-in with cloud provider's services
4. Less control over underlying infrastructure
5. Debugging and monitoring can be more challenging
6. May have higher costs at very large scale

## Best Suited For
- Startups and small to medium businesses
- Applications with variable or unpredictable authentication loads
- Development teams focused on rapid delivery
- Organizations looking to minimize operational overhead
- Applications with cost-sensitive requirements
- Seasonal or event-driven applications with traffic spikes`
  },
  {
    id: "hybrid",
    name: "Hybrid Authentication",
    description: "Combines elements from multiple authentication approaches",
    content: `# Hybrid Authentication Architecture

## Overview
The hybrid authentication architecture combines elements from multiple authentication approaches to create a flexible solution that addresses diverse requirements. This approach is particularly valuable for organizations transitioning between architectures or dealing with complex legacy and modern application ecosystems.

## Key Components

### 1. Centralized Identity Provider
- Core identity service that acts as the source of truth
- Manages user accounts, credentials, and profiles
- Provides centralized policy management
- Supports federation with external identity providers

### 2. Authentication Microservices
- Specialized services for specific authentication scenarios
- Can be deployed and scaled independently
- Examples:
  - Multi-factor authentication service
  - Social login service
  - Enterprise SSO service
  - Legacy system integration service

### 3. API Gateway / BFF (Backend for Frontend)
- Handles authentication for client applications
- Implements token validation and transformation
- Routes requests to appropriate authentication services
- Provides unified API for client applications

### 4. Distributed Caching
- Shared cache for authentication state and tokens
- Improves performance and reduces database load
- Enables stateless services while maintaining session information
- Examples: Redis, Hazelcast

### 5. External Identity Provider Integrations
- Connectors for various identity providers:
  - Google/Google Workspace
  - Facebook
  - Apple
  - Microsoft/Azure AD
- Standardizes claims and token formats across providers

### 6. Legacy Authentication Bridge
- Adapters for integrating with legacy authentication systems
- Provides backward compatibility for existing applications
- Enables gradual migration to modern authentication

## Implementation in .NET

\`\`\`csharp
// Startup.cs for main application
public void ConfigureServices(IServiceCollection services)
{
    var config = Configuration;
    
    // Add Identity with EF Core
    services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();
    
    // Add distributed cache
    services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = config.GetConnectionString("RedisConnection");
        options.InstanceName = "AuthCache_";
    });
    
    // Configure authentication with JWT
    services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.Authority = config["IdentityServer:Authority"];
        options.Audience = config["IdentityServer:Audience"];
        options.RequireHttpsMetadata = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2)
        };
        
        // Add distributed token validation
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var cache = context.HttpContext.RequestServices
                    .GetRequiredService<IDistributedCache>();
                var token = context.SecurityToken as JwtSecurityToken;
                
                // Check if token is revoked
                var isRevoked = await cache.GetStringAsync($"revoked_token:{token.Id}");
                if (!string.IsNullOrEmpty(isRevoked))
                {
                    context.Fail("Token has been revoked");
                }
            }
        };
    });
    
    // Add external authentication providers
    services.AddAuthentication()
        .AddGoogle(options =>
        {
            options.ClientId = config["Authentication:Google:ClientId"];
            options.ClientSecret = config["Authentication:Google:ClientSecret"];
        })
        .AddFacebook(options =>
        {
            options.ClientId = config["Authentication:Facebook:ClientId"];
            options.ClientSecret = config["Authentication:Facebook:ClientSecret"];
        })
        .AddMicrosoftAccount(options =>
        {
            options.ClientId = config["Authentication:Microsoft:ClientId"];
            options.ClientSecret = config["Authentication:Microsoft:ClientSecret"];
        })
        .AddApple(options =>
        {
            options.ClientId = config["Authentication:Apple:ClientId"];
            options.KeyId = config["Authentication:Apple:KeyId"];
            options.TeamId = config["Authentication:Apple:TeamId"];
            options.PrivateKey = config["Authentication:Apple:PrivateKey"];
        })
        .AddOpenIdConnect("AzureAD", options =>
        {
            options.Authority = $"https://login.microsoftonline.com/{config["Authentication:AzureAd:TenantId"]}";
            options.ClientId = config["Authentication:AzureAd:ClientId"];
            options.ClientSecret = config["Authentication:AzureAd:ClientSecret"];
        })
        .AddOpenIdConnect("GoogleWorkspace", options =>
        {
            options.Authority = "https://accounts.google.com";
            options.ClientId = config["Authentication:GoogleWorkspace:ClientId"];
            options.ClientSecret = config["Authentication:GoogleWorkspace:ClientSecret"];
            options.CallbackPath = "/signin-google-workspace";
        });
    
    // Add HTTP client for authentication microservices
    services.AddHttpClient("MfaService", client =>
    {
        client.BaseAddress = new Uri(config["AuthServices:MfaService"]);
    });
    
    services.AddHttpClient("SocialLoginService", client =>
    {
        client.BaseAddress = new Uri(config["AuthServices:SocialLoginService"]);
    });
    
    // Add legacy authentication bridge
    services.AddSingleton<ILegacyAuthBridge, LegacyAuthBridge>();
}
\`\`\`

## Scalability Considerations

### Mixed Scaling Strategies
- Scale centralized components vertically for stability
- Scale specialized services horizontally for flexibility
- Use auto-scaling for components with variable load
- Implement priority-based scaling for critical authentication services

### Tiered Caching Strategy
- Implement multi-level caching:
  - In-memory cache for high-frequency operations
  - Distributed cache for shared authentication state
  - Database for persistent storage
- Use cache-aside pattern for efficient data access

### Intelligent Load Distribution
- Route authentication traffic based on request characteristics
- Implement priority queues for critical authentication operations
- Use circuit breakers to prevent cascading failures
- Implement bulkhead pattern to isolate failures

### Progressive Enhancement
- Implement graceful degradation for authentication services
- Provide fallback authentication methods when primary methods fail
- Design for partial availability during outages
- Implement feature flags for controlling authentication capabilities

## Security Considerations
- Implement defense in depth with multiple security layers
- Use different security approaches for different sensitivity levels
- Implement comprehensive audit logging across all components
- Deploy Web Application Firewall (WAF) for API protection
- Implement proper key management with rotation policies
- Use short-lived access tokens with refresh token rotation
- Implement risk-based authentication for sensitive operations

## Advantages
1. Flexibility to address diverse authentication requirements
2. Ability to leverage best aspects of different architectures
3. Supports gradual migration from legacy to modern authentication
4. Can optimize different components based on specific needs
5. Allows for technology diversity where appropriate
6. Can balance security, performance, and user experience
7. Adaptable to changing business requirements

## Disadvantages
1. Increased complexity in overall architecture
2. Potential inconsistencies across different components
3. Requires careful integration testing
4. May have higher operational overhead
5. Requires clear boundaries and interfaces between components
6. More challenging to maintain and troubleshoot

## Best Suited For
- Organizations with diverse application portfolios
- Enterprises transitioning from legacy to modern architectures
- Applications with varying authentication requirements
- Organizations with mixed technology stacks
- Systems with both internal and external user populations
- Applications requiring different authentication approaches for different user segments`
  },
  {
    id: "validation",
    name: "Platform Coverage Validation",
    description: "Validation of authentication platform support across architectures",
    content: `# Authentication Platform Coverage Validation

## Overview
This document validates that each architectural approach supports all required authentication platforms:
- Google Suite (Google Workspace)
- Google (personal accounts)
- Facebook
- Apple
- Azure AD
- Microsoft (personal accounts)

## Centralized Authentication Architecture
| Provider | Support | Implementation Method |
|----------|---------|----------------------|
| Google Suite | ✅ | OpenID Connect integration via \`.AddOpenIdConnect("GoogleWorkspace")\` |
| Google | ✅ | OAuth 2.0 integration via \`.AddGoogle()\` |
| Facebook | ✅ | OAuth 2.0 integration via \`.AddFacebook()\` |
| Apple | ✅ | OAuth 2.0 integration via \`.AddApple()\` |
| Azure AD | ✅ | OpenID Connect integration via \`.AddOpenIdConnect("AzureAD")\` |
| Microsoft | ✅ | OAuth 2.0 integration via \`.AddMicrosoftAccount()\` |

## Distributed Authentication Architecture
| Provider | Support | Implementation Method |
|----------|---------|----------------------|
| Google Suite | ✅ | OpenID Connect integration via \`.AddOpenIdConnect("GoogleWorkspace")\` |
| Google | ✅ | OAuth 2.0 integration via \`.AddGoogle()\` |
| Facebook | ✅ | OAuth 2.0 integration via \`.AddFacebook()\` |
| Apple | ✅ | OAuth 2.0 integration via \`.AddApple()\` |
| Azure AD | ✅ | OpenID Connect integration via \`.AddOpenIdConnect("AzureAD")\` |
| Microsoft | ✅ | OAuth 2.0 integration via \`.AddMicrosoftAccount()\` |

## Microservices-Based Authentication Architecture
| Provider | Support | Implementation Method |
|----------|---------|----------------------|
| Google Suite | ✅ | Dedicated microservice with OpenID Connect integration |
| Google | ✅ | Dedicated microservice with OAuth 2.0 integration |
| Facebook | ✅ | Dedicated microservice with OAuth 2.0 integration |
| Apple | ✅ | Dedicated microservice with OAuth 2.0 integration |
| Azure AD | ✅ | Dedicated microservice with OpenID Connect integration |
| Microsoft | ✅ | Dedicated microservice with OAuth 2.0 integration |

## Serverless Authentication Architecture
| Provider | Support | Implementation Method |
|----------|---------|----------------------|
| Google Suite | ✅ | Azure AD B2C or custom serverless functions with OpenID Connect |
| Google | ✅ | Azure AD B2C or custom serverless functions with OAuth 2.0 |
| Facebook | ✅ | Azure AD B2C or custom serverless functions with OAuth 2.0 |
| Apple | ✅ | Azure AD B2C or custom serverless functions with OAuth 2.0 |
| Azure AD | ✅ | Azure AD B2C or custom serverless functions with OpenID Connect |
| Microsoft | ✅ | Azure AD B2C or custom serverless functions with OAuth 2.0 |

## Hybrid Authentication Architecture
| Provider | Support | Implementation Method |
|----------|---------|----------------------|
| Google Suite | ✅ | OpenID Connect integration via \`.AddOpenIdConnect("GoogleWorkspace")\` |
| Google | ✅ | OAuth 2.0 integration via \`.AddGoogle()\` |
| Facebook | ✅ | OAuth 2.0 integration via \`.AddFacebook()\` |
| Apple | ✅ | OAuth 2.0 integration via \`.AddApple()\` |
| Azure AD | ✅ | OpenID Connect integration via \`.AddOpenIdConnect("AzureAD")\` |
| Microsoft | ✅ | OAuth 2.0 integration via \`.AddMicrosoftAccount()\` |

## Conclusion
All architectural approaches provide comprehensive support for the required authentication platforms. Each architecture implements the necessary protocols (OAuth 2.0 and OpenID Connect) to integrate with Google Suite, Google, Facebook, Apple, Azure AD, and Microsoft authentication services.`
  }
];
