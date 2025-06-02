using System.IdentityModel.Tokens.Jwt;
using Presentation.Models;
using Presentation.Services;

namespace _Tests;

// took some help from GPT to create these tests
public class TokenServiceIntegrationTests
{
    // ensures environment variables always sets correctly for all tests
    private static void SetEnv()
    {
        Environment.SetEnvironmentVariable("Issuer", "https://localhost:7111");
        Environment.SetEnvironmentVariable("Audience", "Ventixe");
        Environment.SetEnvironmentVariable("SecretKey", "aaaf0aa7-7d0d-43ad-91c4-cd6528d6e93b");
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_ValidRequest_ReturnsToken()
    {
        // Arrange
        SetEnv();
        var service = new TokenService();
        var request = new TokenRequest
        {
            UserId = "testuser",
            Email = "testuser@example.com",
            Role = "User"
        };

        // Act
        var response = await service.GenerateAccessTokenAsync(request);

        // Assert
        Assert.True(response.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(response.AccessToken));
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_ValidToken_ReturnsSuccess()
    {
        // Arrange
        SetEnv();
        var service = new TokenService();
        var tokenRequest = new TokenRequest
        {
            UserId = "testuser",
            Email = "testuser@example.com",
            Role = "User"
        };

        var tokenResponse = await service.GenerateAccessTokenAsync(tokenRequest);

        var validationRequest = new ValidationRequest
        {
            UserId = "testuser",
            AccessToken = tokenResponse.AccessToken
        };

        // Act
        var validationResponse = await service.ValidateAccessTokenAsync(validationRequest);

        // Assert
        Assert.True(validationResponse.Succeeded);
        Assert.Contains("Token is valid", validationResponse.Message);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_InvalidUserId_ReturnsFailure()
    {
        // Arrange
        SetEnv();
        var service = new TokenService();
        var tokenRequest = new TokenRequest
        {
            UserId = "testuser",
            Email = "testuser@example.com",
            Role = "User"
        };

        var tokenResponse = await service.GenerateAccessTokenAsync(tokenRequest);

        var validationRequest = new ValidationRequest
        {
            UserId = "anotheruser", // Wrong userId
            AccessToken = tokenResponse.AccessToken
        };

        // Act
        var validationResponse = await service.ValidateAccessTokenAsync(validationRequest);

        // Assert
        Assert.False(validationResponse.Succeeded);
        Assert.Contains("does not match", validationResponse.Message);
    }
    
    [Fact]
    public async Task GenerateAccessTokenAsync_Fails_If_UserId_Missing()
    {
        SetEnv();
        var service = new TokenService();
        var request = new TokenRequest { UserId = null, Email = "testuser@example.com", Role = "User" };

        var response = await service.GenerateAccessTokenAsync(request);

        Assert.False(response.Succeeded);
        Assert.Contains("No UserId", response.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_Fails_With_Invalid_Token()
    {
        SetEnv();
        var service = new TokenService();
        var validationRequest = new ValidationRequest
        {
            UserId = "testuser",
            AccessToken = "this.is.not.a.valid.token"
        };

        var response = await service.ValidateAccessTokenAsync(validationRequest);

        Assert.False(response.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(response.Message));
    }

    [Fact]
    public async Task ValidateAccessTokenAsync_Fails_With_Wrong_Secret()
    {
        // Generate token with correct secret
        SetEnv();
        var service = new TokenService();
        var tokenRequest = new TokenRequest { UserId = "testuser", Email = "testuser@example.com", Role = "User" };
        var tokenResponse = await service.GenerateAccessTokenAsync(tokenRequest);

        // Change secret before validation
        Environment.SetEnvironmentVariable("SecretKey", "incorrect-secret-key");
        var serviceWithWrongSecret = new TokenService();

        var validationRequest = new ValidationRequest
        {
            UserId = "testuser",
            AccessToken = tokenResponse.AccessToken
        };

        var response = await serviceWithWrongSecret.ValidateAccessTokenAsync(validationRequest);

        Assert.False(response.Succeeded);
        Assert.False(string.IsNullOrWhiteSpace(response.Message));

        // Restore original secret for other tests
        SetEnv();
    }

    [Fact]
    public async Task GenerateAccessTokenAsync_Token_Contains_Correct_Claims()
    {
        SetEnv();
        var service = new TokenService();
        var request = new TokenRequest
        {
            UserId = "claimuser",
            Email = "claimuser@example.com",
            Role = "Admin"
        };

        var response = await service.GenerateAccessTokenAsync(request);

        Assert.True(response.Succeeded);

        // Read claims from the token
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(response.AccessToken);

        Assert.Equal("claimuser", token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub || c.Type == "nameid")?.Value);
        Assert.Equal("claimuser@example.com", token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email || c.Type == "email")?.Value);
        Assert.Equal("Admin", token.Claims.FirstOrDefault(c => c.Type == "role")?.Value);
    }
}