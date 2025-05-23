using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Presentation.Models;

namespace Presentation.Services;

public interface ITokenService
{
    Task<TokenResponse> GenerateAccessTokenAsync(TokenRequest request, int expiresInDays = 30);
    Task<ValidationResponse> ValidateAccessTokenAsync(ValidationRequest request);
}

public  class TokenService : ITokenService
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly string _secretKey;
    
    public TokenService()
    {
        _issuer = Environment.GetEnvironmentVariable("Issuer") ?? throw new InvalidOperationException("Issuer environment variable not set.");
        _audience = Environment.GetEnvironmentVariable("Audience") ?? throw new InvalidOperationException("Audience environment variable not set.");
        _secretKey = Environment.GetEnvironmentVariable("SecretKey") ?? throw new InvalidOperationException("SecretKey environment variable not set.");
    }
    
    public async Task<TokenResponse> GenerateAccessTokenAsync(TokenRequest request, int expiresInDays = 30)
    {
        try
        {
            if (string.IsNullOrEmpty(request.UserId))
                throw new NullReferenceException("No UserId provided");
            
            var credentials = new SigningCredentials (new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)), SecurityAlgorithms.HmacSha256) ?? throw new NullReferenceException("Unable to create credentials");
            
            // using var http = new HttpClient();
            // var response = await http.PostAsJsonAsync("", request);
            // if (!response.IsSuccessStatusCode)
            //     throw new Exception($"User {request.UserId} is invalid. Status code: {response.StatusCode}");
            
            List<Claim> claims = [new(ClaimTypes.NameIdentifier, request.UserId)];

            if (!string.IsNullOrEmpty(request.Email))
                claims.Add(new Claim(ClaimTypes.Email, request.Email));

            if (!string.IsNullOrEmpty(request.Role))
                claims.Add(new Claim(ClaimTypes.Role, request.Role));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = credentials,
                // Expires = DateTime.UtcNow.AddMinutes(15) // if we also implement a refresh token 
                Expires = DateTime.UtcNow.AddDays(expiresInDays) // otherwise maybe it's better to set it to 30 days
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            
            return new TokenResponse
            {
                Succeeded = true,
                AccessToken = tokenHandler.WriteToken(token)
            };
        }
    
        catch (Exception ex)
        { return new TokenResponse { Succeeded = false, Message = ex.Message }; }
    }

    public async Task<ValidationResponse> ValidateAccessTokenAsync(ValidationRequest request)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        
        try
        {
            var principal = tokenHandler.ValidateToken(request.AccessToken, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = true,
                ValidAudience = _audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)),
                ClockSkew = TimeSpan.Zero,
                
            }, out SecurityToken validatedToken);
            
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? throw new NullReferenceException("UserId in claims is null");
            if (userId != request.UserId)
                throw new Exception("UserId in claims does not match UserId in request");

            // using var http = new HttpClient();
            // var response = await http.GetAsync($"http://...../api/users/exists/{userId}");
            // if (!response.IsSuccessStatusCode)
            //     throw new NullReferenceException($"User {userId} not found. Status code: {response.StatusCode}");
            
            return new ValidationResponse { Succeeded = true };
        }
        catch (Exception ex)
        { return new ValidationResponse { Succeeded = false, Message = ex.Message }; }
    }
}

    
