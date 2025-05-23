using System.ComponentModel.DataAnnotations;

namespace Presentation.Models;

public class TokenResponse
{
    [Required]
    public bool Succeeded { get; set; }
    
    [Required]
    public string AccessToken { get; set; } = null!;
    public string? Message { get; set; }
}