using System.ComponentModel.DataAnnotations;

namespace Presentation.Models;

public class TokenRequest
{
    [Required]
    public string UserId { get; set; } = null!;
    public string? Email { get; set; }
    public string? Role { get; set; }
}