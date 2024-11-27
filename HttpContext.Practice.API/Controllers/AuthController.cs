using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace HttpContext.Practice.API.Controllers
{
    [Route("api/[controller]/[Action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        public async Task<IActionResult> GetToken()
        {
            string userToken = GenerateToken("USER1", "vishal.waman@parallel-minds.com", "ADMIN");
            return Ok(userToken);
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> GetTokenDetail()
        {
            string ? Name = HttpContext.User.Identity?.Name;
            return Ok(Name);
        }

        private string GenerateToken(string userId, string userEmail, string userRole)
        {
            // Retrieve JWT settings
            var key = _configuration["Jwt:Key"];
            var issuer = _configuration["Jwt:Issuer"];
            var audience = _configuration["Jwt:Audience"];
            var expireMinutes = int.Parse(_configuration["Jwt:ExpireMinutes"]);

            // Security key
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Claims
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.Email, userEmail),
            new Claim(ClaimTypes.Role, userRole),
            new Claim(ClaimTypes.Name, "VISHAL_WAMAN"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            // Token creation
            var token = new JwtSecurityToken(
                issuer,
                audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(expireMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
