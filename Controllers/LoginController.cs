using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using erp_api.Services;

[Route("api/[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly LoginService _loginService;

    public LoginController(LoginService loginService)
    {
        _loginService = loginService;
    }

    [HttpPost]
    [AllowAnonymous] 
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _loginService.AuthenticateUser(request.email, request.user_password);

        if (user == null)
        {
            return Unauthorized(new 
            { 
                status = false, 
                message = "Invalid email or password" 
            });
        }

        var token = _loginService.GenerateJwtToken(user);

        return Ok(new 
        {
            status = true,
            message = "Login successful",
            token,
            user = new
            {
                user.user_id,
                user.email,
                user.firstname,
                user.lastname
            }
        });
    }
}
