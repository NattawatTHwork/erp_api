using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Services;

[Route("api/[controller]")]
[ApiController]
public class RegisterController : ControllerBase
{
    private readonly RegisterService _registerService;

    public RegisterController(RegisterService registerService)
    {
        _registerService = registerService;
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
    {
        var isEmailExists = await _registerService.CheckIfEmailExists(request.email);
        if (isEmailExists)
        {
            return BadRequest(new 
            { 
                status = false, 
                message = "Email already exists" 
            });
        }
        request.user_code = await _registerService.GenerateUserCode();
        var newUser = await _registerService.RegisterUser(request);
        
        return CreatedAtAction(nameof(Register), new { id = newUser.user_id }, new 
        { 
            status = true, 
            message = "User registered successfully", 
            user_id = newUser.user_id 
        });
    }
}
