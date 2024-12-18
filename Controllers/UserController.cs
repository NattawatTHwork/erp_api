using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class UserController : ControllerBase
{
    private readonly UserService _userService;

    public UserController(UserService userService)
    {
        _userService = userService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _userService.GetAllUsers();
        return Ok(new
        {
            status = true,
            message = "Successfully Retrieved",
            data = result
        });
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(int id)
    {
        var user = await _userService.GetUserById(id);
        if (user == null)
            return NotFound(new
            {
                status = false,
                message = "User not found"
            });

        return Ok(new
        {
            status = true,
            message = "Successfully Retrieved",
            data = user
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] User user)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        user.user_code = await _userService.GenerateUserCode();
        user.created_at = DateTime.UtcNow;
        user.created_by = userId;

        await _userService.AddUser(user);

        return CreatedAtAction(nameof(GetById), new { id = user.user_id }, new
        {
            status = true,
            message = "Successfully Created",
            data = user
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] User updatedUser)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var user = await _userService.GetUserById(id);

        if (user == null)
            return NotFound(new
            {
                status = false,
                message = "User not found"
            });

        await _userService.UpdateUser(user, updatedUser, userId);

        return Ok(new
        {
            status = true,
            message = "Successfully Updated"
        });
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        if (id == 1)
        {
            return StatusCode(403, new
            {
                status = false,
                message = "Cannot delete this user"
            });
        }

        var userId = JwtHelper.GetUserIdFromToken(User);
        var user = await _userService.GetUserById(id);

        if (user == null)
            return NotFound(new
            {
                status = false,
                message = "User not found"
            });

        await _userService.SoftDeleteUser(user, userId);

        return Ok(new
        {
            status = true,
            message = "Successfully Deleted"
        });
    }

    [HttpPut("ChangePassword/{id}")]
    public async Task<IActionResult> ChangePassword(int id, [FromBody] string newPassword)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var user = await _userService.GetUserById(id);

        if (user == null)
            return NotFound(new
            {
                status = false,
                message = "User not found"
            });

        await _userService.ChangePassword(user, newPassword, userId);

        return Ok(new
        {
            status = true,
            message = "Password successfully updated"
        });
    }

    [HttpPut("UpdateProfile/{id}")]
    public async Task<IActionResult> UpdateProfile(int id, [FromBody] User updatedUser)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var user = await _userService.GetUserById(id);

        if (user == null)
            return NotFound(new
            {
                status = false,
                message = "User not found"
            });

        await _userService.UpdateUserProfile(user, updatedUser, userId);

        return Ok(new
        {
            status = true,
            message = "Profile successfully updated"
        });
    }
}
