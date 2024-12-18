using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class UserStatusController : ControllerBase
{
    private readonly UserStatusService _userStatusService;

    public UserStatusController(UserStatusService userStatusService)
    {
        _userStatusService = userStatusService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _userStatusService.GetAllUserStatuses();
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
        var userStatus = await _userStatusService.GetUserStatusById(id);
        if (userStatus == null) 
            return NotFound(new 
            {
                status = false,
                message = "User status not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = userStatus
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] UserStatus userStatus)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        userStatus.user_status_code = await _userStatusService.GenerateUserStatusCode();
        userStatus.created_at = DateTime.UtcNow;
        userStatus.created_by = userId;

        await _userStatusService.AddUserStatus(userStatus);
        
        return CreatedAtAction(nameof(GetById), new { id = userStatus.user_status_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = userStatus
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] UserStatus updatedStatus)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var userStatus = await _userStatusService.GetUserStatusById(id);
        
        if (userStatus == null) 
            return NotFound(new 
            {
                status = false,
                message = "User status not found"
            });

        await _userStatusService.UpdateUserStatus(userStatus, updatedStatus, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Updated"
        });
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var userStatus = await _userStatusService.GetUserStatusById(id);
        
        if (userStatus == null) 
            return NotFound(new 
            {
                status = false,
                message = "User status not found"
            });

        await _userStatusService.SoftDeleteUserStatus(userStatus, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
