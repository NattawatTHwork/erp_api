using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class RolePermissionController : ControllerBase
{
    private readonly RolePermissionService _rolePermissionService;

    public RolePermissionController(RolePermissionService rolePermissionService)
    {
        _rolePermissionService = rolePermissionService;
    }

    [HttpPost]
    public async Task<IActionResult> CreateMultiple([FromBody] dynamic request)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        int roleId = request.role_id;
        List<int> permissionIds = request.permission_id.ToObject<List<int>>();

        await _rolePermissionService.CreateMultipleRolePermissions(roleId, permissionIds, userId);
        
        return Ok(new 
        {
            status = true, 
            message = "Role-Permissions updated successfully" 
        });
    }

    [HttpGet("permissions/{roleId}")]
    public async Task<IActionResult> GetPermissionsByRoleId(int roleId)
    {
        var permissions = await _rolePermissionService.GetPermissionsByRoleId(roleId);
        return Ok(new 
        {
            status = true, 
            message = "Successfully Retrieved", 
            data = permissions 
        });
    }
}
