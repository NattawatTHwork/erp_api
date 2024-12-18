using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class PermissionController : ControllerBase
{
    private readonly PermissionService _permissionService;

    public PermissionController(PermissionService permissionService)
    {
        _permissionService = permissionService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _permissionService.GetAllPermissions();
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
        var permission = await _permissionService.GetPermissionById(id);
        if (permission == null) 
            return NotFound(new 
            {
                status = false,
                message = "Permission not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = permission
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] Permission permission)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        permission.permission_code = await _permissionService.GeneratePermissionCode();
        permission.created_at = DateTime.UtcNow;
        permission.created_by = userId;

        await _permissionService.AddPermission(permission);
        
        return CreatedAtAction(nameof(GetById), new { id = permission.permission_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = permission
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] Permission updatedPermission)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var permission = await _permissionService.GetPermissionById(id);
        
        if (permission == null) 
            return NotFound(new 
            {
                status = false,
                message = "Permission not found"
            });

        await _permissionService.UpdatePermission(permission, updatedPermission, userId);
        
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
        var permission = await _permissionService.GetPermissionById(id);
        
        if (permission == null) 
            return NotFound(new 
            {
                status = false,
                message = "Permission not found"
            });

        await _permissionService.SoftDeletePermission(permission, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
