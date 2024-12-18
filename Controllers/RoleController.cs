using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class RoleController : ControllerBase
{
    private readonly RoleService _roleService;

    public RoleController(RoleService roleService)
    {
        _roleService = roleService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _roleService.GetAllRoles();
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
        var role = await _roleService.GetRoleById(id);
        if (role == null) 
            return NotFound(new 
            {
                status = false,
                message = "Role not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = role
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] Role role)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        role.role_code = await _roleService.GenerateRoleCode();
        role.created_at = DateTime.UtcNow;
        role.created_by = userId;

        await _roleService.AddRole(role);
        
        return CreatedAtAction(nameof(GetById), new { id = role.role_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = role
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] Role updatedRole)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var role = await _roleService.GetRoleById(id);
        
        if (role == null) 
            return NotFound(new 
            {
                status = false,
                message = "Role not found"
            });

        await _roleService.UpdateRole(role, updatedRole, userId);
        
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
        var role = await _roleService.GetRoleById(id);
        
        if (role == null) 
            return NotFound(new 
            {
                status = false,
                message = "Role not found"
            });

        await _roleService.SoftDeleteRole(role, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
