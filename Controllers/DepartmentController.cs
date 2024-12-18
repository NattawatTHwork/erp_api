using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class DepartmentController : ControllerBase
{
    private readonly DepartmentService _departmentService;

    public DepartmentController(DepartmentService departmentService)
    {
        _departmentService = departmentService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _departmentService.GetAllDepartments();
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
        var department = await _departmentService.GetDepartmentById(id);
        if (department == null)
            return NotFound(new
            {
                status = false,
                message = "Department not found"
            });

        return Ok(new
        {
            status = true,
            message = "Successfully Retrieved",
            data = department
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] Department department)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        department.department_code = await _departmentService.GenerateDepartmentCode();
        department.created_at = DateTime.UtcNow;
        department.created_by = userId;

        await _departmentService.AddDepartment(department);

        return CreatedAtAction(nameof(GetById), new { id = department.department_id }, new
        {
            status = true,
            message = "Successfully Created",
            data = department
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] Department updatedDepartment)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var department = await _departmentService.GetDepartmentById(id);

        if (department == null)
            return NotFound(new
            {
                status = false,
                message = "Department not found"
            });

        await _departmentService.UpdateDepartment(department, updatedDepartment, userId);

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
        var department = await _departmentService.GetDepartmentById(id);

        if (department == null)
            return NotFound(new
            {
                status = false,
                message = "Department not found"
            });

        await _departmentService.SoftDeleteDepartment(department, userId);

        return Ok(new
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
