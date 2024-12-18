using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers; 
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class EquipmentGroupController : ControllerBase
{
    private readonly EquipmentGroupService _equipmentGroupService;

    public EquipmentGroupController(EquipmentGroupService equipmentGroupService)
    {
        _equipmentGroupService = equipmentGroupService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _equipmentGroupService.GetAllEquipmentGroups();
        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = result
        });
    }

    [HttpGet("equipment_department/{departmentId}")]
    public async Task<IActionResult> GetByDepartmentId(int departmentId)
    {
        var result = await _equipmentGroupService.GetEquipmentGroupsByDepartmentId(departmentId);
        if (!result.Any())
            return NotFound(new 
            {
                status = false,
                message = "No Equipment Groups found for the specified department"
            });

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
        var equipmentGroup = await _equipmentGroupService.GetEquipmentGroupById(id);
        if (equipmentGroup == null) 
            return NotFound(new 
            {
                status = false,
                message = "Equipment Group not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = equipmentGroup
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] EquipmentGroup equipmentGroup)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        equipmentGroup.equipment_group_code = await _equipmentGroupService.GenerateEquipmentGroupCode();
        equipmentGroup.created_at = DateTime.UtcNow;
        equipmentGroup.created_by = userId;

        await _equipmentGroupService.AddEquipmentGroup(equipmentGroup);
        
        return CreatedAtAction(nameof(GetById), new { id = equipmentGroup.equipment_group_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = equipmentGroup
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] EquipmentGroup updatedEquipmentGroup)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var equipmentGroup = await _equipmentGroupService.GetEquipmentGroupById(id);
        
        if (equipmentGroup == null) 
            return NotFound(new 
            {
                status = false,
                message = "Equipment Group not found"
            });

        await _equipmentGroupService.UpdateEquipmentGroup(equipmentGroup, updatedEquipmentGroup, userId);
        
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
        var equipmentGroup = await _equipmentGroupService.GetEquipmentGroupById(id);
        
        if (equipmentGroup == null) 
            return NotFound(new 
            {
                status = false,
                message = "Equipment Group not found"
            });

        await _equipmentGroupService.SoftDeleteEquipmentGroup(equipmentGroup, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
