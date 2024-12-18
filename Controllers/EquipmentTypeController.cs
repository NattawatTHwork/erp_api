using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers; 
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class EquipmentTypeController : ControllerBase
{
    private readonly EquipmentTypeService _equipmentTypeService;

    public EquipmentTypeController(EquipmentTypeService equipmentTypeService)
    {
        _equipmentTypeService = equipmentTypeService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _equipmentTypeService.GetAllEquipmentTypes();
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
        var equipmentType = await _equipmentTypeService.GetEquipmentTypeById(id);
        if (equipmentType == null) 
            return NotFound(new 
            {
                status = false,
                message = "Equipment Type not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = equipmentType
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] EquipmentType equipmentType)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        equipmentType.equipment_type_code = await _equipmentTypeService.GenerateEquipmentTypeCode();
        equipmentType.created_at = DateTime.UtcNow;
        equipmentType.created_by = userId;

        await _equipmentTypeService.AddEquipmentType(equipmentType);
        
        return CreatedAtAction(nameof(GetById), new { id = equipmentType.equipment_type_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = equipmentType
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] EquipmentType updatedEquipmentType)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var equipmentType = await _equipmentTypeService.GetEquipmentTypeById(id);
        
        if (equipmentType == null) 
            return NotFound(new 
            {
                status = false,
                message = "Equipment Type not found"
            });

        await _equipmentTypeService.UpdateEquipmentType(equipmentType, updatedEquipmentType, userId);
        
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
        var equipmentType = await _equipmentTypeService.GetEquipmentTypeById(id);
        
        if (equipmentType == null) 
            return NotFound(new 
            {
                status = false,
                message = "Equipment Type not found"
            });

        await _equipmentTypeService.SoftDeleteEquipmentType(equipmentType, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
