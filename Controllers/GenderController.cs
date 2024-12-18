using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers; 
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class GenderController : ControllerBase
{
    private readonly GenderService _genderService;

    public GenderController(GenderService genderService)
    {
        _genderService = genderService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _genderService.GetAllGenders();
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
        var gender = await _genderService.GetGenderById(id);
        if (gender == null) 
            return NotFound(new 
            {
                status = false,
                message = "Gender not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = gender
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] Gender gender)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        gender.gender_code = await _genderService.GenerateGenderCode();
        gender.created_at = DateTime.UtcNow;
        gender.created_by = userId;

        await _genderService.AddGender(gender);
        
        return CreatedAtAction(nameof(GetById), new { id = gender.gender_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = gender
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] Gender updatedGender)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var gender = await _genderService.GetGenderById(id);
        
        if (gender == null) 
            return NotFound(new 
            {
                status = false,
                message = "Gender not found"
            });

        await _genderService.UpdateGender(gender, updatedGender, userId);
        
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
        var gender = await _genderService.GetGenderById(id);
        
        if (gender == null) 
            return NotFound(new 
            {
                status = false,
                message = "Gender not found"
            });

        await _genderService.SoftDeleteGender(gender, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
