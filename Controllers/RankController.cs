using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers; 
using erp_api.Services; 

[Route("api/[controller]")]
[ApiController]
[Authorize] 
public class RankController : ControllerBase
{
    private readonly RankService _rankService;

    public RankController(RankService rankService)
    {
        _rankService = rankService;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var result = await _rankService.GetAllRanks();
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
        var rank = await _rankService.GetRankById(id);
        if (rank == null) 
            return NotFound(new 
            {
                status = false,
                message = "Rank not found"
            });

        return Ok(new 
        {
            status = true,
            message = "Successfully Retrieved",
            data = rank
        });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] Rank rank)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        rank.rank_code = await _rankService.GenerateRankCode();
        rank.created_at = DateTime.UtcNow;
        rank.created_by = userId;

        await _rankService.AddRank(rank);
        
        return CreatedAtAction(nameof(GetById), new { id = rank.rank_id }, new 
        {
            status = true,
            message = "Successfully Created",
            data = rank
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] Rank updatedRank)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var rank = await _rankService.GetRankById(id);
        
        if (rank == null) 
            return NotFound(new 
            {
                status = false,
                message = "Rank not found"
            });

        await _rankService.UpdateRank(rank, updatedRank, userId);
        
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
        var rank = await _rankService.GetRankById(id);
        
        if (rank == null) 
            return NotFound(new 
            {
                status = false,
                message = "Rank not found"
            });

        await _rankService.SoftDeleteRank(rank, userId);
        
        return Ok(new 
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
