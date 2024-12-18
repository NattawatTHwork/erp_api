using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using erp_api.Helpers;
using erp_api.Services;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class EquipmentTransactionController : ControllerBase
{
    private readonly EquipmentTransactionService _transactionService;

    public EquipmentTransactionController(EquipmentTransactionService transactionService)
    {
        _transactionService = transactionService;
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(int id)
    {
        var transaction = await _transactionService.GetTransactionById(id);
        if (transaction == null)
            return NotFound(new
            {
                status = false,
                message = "Transaction not found"
            });

        return Ok(new
        {
            status = true,
            message = "Successfully Retrieved",
            data = transaction
        });
    }

    [HttpPost("borrow")]
    public async Task<IActionResult> Borrow([FromBody] EquipmentTransaction transaction)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var result = await _transactionService.BorrowEquipment(transaction, userId);

        if (result.data == null)
        {
            return BadRequest(new
            {
                status = false,
                message = result.message
            });
        }

        return CreatedAtAction(nameof(GetById), new { id = result.data.equipment_transaction_id }, new
        {
            status = true,
            message = "Successfully Borrowed",
            data = result.data
        });
    }

    [HttpPost("return")]
    public async Task<IActionResult> Return([FromBody] EquipmentTransaction transaction)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var result = await _transactionService.ReturnEquipment(transaction, userId);

        if (!result.success)
        {
            return BadRequest(new
            {
                status = false,
                message = result.message
            });
        }

        return Ok(new
        {
            status = true,
            message = "Successfully Returned",
            data = result.data
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, [FromBody] EquipmentTransaction updatedTransaction)
    {
        var userId = JwtHelper.GetUserIdFromToken(User);
        var result = await _transactionService.UpdateTransaction(id, updatedTransaction, userId);

        if (!result.success)
        {
            return NotFound(new
            {
                status = false,
                message = result.message
            });
        }

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
        var result = await _transactionService.DeleteTransaction(id, userId);

        if (!result.success)
        {
            return NotFound(new
            {
                status = false,
                message = result.message
            });
        }

        return Ok(new
        {
            status = true,
            message = "Successfully Deleted"
        });
    }
}
