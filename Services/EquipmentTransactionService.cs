using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class EquipmentTransactionService
    {
        private readonly ErpDbContext _context;

        public EquipmentTransactionService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<EquipmentTransaction?> GetTransactionById(int id)
        {
            return await _context.tb_equipment_transactions
                .FirstOrDefaultAsync(t => t.equipment_transaction_id == id && !t.is_deleted);
        }

        public async Task<(bool success, string message, EquipmentTransaction? data)> BorrowEquipment(EquipmentTransaction transaction, int userId)
        {
            var existingTransaction = await _context.tb_equipment_transactions
                .Where(t => t.equipment_id == transaction.equipment_id && t.status_equipment_transaction == 1 && !t.is_deleted)
                .FirstOrDefaultAsync();

            if (existingTransaction != null)
            {
                return (false, "This equipment is currently borrowed.", null);
            }

            string newCode = await GenerateTransactionCode();

            transaction.equipment_transaction_code = newCode;
            transaction.status_equipment_transaction = 1;
            transaction.equipment_transaction_timestamp = DateTime.UtcNow;
            transaction.updated_by = userId;
            transaction.updated_at = DateTime.UtcNow;

            _context.tb_equipment_transactions.Add(transaction);
            await _context.SaveChangesAsync();

            return (true, "Successfully Borrowed", transaction);
        }

        public async Task<(bool success, string message, EquipmentTransaction? data)> ReturnEquipment(EquipmentTransaction transaction, int userId)
        {
            var existingTransaction = await _context.tb_equipment_transactions
                .Where(t => t.equipment_id == transaction.equipment_id && t.status_equipment_transaction == 1 && !t.is_deleted)
                .FirstOrDefaultAsync();

            if (existingTransaction == null)
            {
                return (false, "This equipment is not currently borrowed.", null);
            }

            transaction.equipment_transaction_code = existingTransaction.equipment_transaction_code;
            transaction.status_equipment_transaction = 2;
            transaction.equipment_transaction_timestamp = DateTime.UtcNow;
            transaction.updated_by = userId;
            transaction.updated_at = DateTime.UtcNow;

            _context.tb_equipment_transactions.Add(transaction);
            await _context.SaveChangesAsync();

            return (true, "Successfully Returned", transaction);
        }

        public async Task<(bool success, string message)> UpdateTransaction(int id, EquipmentTransaction updatedTransaction, int userId)
        {
            var transaction = await _context.tb_equipment_transactions.FindAsync(id);
            
            if (transaction == null) 
                return (false, "Transaction not found");

            transaction.note = updatedTransaction.note;
            transaction.updated_by = userId;
            transaction.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return (true, "Successfully Updated");
        }

        public async Task<(bool success, string message)> DeleteTransaction(int id, int userId)
        {
            var transaction = await _context.tb_equipment_transactions.FindAsync(id);
            
            if (transaction == null) 
                return (false, "Transaction not found");

            transaction.is_deleted = true;
            transaction.updated_by = userId;
            transaction.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return (true, "Successfully Deleted");
        }

        private async Task<string> GenerateTransactionCode()
        {
            var latestTransaction = await _context.tb_equipment_transactions
                .OrderByDescending(t => t.equipment_transaction_code)
                .FirstOrDefaultAsync();
            
            string newCode = "TRX0000001";
            if (latestTransaction != null && !string.IsNullOrEmpty(latestTransaction.equipment_transaction_code))
            {
                var match = Regex.Match(latestTransaction.equipment_transaction_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"TRX{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }
    }
}
