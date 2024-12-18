using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class EquipmentService
    {
        private readonly ErpDbContext _context;

        public EquipmentService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<Equipment>> GetAllEquipments()
        {
            return await _context.tb_equipments
                .Where(e => !e.is_deleted)
                .ToListAsync();
        }

        public async Task<Equipment?> GetEquipmentById(int id)
        {
            return await _context.tb_equipments
                .FirstOrDefaultAsync(e => e.equipment_id == id && !e.is_deleted);
        }

        public async Task<string> GenerateEquipmentCode()
        {
            var latestEquipment = await _context.tb_equipments
                .OrderByDescending(e => e.equipment_code)
                .FirstOrDefaultAsync();
            
            string newCode = "EQM0000001";
            if (latestEquipment != null && !string.IsNullOrEmpty(latestEquipment.equipment_code))
            {
                var match = Regex.Match(latestEquipment.equipment_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"EQM{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddEquipment(Equipment equipment)
        {
            _context.tb_equipments.Add(equipment);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateEquipment(Equipment existingEquipment, Equipment updatedEquipment, int userId)
        {
            existingEquipment.equipment = updatedEquipment.equipment;
            existingEquipment.description = updatedEquipment.description;
            existingEquipment.equipment_group_id = updatedEquipment.equipment_group_id;
            existingEquipment.equipment_type_id = updatedEquipment.equipment_type_id;
            existingEquipment.updated_by = userId;
            existingEquipment.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteEquipment(Equipment equipment, int userId)
        {
            equipment.is_deleted = true;
            equipment.updated_by = userId;
            equipment.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
