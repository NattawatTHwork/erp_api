using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class EquipmentTypeService
    {
        private readonly ErpDbContext _context;

        public EquipmentTypeService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<EquipmentType>> GetAllEquipmentTypes()
        {
            return await _context.tb_equipment_types
                .Where(et => !et.is_deleted)
                .ToListAsync();
        }

        public async Task<EquipmentType?> GetEquipmentTypeById(int id)
        {
            return await _context.tb_equipment_types
                .FirstOrDefaultAsync(et => et.equipment_type_id == id && !et.is_deleted);
        }

        public async Task<string> GenerateEquipmentTypeCode()
        {
            var latestEquipmentType = await _context.tb_equipment_types
                .OrderByDescending(et => et.equipment_type_code)
                .FirstOrDefaultAsync();
            
            string newCode = "EQT0000001";
            if (latestEquipmentType != null && !string.IsNullOrEmpty(latestEquipmentType.equipment_type_code))
            {
                var match = Regex.Match(latestEquipmentType.equipment_type_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"EQT{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddEquipmentType(EquipmentType equipmentType)
        {
            _context.tb_equipment_types.Add(equipmentType);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateEquipmentType(EquipmentType existingEquipmentType, EquipmentType updatedEquipmentType, int userId)
        {
            existingEquipmentType.equipment_type = updatedEquipmentType.equipment_type;
            existingEquipmentType.updated_by = userId;
            existingEquipmentType.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteEquipmentType(EquipmentType equipmentType, int userId)
        {
            equipmentType.is_deleted = true;
            equipmentType.updated_by = userId;
            equipmentType.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
