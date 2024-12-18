using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class EquipmentGroupService
    {
        private readonly ErpDbContext _context;

        public EquipmentGroupService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<EquipmentGroup>> GetAllEquipmentGroups()
        {
            return await _context.tb_equipment_groups
                .Where(eg => !eg.is_deleted)
                .ToListAsync();
        }

        public async Task<List<EquipmentGroup>> GetEquipmentGroupsByDepartmentId(int departmentId)
        {
            return await _context.tb_equipment_groups
                .Where(eg => eg.department_id == departmentId && !eg.is_deleted)
                .ToListAsync();
        }

        public async Task<EquipmentGroup?> GetEquipmentGroupById(int id)
        {
            return await _context.tb_equipment_groups
                .FirstOrDefaultAsync(eg => eg.equipment_group_id == id && !eg.is_deleted);
        }

        public async Task<string> GenerateEquipmentGroupCode()
        {
            var latestEquipmentGroup = await _context.tb_equipment_groups
                .OrderByDescending(eg => eg.equipment_group_code)
                .FirstOrDefaultAsync();

            string newCode = "EQC0000001";
            if (latestEquipmentGroup != null && !string.IsNullOrEmpty(latestEquipmentGroup.equipment_group_code))
            {
                var match = Regex.Match(latestEquipmentGroup.equipment_group_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"EQC{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddEquipmentGroup(EquipmentGroup equipmentGroup)
        {
            _context.tb_equipment_groups.Add(equipmentGroup);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateEquipmentGroup(EquipmentGroup existingEquipmentGroup, EquipmentGroup updatedEquipmentGroup, int userId)
        {
            existingEquipmentGroup.equipment_group = updatedEquipmentGroup.equipment_group;
            existingEquipmentGroup.updated_by = userId;
            existingEquipmentGroup.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteEquipmentGroup(EquipmentGroup equipmentGroup, int userId)
        {
            equipmentGroup.is_deleted = true;
            equipmentGroup.updated_by = userId;
            equipmentGroup.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
