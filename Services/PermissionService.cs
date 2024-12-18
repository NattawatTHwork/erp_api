using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class PermissionService
    {
        private readonly ErpDbContext _context;

        public PermissionService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<Permission>> GetAllPermissions()
        {
            return await _context.tb_permissions
                .Where(p => !p.is_deleted)
                .ToListAsync();
        }

        public async Task<Permission?> GetPermissionById(int id)
        {
            return await _context.tb_permissions
                .FirstOrDefaultAsync(p => p.permission_id == id && !p.is_deleted);
        }

        public async Task<string> GeneratePermissionCode()
        {
            var latestPermission = await _context.tb_permissions
                .OrderByDescending(p => p.permission_code)
                .FirstOrDefaultAsync();
            
            string newCode = "PMS0000001";
            if (latestPermission != null && !string.IsNullOrEmpty(latestPermission.permission_code))
            {
                var match = Regex.Match(latestPermission.permission_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"PMS{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddPermission(Permission permission)
        {
            _context.tb_permissions.Add(permission);
            await _context.SaveChangesAsync();
        }

        public async Task UpdatePermission(Permission existingPermission, Permission updatedPermission, int userId)
        {
            existingPermission.permission = updatedPermission.permission;
            existingPermission.description = updatedPermission.description;
            existingPermission.updated_by = userId;
            existingPermission.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeletePermission(Permission permission, int userId)
        {
            permission.is_deleted = true;
            permission.updated_by = userId;
            permission.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
