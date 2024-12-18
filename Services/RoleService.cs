using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class RoleService
    {
        private readonly ErpDbContext _context;

        public RoleService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<Role>> GetAllRoles()
        {
            return await _context.tb_roles
                .Where(r => !r.is_deleted)
                .ToListAsync();
        }

        public async Task<Role?> GetRoleById(int id)
        {
            return await _context.tb_roles
                .FirstOrDefaultAsync(r => r.role_id == id && !r.is_deleted);
        }

        public async Task<string> GenerateRoleCode()
        {
            var latestRole = await _context.tb_roles
                .OrderByDescending(r => r.role_code)
                .FirstOrDefaultAsync();
            
            string newCode = "ROE0000001";
            if (latestRole != null && !string.IsNullOrEmpty(latestRole.role_code))
            {
                var match = Regex.Match(latestRole.role_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"ROE{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddRole(Role role)
        {
            _context.tb_roles.Add(role);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRole(Role existingRole, Role updatedRole, int userId)
        {
            existingRole.role = updatedRole.role;
            existingRole.description = updatedRole.description;
            existingRole.updated_by = userId;
            existingRole.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteRole(Role role, int userId)
        {
            role.is_deleted = true;
            role.updated_by = userId;
            role.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
