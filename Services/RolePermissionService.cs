using Microsoft.EntityFrameworkCore;

namespace erp_api.Services
{
    public class RolePermissionService
    {
        private readonly ErpDbContext _context;

        public RolePermissionService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task CreateMultipleRolePermissions(int roleId, List<int> permissionIds, int userId)
        {
            var existingPermissions = await _context.tb_role_permissions
                .Where(rp => rp.role_id == roleId && !rp.is_deleted)
                .ToListAsync();

            var existingPermissionIds = existingPermissions.Select(rp => rp.permission_id).ToList();

            var permissionsToAdd = permissionIds.Except(existingPermissionIds).ToList();

            var permissionsToDelete = existingPermissionIds.Except(permissionIds).ToList();

            var newRolePermissions = permissionsToAdd.Select(permissionId => new RolePermission
            {
                role_id = roleId,
                permission_id = permissionId,
                is_deleted = false,
                created_at = DateTime.UtcNow,
                updated_at = DateTime.UtcNow,
                created_by = userId,
                updated_by = userId
            }).ToList();

            if (newRolePermissions.Any())
            {
                _context.tb_role_permissions.AddRange(newRolePermissions);
            }

            var rolePermissionsToUpdate = existingPermissions.Where(rp => permissionsToDelete.Contains(rp.permission_id)).ToList();
            foreach (var rp in rolePermissionsToUpdate)
            {
                rp.is_deleted = true;
                rp.updated_at = DateTime.UtcNow;
                rp.updated_by = userId;
            }

            await _context.SaveChangesAsync();
        }

        public async Task<List<int>> GetPermissionsByRoleId(int roleId)
        {
            return await _context.tb_role_permissions
                .Where(rp => rp.role_id == roleId && !rp.is_deleted)
                .Select(rp => rp.permission_id)
                .ToListAsync();
        }
    }
}
