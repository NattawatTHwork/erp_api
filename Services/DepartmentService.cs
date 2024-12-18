using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class DepartmentService
    {
        private readonly ErpDbContext _context;

        public DepartmentService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<Department>> GetAllDepartments()
        {
            return await _context.tb_departments
                .Where(d => !d.is_deleted)
                .ToListAsync();
        }

        public async Task<Department?> GetDepartmentById(int id)
        {
            return await _context.tb_departments
                .FirstOrDefaultAsync(d => d.department_id == id && !d.is_deleted);
        }

        public async Task<string> GenerateDepartmentCode()
        {
            var latestDepartment = await _context.tb_departments
                .OrderByDescending(d => d.department_code)
                .FirstOrDefaultAsync();

            string newCode = "DEP00001";
            if (latestDepartment != null && !string.IsNullOrEmpty(latestDepartment.department_code))
            {
                var match = Regex.Match(latestDepartment.department_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"DEP{(latestNumber + 1).ToString("D5")}";
                }
            }
            return newCode;
        }

        public async Task AddDepartment(Department department)
        {
            _context.tb_departments.Add(department);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateDepartment(Department existingDepartment, Department updatedDepartment, int userId)
        {
            existingDepartment.department = updatedDepartment.department;
            existingDepartment.description = updatedDepartment.description;
            existingDepartment.updated_by = userId;
            existingDepartment.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteDepartment(Department department, int userId)
        {
            department.is_deleted = true;
            department.updated_by = userId;
            department.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
