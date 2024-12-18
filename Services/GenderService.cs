using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class GenderService
    {
        private readonly ErpDbContext _context;

        public GenderService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<Gender>> GetAllGenders()
        {
            return await _context.tb_genders
                .Where(g => !g.is_deleted)
                .ToListAsync();
        }

        public async Task<Gender?> GetGenderById(int id)
        {
            return await _context.tb_genders
                .FirstOrDefaultAsync(g => g.gender_id == id && !g.is_deleted);
        }

        public async Task<string> GenerateGenderCode()
        {
            var latestGender = await _context.tb_genders
                .OrderByDescending(g => g.gender_code)
                .FirstOrDefaultAsync();
            
            string newCode = "GDR0000001";
            if (latestGender != null && !string.IsNullOrEmpty(latestGender.gender_code))
            {
                var match = Regex.Match(latestGender.gender_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"GDR{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddGender(Gender gender)
        {
            _context.tb_genders.Add(gender);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateGender(Gender existingGender, Gender updatedGender, int userId)
        {
            existingGender.gender = updatedGender.gender;
            existingGender.updated_by = userId;
            existingGender.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteGender(Gender gender, int userId)
        {
            gender.is_deleted = true;
            gender.updated_by = userId;
            gender.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
