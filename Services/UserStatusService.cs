using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class UserStatusService
    {
        private readonly ErpDbContext _context;

        public UserStatusService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<UserStatus>> GetAllUserStatuses()
        {
            return await _context.tb_user_status
                .Where(us => !us.is_deleted)
                .ToListAsync();
        }

        public async Task<UserStatus?> GetUserStatusById(int id)
        {
            return await _context.tb_user_status
                .FirstOrDefaultAsync(us => us.user_status_id == id && !us.is_deleted);
        }

        public async Task<string> GenerateUserStatusCode()
        {
            var latestStatus = await _context.tb_user_status
                .OrderByDescending(us => us.user_status_code)
                .FirstOrDefaultAsync();
            
            string newCode = "USS0000001";
            if (latestStatus != null && !string.IsNullOrEmpty(latestStatus.user_status_code))
            {
                var match = Regex.Match(latestStatus.user_status_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"USS{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddUserStatus(UserStatus userStatus)
        {
            _context.tb_user_status.Add(userStatus);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateUserStatus(UserStatus existingStatus, UserStatus updatedStatus, int userId)
        {
            existingStatus.user_status = updatedStatus.user_status;
            existingStatus.updated_by = userId;
            existingStatus.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteUserStatus(UserStatus userStatus, int userId)
        {
            userStatus.is_deleted = true;
            userStatus.updated_by = userId;
            userStatus.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
