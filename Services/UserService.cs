using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class UserService
    {
        private readonly ErpDbContext _context;

        public UserService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<User>> GetAllUsers()
        {
            return await _context.tb_users
                .Where(u => !u.is_deleted)
                .ToListAsync();
        }

        public async Task<User?> GetUserById(int id)
        {
            return await _context.tb_users
                .FirstOrDefaultAsync(u => u.user_id == id && !u.is_deleted);
        }

        public async Task<string> GenerateUserCode()
        {
            var latestUser = await _context.tb_users
                .OrderByDescending(u => u.user_code)
                .FirstOrDefaultAsync();
            
            string newCode = "USR0000001";
            if (latestUser != null && !string.IsNullOrEmpty(latestUser.user_code))
            {
                var match = Regex.Match(latestUser.user_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"USR{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddUser(User user)
        {
            _context.tb_users.Add(user);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateUser(User existingUser, User updatedUser, int userId)
        {
            existingUser.firstname = updatedUser.firstname;
            existingUser.lastname = updatedUser.lastname;
            existingUser.user_password = updatedUser.user_password;
            existingUser.role_id = updatedUser.role_id;
            existingUser.rank_id = updatedUser.rank_id;
            existingUser.gender_id = updatedUser.gender_id;
            existingUser.birthdate = updatedUser.birthdate;
            existingUser.phone_number = updatedUser.phone_number;
            existingUser.user_status_id = updatedUser.user_status_id;
            existingUser.updated_by = userId;
            existingUser.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteUser(User user, int userId)
        {
            user.is_deleted = true;
            user.updated_by = userId;
            user.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task ChangePassword(User user, string newPassword, int userId)
        {
            user.user_password = newPassword;
            user.updated_by = userId;
            user.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task UpdateUserProfile(User existingUser, User updatedUser, int userId)
        {
            existingUser.firstname = updatedUser.firstname;
            existingUser.lastname = updatedUser.lastname;
            existingUser.role_id = updatedUser.role_id;
            existingUser.rank_id = updatedUser.rank_id;
            existingUser.gender_id = updatedUser.gender_id;
            existingUser.birthdate = updatedUser.birthdate;
            existingUser.phone_number = updatedUser.phone_number;
            existingUser.user_status_id = updatedUser.user_status_id;
            existingUser.updated_by = userId;
            existingUser.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
