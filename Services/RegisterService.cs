using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class RegisterService
    {
        private readonly ErpDbContext _context;

        public RegisterService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<bool> CheckIfEmailExists(string email)
        {
            return await _context.tb_users
                .AnyAsync(u => u.email == email && !u.is_deleted);
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

        public async Task<User> RegisterUser(UserRegisterRequest request)
        {
            string hashedPassword = HashPassword(request.user_password);

            var newUser = new User
            {
                user_code = request.user_code,
                email = request.email,
                user_password = hashedPassword,
                firstname = request.firstname,
                lastname = request.lastname,
                gender_id = request.gender_id,
                role_id = request.role_id,
                department_id = request.department_id,
                rank_id = request.rank_id,
                user_status_id = request.user_status_id,
                phone_number = request.phone_number,
                birthdate = request.birthdate.ToUniversalTime(),
                created_by = request.created_by,
                created_at = DateTime.UtcNow,
                updated_by = request.created_by,
                updated_at = DateTime.UtcNow
            };

            _context.tb_users.Add(newUser);
            await _context.SaveChangesAsync();

            return newUser;
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(password);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}
