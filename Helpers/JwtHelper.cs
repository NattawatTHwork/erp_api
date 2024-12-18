using System.Security.Claims;

namespace erp_api.Helpers
{
    public static class JwtHelper
    {
        /// <summary>
        /// ดึง user_id จาก token ที่เข้ารหัสใน ClaimsPrincipal
        /// </summary>
        /// <param name="user">ClaimsPrincipal ของ User</param>
        /// <returns>user_id ในรูปแบบ int</returns>
        public static int GetUserIdFromToken(ClaimsPrincipal user)
        {
            var userIdClaim = user.FindFirst("user_id")?.Value;
            if (int.TryParse(userIdClaim, out int userId))
            {
                return userId;
            }
            throw new UnauthorizedAccessException("User ID not found in token.");
        }
    }
}
