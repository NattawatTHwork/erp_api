using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

public class PermissionMiddleware
{
    private readonly RequestDelegate _next;

    public PermissionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ErpDbContext dbContext)
    {
        // 🔥 ตรวจสอบ Endpoint ก่อน ถ้าไม่เจอให้ผ่านไป
        var endpoint = context.GetEndpoint();
        if (endpoint == null)
        {
            await _next(context); 
            return;
        }

        // 🔥 ถ้า Endpoint มี AllowAnonymous ให้ข้าม middleware นี้
        var allowAnonymous = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute>();
        if (allowAnonymous != null)
        {
            await _next(context); 
            return;
        }

        // 🔥 ดึงข้อมูลจาก Header (Authorization และ Permission)
        if (!context.Request.Headers.TryGetValue("Authorization", out StringValues tokenValues) ||
            !context.Request.Headers.TryGetValue("Permission", out StringValues permissionIdValues))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new 
            { 
                status = false, 
                message = "Authorization token or permission_id is missing." 
            });
            return;
        }

        try
        {
            string token = tokenValues.FirstOrDefault()?.Replace("Bearer ", "") ?? string.Empty;
            string permissionId = permissionIdValues.FirstOrDefault() ?? string.Empty;

            if (string.IsNullOrEmpty(token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "Authorization token is missing." 
                });
                return;
            }

            if (string.IsNullOrEmpty(permissionId))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "Permission ID is missing." 
                });
                return;
            }

            // 🔥 Decode JWT Token
            var handler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken;

            try
            {
                jwtToken = handler.ReadJwtToken(token);
            }
            catch (System.Exception)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "Invalid or expired token." 
                });
                return;
            }

            // 🔥 ดึง user_id จาก JWT Token
            var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "user_id");
            if (userIdClaim == null)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "User ID not found in the token." 
                });
                return;
            }

            if (!int.TryParse(userIdClaim.Value, out int userId))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "Invalid User ID in the token." 
                });
                return;
            }

            if (!int.TryParse(permissionId, out int permissionIdInt))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "Invalid permission_id format." 
                });
                return;
            }

            // 🔥 ค้นหา role_id ของ user_id
            var roleId = await dbContext.tb_users
                .Where(u => u.user_id == userId && !u.is_deleted)
                .Select(u => u.role_id)
                .FirstOrDefaultAsync();

            if (roleId == 0)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "No role found for this user." 
                });
                return;
            }

            // 🔥 ตรวจสอบในตาราง tb_role_permissions ว่า role_id มี permission_id หรือไม่
            var hasPermission = await dbContext.tb_role_permissions
                .AnyAsync(rp => rp.role_id == roleId && 
                                rp.permission_id == permissionIdInt && 
                                !rp.is_deleted);

            if (!hasPermission)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new 
                { 
                    status = false, 
                    message = "You do not have permission to access this resource." 
                });
                return;
            }
        }
        catch (System.Exception ex)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new 
            { 
                status = false, 
                message = $"Unauthorized: {ex.Message}" 
            });
            return;
        }

        // 🔥 ถ้าผ่านทุกอย่างแล้ว ก็ส่งต่อไปยัง request ถัดไป
        await _next(context);
    }
}
