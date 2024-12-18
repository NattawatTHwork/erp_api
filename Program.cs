using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using erp_api.Services;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = "wwwroot",
    ApplicationName = "erp_api",
    EnvironmentName = Environments.Production
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(2095);
    options.ListenAnyIP(8443, listenOptions =>
    {
        listenOptions.UseHttps("/etc/letsencrypt/live/thaicodelab.com/fullchain.pem",
                               "/etc/letsencrypt/live/thaicodelab.com/privkey.pem");
    });
});

builder.Services.AddDbContext<ErpDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

if (builder.Environment.IsProduction())
{
    var cert = new X509Certificate2("/etc/letsencrypt/live/thaicodelab.com/fullchain.pem");

    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo("/var/www/erp_api/keys/"))
        .ProtectKeysWithCertificate(cert);
}

builder.Services.AddScoped<EquipmentGroupService>();
builder.Services.AddScoped<EquipmentService>();
builder.Services.AddScoped<EquipmentTransactionService>();
builder.Services.AddScoped<EquipmentTypeService>();
builder.Services.AddScoped<GenderService>();
builder.Services.AddScoped<LoginService>();
builder.Services.AddScoped<PermissionService>();
builder.Services.AddScoped<RankService>();
builder.Services.AddScoped<RegisterService>();
builder.Services.AddScoped<RolePermissionService>();
builder.Services.AddScoped<RoleService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<UserStatusService>();

builder.Services.AddControllers();
builder.Services.AddRouting(options => options.LowercaseUrls = true);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key must be configured.");
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = signingKey
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<PermissionMiddleware>();

app.MapControllers();

app.Run();
