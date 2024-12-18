using Microsoft.EntityFrameworkCore;

public class ErpDbContext : DbContext
{
    public ErpDbContext(DbContextOptions<ErpDbContext> options) : base(options) { }

    public DbSet<User> tb_users { get; set; } = null!;
    public DbSet<UserStatus> tb_user_status { get; set; } = null!;
    public DbSet<Gender> tb_genders { get; set; } = null!;
    public DbSet<Role> tb_roles { get; set; } = null!;
    public DbSet<Permission> tb_permissions { get; set; } = null!;
    public DbSet<RolePermission> tb_role_permissions { get; set; } = null!;
    public DbSet<Rank> tb_ranks { get; set; } = null!;
    public DbSet<Department> tb_departments { get; set; } = null!;

    public DbSet<Equipment> tb_equipments { get; set; } = null!;
    public DbSet<EquipmentTransaction> tb_equipment_transactions { get; set; } = null!;
    public DbSet<EquipmentGroup> tb_equipment_groups { get; set; } = null!;
    public DbSet<EquipmentType> tb_equipment_types { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().ToTable("tb_users", "sc_center_users");
        modelBuilder.Entity<UserStatus>().ToTable("tb_user_status", "sc_center_users");
        modelBuilder.Entity<Gender>().ToTable("tb_genders", "sc_center_users");
        modelBuilder.Entity<Role>().ToTable("tb_roles", "sc_center_users");
        modelBuilder.Entity<Permission>().ToTable("tb_permissions", "sc_center_users");
        modelBuilder.Entity<RolePermission>().ToTable("tb_role_permissions", "sc_center_users");
        modelBuilder.Entity<Rank>().ToTable("tb_ranks", "sc_center_users");
        modelBuilder.Entity<Department>().ToTable("tb_departments", "sc_center_users");

        modelBuilder.Entity<User>().HasKey(u => u.user_id);
        modelBuilder.Entity<UserStatus>().HasKey(us => us.user_status_id);
        modelBuilder.Entity<Gender>().HasKey(g => g.gender_id);
        modelBuilder.Entity<Role>().HasKey(r => r.role_id);
        modelBuilder.Entity<Permission>().HasKey(p => p.permission_id);
        modelBuilder.Entity<RolePermission>().HasKey(rp => rp.role_permission_id);
        modelBuilder.Entity<Rank>().HasKey(r => r.rank_id);
        modelBuilder.Entity<Department>().HasKey(d => d.department_id);

        modelBuilder.Entity<User>().Property(u => u.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<UserStatus>().Property(us => us.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<Gender>().Property(g => g.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<Role>().Property(r => r.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<Permission>().Property(p => p.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<RolePermission>().Property(rp => rp.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<Rank>().Property(r => r.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<Department>().Property(d => d.is_deleted).HasDefaultValue(false);

        modelBuilder.Entity<User>()
            .HasOne<UserStatus>()
            .WithMany()
            .HasForeignKey(u => u.user_status_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<User>()
            .HasOne<Gender>()
            .WithMany()
            .HasForeignKey(u => u.gender_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<User>()
            .HasOne<Role>()
            .WithMany()
            .HasForeignKey(u => u.role_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<User>()
            .HasOne<Rank>()
            .WithMany()
            .HasForeignKey(u => u.rank_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<User>()
            .HasOne<Department>()
            .WithMany()
            .HasForeignKey(u => u.department_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Role>().HasData(
            new Role
            {
                role_id = 1,
                role_code = "ROE0000001",
                role = "Super Admin",
                description = "Super Admin",
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<Department>().HasData(
            new Department
            {
                department_id = 1,
                department_code = "DEP0000001",
                department = "Human Resources",
                description = "Human Resources",
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<Rank>().HasData(
            new Rank
            {
                rank_id = 1,
                rank_code = "RAK0000001",
                full_rank = "Mister",
                short_rank = "Mr.",
                sequence = 1,
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<Gender>().HasData(
            new Gender
            {
                gender_id = 1,
                gender_code = "GDR0000001",
                gender = "Male",
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<UserStatus>().HasData(
            new UserStatus
            {
                user_status_id = 1,
                user_status_code = "USS0000001",
                user_status = "Active",
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            },
            new UserStatus
            {
                user_status_id = 2,
                user_status_code = "USS0000002",
                user_status = "Inactive",
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<Permission>().HasData(
            new Permission
            {
                permission_id = 1,
                permission_code = "PMS0000001",
                permission = "index",
                description = "index page",
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                role_permission_id = 1,
                role_id = 1,
                permission_id = 1,
                created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                created_by = 1,
                updated_by = 1,
                is_deleted = false
            }
        );

        modelBuilder.Entity<User>().HasData(
                    new User
                    {
                        user_id = 1,
                        user_code = "USR0000001",
                        email = "superadmin@superadmin.com",
                        user_password = "jZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI=",
                        role_id = 1,
                        department_id = 1,
                        rank_id = 1,
                        firstname = "Super",
                        lastname = "Admin",
                        gender_id = 1,
                        birthdate = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                        phone_number = "0123456789",
                        recovery_code = "123456",
                        recovery_expiration = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                        created_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                        updated_at = new DateTime(2024, 01, 01, 0, 0, 0, DateTimeKind.Utc),
                        created_by = 1,
                        updated_by = 1,
                        user_status_id = 1,
                        is_deleted = false
                    }
                );

        modelBuilder.Entity<Equipment>().ToTable("tb_equipments", "sc_equipments");
        modelBuilder.Entity<EquipmentTransaction>().ToTable("tb_equipment_transactions", "sc_equipments");
        modelBuilder.Entity<EquipmentGroup>().ToTable("tb_equipment_groups", "sc_equipments");
        modelBuilder.Entity<EquipmentType>().ToTable("tb_equipment_types", "sc_equipments");

        modelBuilder.Entity<Equipment>().HasKey(e => e.equipment_id);
        modelBuilder.Entity<EquipmentTransaction>().HasKey(et => et.equipment_transaction_id);
        modelBuilder.Entity<EquipmentGroup>().HasKey(eg => eg.equipment_group_id);
        modelBuilder.Entity<EquipmentType>().HasKey(et => et.equipment_type_id);

        modelBuilder.Entity<Equipment>().Property(e => e.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<EquipmentTransaction>().Property(et => et.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<EquipmentGroup>().Property(eg => eg.is_deleted).HasDefaultValue(false);
        modelBuilder.Entity<EquipmentType>().Property(et => et.is_deleted).HasDefaultValue(false);

        modelBuilder.Entity<Equipment>()
            .HasOne<EquipmentGroup>()
            .WithMany()
            .HasForeignKey(e => e.equipment_group_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Equipment>()
            .HasOne<EquipmentType>()
            .WithMany()
            .HasForeignKey(e => e.equipment_type_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<EquipmentTransaction>()
            .HasOne<Equipment>()
            .WithMany()
            .HasForeignKey(et => et.equipment_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<EquipmentTransaction>()
            .HasOne<User>()
            .WithMany()
            .HasForeignKey(et => et.approve_user_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<EquipmentTransaction>()
            .HasOne<User>()
            .WithMany()
            .HasForeignKey(et => et.equipment_transaction_user_id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<EquipmentGroup>()
            .HasOne<Department>()
            .WithMany()
            .HasForeignKey(eg => eg.department_id)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
