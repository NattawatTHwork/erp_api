using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace erp_api.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "sc_center_users");

            migrationBuilder.EnsureSchema(
                name: "sc_equipments");

            migrationBuilder.CreateTable(
                name: "tb_departments",
                schema: "sc_center_users",
                columns: table => new
                {
                    department_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    department_code = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    department = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_departments", x => x.department_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_equipment_types",
                schema: "sc_equipments",
                columns: table => new
                {
                    equipment_type_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    equipment_type_code = table.Column<string>(type: "text", nullable: false),
                    equipment_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_equipment_types", x => x.equipment_type_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_genders",
                schema: "sc_center_users",
                columns: table => new
                {
                    gender_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    gender_code = table.Column<string>(type: "text", nullable: false),
                    gender = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_genders", x => x.gender_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_permissions",
                schema: "sc_center_users",
                columns: table => new
                {
                    permission_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    permission_code = table.Column<string>(type: "text", nullable: false),
                    permission = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_permissions", x => x.permission_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_ranks",
                schema: "sc_center_users",
                columns: table => new
                {
                    rank_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    rank_code = table.Column<string>(type: "text", nullable: false),
                    full_rank = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    short_rank = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    sequence = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_ranks", x => x.rank_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_role_permissions",
                schema: "sc_center_users",
                columns: table => new
                {
                    role_permission_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    role_id = table.Column<int>(type: "integer", nullable: false),
                    permission_id = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_role_permissions", x => x.role_permission_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_roles",
                schema: "sc_center_users",
                columns: table => new
                {
                    role_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    role_code = table.Column<string>(type: "text", nullable: false),
                    role = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_roles", x => x.role_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_user_status",
                schema: "sc_center_users",
                columns: table => new
                {
                    user_status_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    user_status_code = table.Column<string>(type: "text", nullable: false),
                    user_status = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_user_status", x => x.user_status_id);
                });

            migrationBuilder.CreateTable(
                name: "tb_equipment_groups",
                schema: "sc_equipments",
                columns: table => new
                {
                    equipment_group_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    equipment_group_code = table.Column<string>(type: "text", nullable: false),
                    equipment_group = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    department_id = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_equipment_groups", x => x.equipment_group_id);
                    table.ForeignKey(
                        name: "FK_tb_equipment_groups_tb_departments_department_id",
                        column: x => x.department_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_departments",
                        principalColumn: "department_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "tb_users",
                schema: "sc_center_users",
                columns: table => new
                {
                    user_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    user_code = table.Column<string>(type: "text", nullable: false),
                    email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    user_password = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    role_id = table.Column<int>(type: "integer", nullable: false),
                    department_id = table.Column<int>(type: "integer", nullable: false),
                    rank_id = table.Column<int>(type: "integer", nullable: false),
                    firstname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    lastname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    gender_id = table.Column<int>(type: "integer", nullable: false),
                    birthdate = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    phone_number = table.Column<string>(type: "text", nullable: false),
                    recovery_code = table.Column<string>(type: "text", nullable: false),
                    recovery_expiration = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    user_status_id = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_users", x => x.user_id);
                    table.ForeignKey(
                        name: "FK_tb_users_tb_departments_department_id",
                        column: x => x.department_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_departments",
                        principalColumn: "department_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_users_tb_genders_gender_id",
                        column: x => x.gender_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_genders",
                        principalColumn: "gender_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_users_tb_ranks_rank_id",
                        column: x => x.rank_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_ranks",
                        principalColumn: "rank_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_users_tb_roles_role_id",
                        column: x => x.role_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_roles",
                        principalColumn: "role_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_users_tb_user_status_user_status_id",
                        column: x => x.user_status_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_user_status",
                        principalColumn: "user_status_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "tb_equipments",
                schema: "sc_equipments",
                columns: table => new
                {
                    equipment_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    equipment_code = table.Column<string>(type: "text", nullable: false),
                    equipment = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    description = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    equipment_group_id = table.Column<int>(type: "integer", nullable: false),
                    equipment_type_id = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<int>(type: "integer", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_equipments", x => x.equipment_id);
                    table.ForeignKey(
                        name: "FK_tb_equipments_tb_equipment_groups_equipment_group_id",
                        column: x => x.equipment_group_id,
                        principalSchema: "sc_equipments",
                        principalTable: "tb_equipment_groups",
                        principalColumn: "equipment_group_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_equipments_tb_equipment_types_equipment_type_id",
                        column: x => x.equipment_type_id,
                        principalSchema: "sc_equipments",
                        principalTable: "tb_equipment_types",
                        principalColumn: "equipment_type_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "tb_equipment_transactions",
                schema: "sc_equipments",
                columns: table => new
                {
                    equipment_transaction_id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    equipment_transaction_code = table.Column<string>(type: "text", nullable: false),
                    equipment_id = table.Column<int>(type: "integer", nullable: false),
                    approve_user_id = table.Column<int>(type: "integer", nullable: false),
                    equipment_transaction_user_id = table.Column<int>(type: "integer", nullable: false),
                    equipment_transaction_timestamp = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    status_equipment_transaction = table.Column<int>(type: "integer", nullable: false),
                    note = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    updated_by = table.Column<int>(type: "integer", nullable: false),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tb_equipment_transactions", x => x.equipment_transaction_id);
                    table.ForeignKey(
                        name: "FK_tb_equipment_transactions_tb_equipments_equipment_id",
                        column: x => x.equipment_id,
                        principalSchema: "sc_equipments",
                        principalTable: "tb_equipments",
                        principalColumn: "equipment_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_equipment_transactions_tb_users_approve_user_id",
                        column: x => x.approve_user_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_users",
                        principalColumn: "user_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_tb_equipment_transactions_tb_users_equipment_transaction_us~",
                        column: x => x.equipment_transaction_user_id,
                        principalSchema: "sc_center_users",
                        principalTable: "tb_users",
                        principalColumn: "user_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_departments",
                columns: new[] { "department_id", "created_at", "created_by", "department", "department_code", "description", "updated_at", "updated_by" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "Human Resources", "DEP0000001", "Human Resources", new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1 });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_genders",
                columns: new[] { "gender_id", "created_at", "created_by", "gender", "gender_code", "updated_at", "updated_by" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "Male", "GDR0000001", new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1 });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_permissions",
                columns: new[] { "permission_id", "created_at", "created_by", "description", "permission", "permission_code", "updated_at", "updated_by" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "index page", "index", "PMS0000001", new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1 });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_ranks",
                columns: new[] { "rank_id", "created_at", "created_by", "full_rank", "rank_code", "sequence", "short_rank", "updated_at", "updated_by" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "Mister", "RAK0000001", 1, "Mr.", new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1 });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_role_permissions",
                columns: new[] { "role_permission_id", "created_at", "created_by", "permission_id", "role_id", "updated_at", "updated_by" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, 1, 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1 });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_roles",
                columns: new[] { "role_id", "created_at", "created_by", "description", "role", "role_code", "updated_at", "updated_by" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "Super Admin", "Super Admin", "ROE0000001", new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1 });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_user_status",
                columns: new[] { "user_status_id", "created_at", "created_by", "updated_at", "updated_by", "user_status", "user_status_code" },
                values: new object[,]
                {
                    { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "Active", "USS0000001" },
                    { 2, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "Inactive", "USS0000002" }
                });

            migrationBuilder.InsertData(
                schema: "sc_center_users",
                table: "tb_users",
                columns: new[] { "user_id", "birthdate", "created_at", "created_by", "department_id", "email", "firstname", "gender_id", "lastname", "phone_number", "rank_id", "recovery_code", "recovery_expiration", "role_id", "updated_at", "updated_by", "user_code", "user_password", "user_status_id" },
                values: new object[] { 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, 1, "superadmin@superadmin.com", "Super", 1, "Admin", "0123456789", 1, "123456", new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, new DateTime(2024, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc), 1, "USR0000001", "jZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI=", 1 });

            migrationBuilder.CreateIndex(
                name: "IX_tb_equipment_groups_department_id",
                schema: "sc_equipments",
                table: "tb_equipment_groups",
                column: "department_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_equipment_transactions_approve_user_id",
                schema: "sc_equipments",
                table: "tb_equipment_transactions",
                column: "approve_user_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_equipment_transactions_equipment_id",
                schema: "sc_equipments",
                table: "tb_equipment_transactions",
                column: "equipment_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_equipment_transactions_equipment_transaction_user_id",
                schema: "sc_equipments",
                table: "tb_equipment_transactions",
                column: "equipment_transaction_user_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_equipments_equipment_group_id",
                schema: "sc_equipments",
                table: "tb_equipments",
                column: "equipment_group_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_equipments_equipment_type_id",
                schema: "sc_equipments",
                table: "tb_equipments",
                column: "equipment_type_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_users_department_id",
                schema: "sc_center_users",
                table: "tb_users",
                column: "department_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_users_gender_id",
                schema: "sc_center_users",
                table: "tb_users",
                column: "gender_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_users_rank_id",
                schema: "sc_center_users",
                table: "tb_users",
                column: "rank_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_users_role_id",
                schema: "sc_center_users",
                table: "tb_users",
                column: "role_id");

            migrationBuilder.CreateIndex(
                name: "IX_tb_users_user_status_id",
                schema: "sc_center_users",
                table: "tb_users",
                column: "user_status_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "tb_equipment_transactions",
                schema: "sc_equipments");

            migrationBuilder.DropTable(
                name: "tb_permissions",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_role_permissions",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_equipments",
                schema: "sc_equipments");

            migrationBuilder.DropTable(
                name: "tb_users",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_equipment_groups",
                schema: "sc_equipments");

            migrationBuilder.DropTable(
                name: "tb_equipment_types",
                schema: "sc_equipments");

            migrationBuilder.DropTable(
                name: "tb_genders",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_ranks",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_roles",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_user_status",
                schema: "sc_center_users");

            migrationBuilder.DropTable(
                name: "tb_departments",
                schema: "sc_center_users");
        }
    }
}
