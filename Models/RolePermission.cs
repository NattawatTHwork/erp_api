using System.ComponentModel.DataAnnotations;

public class RolePermission
{
    [Key]
    public int role_permission_id { get; set; }

    [Required(ErrorMessage = "Role ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Role ID must be a valid ID greater than 0")]
    public int role_id { get; set; }

    [Required(ErrorMessage = "Permission ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Permission ID must be a valid ID greater than 0")]
    public int permission_id { get; set; }
    
    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }

    public bool is_deleted { get; set; } = false;
}
