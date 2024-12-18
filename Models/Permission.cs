using System.ComponentModel.DataAnnotations;

public class Permission
{
    [Key]
    public int permission_id { get; set; }

    public string permission_code { get; set; } = string.Empty;

    [MaxLength(50, ErrorMessage = "Permission Name must be less than 50 characters")]
    public string permission { get; set; } = string.Empty;

    [MaxLength(255, ErrorMessage = "Description must be less than 255 characters")]
    public string description { get; set; } = string.Empty;

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
