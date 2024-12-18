using System.ComponentModel.DataAnnotations;
public class Equipment
{
    public int equipment_id { get; set; }

    public string equipment_code { get; set; } = string.Empty;

    [MaxLength(50, ErrorMessage = "Equipment name must be less than 50 characters")]
    public string equipment { get; set; } = string.Empty;

    [MaxLength(255, ErrorMessage = "Description must be less than 255 characters")]
    public string description { get; set; } = string.Empty;

    [Required(ErrorMessage = "Equipment Group ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Equipment Group ID must be greater than 0")]
    public int equipment_group_id { get; set; }

    [Required(ErrorMessage = "Equipment Type ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Equipment Type ID must be greater than 0")]
    public int equipment_type_id { get; set; }

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}

