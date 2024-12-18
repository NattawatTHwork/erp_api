using System.ComponentModel.DataAnnotations;

public class EquipmentGroup
{
    public int equipment_group_id { get; set; }

    public string equipment_group_code { get; set; } = string.Empty;

    [MaxLength(50, ErrorMessage = "Equipment Group Name must be less than 50 characters")]
    public string equipment_group { get; set; } = string.Empty;

    [Required(ErrorMessage = "Department ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Department ID must be a valid ID")]
    public int department_id { get; set; }

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
