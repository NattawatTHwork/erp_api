using System.ComponentModel.DataAnnotations;

public class EquipmentType
{
    public int equipment_type_id { get; set; }

    public string equipment_type_code { get; set; } = string.Empty;

    [MaxLength(50, ErrorMessage = "Equipment Type Name must be less than 50 characters")]
    public string equipment_type { get; set; } = string.Empty;

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
