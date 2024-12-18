using System.ComponentModel.DataAnnotations;

public class EquipmentTransaction
{
    [Key]
    public int equipment_transaction_id { get; set; }

    public string equipment_transaction_code { get; set; } = string.Empty;

    [Required(ErrorMessage = "Equipment ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Equipment ID must be a valid ID")]
    public int equipment_id { get; set; }

    [Required(ErrorMessage = "Approve User ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Approve User ID must be a valid ID")]
    public int approve_user_id { get; set; }

    [Required(ErrorMessage = "Equipment Transaction User ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Equipment Transaction User ID must be a valid ID")]
    public int equipment_transaction_user_id { get; set; }

    public DateTime equipment_transaction_timestamp { get; set; } = DateTime.UtcNow;

    [Required(ErrorMessage = "Status Equipment Transaction is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Status Equipment Transaction must be a valid ID")]
    public int status_equipment_transaction { get; set; }

    [MaxLength(255, ErrorMessage = "Note must be less than 255 characters")]
    public string note { get; set; } = string.Empty;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
