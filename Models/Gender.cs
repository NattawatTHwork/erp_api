using System.ComponentModel.DataAnnotations;

public class Gender
{
    [Key]
    public int gender_id { get; set; }

    public string gender_code { get; set; } = string.Empty;

    [MaxLength(50, ErrorMessage = "Gender Name must be less than 50 characters")]
    public string gender { get; set; } = string.Empty;

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
