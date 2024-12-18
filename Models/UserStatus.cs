using System.ComponentModel.DataAnnotations;

public class UserStatus
{
    [Key]
    public int user_status_id { get; set; }

    public string user_status_code { get; set; } = string.Empty;

    [MaxLength(255, ErrorMessage = "User Status Name must be less than 255 characters")]
    public string user_status { get; set; } = string.Empty;

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
