using System.ComponentModel.DataAnnotations;

public class User
{
    [Key]
    public int user_id { get; set; }

    public string user_code { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid Email format")]
    [MaxLength(255, ErrorMessage = "Email must be less than 255 characters")]
    public string email { get; set; } = string.Empty;

    [Required(ErrorMessage = "User Password is required")]
    [MaxLength(255, ErrorMessage = "User Password must be less than 255 characters")]
    public string user_password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Role ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Role ID must be a valid ID")]
    public int role_id { get; set; }

    [Required(ErrorMessage = "Department ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Department ID must be a valid ID")]
    public int department_id { get; set; }

    public int rank_id { get; set; }

    [Required(ErrorMessage = "Firstname is required")]
    [MaxLength(255, ErrorMessage = "Firstname must be less than 255 characters")]
    public string firstname { get; set; } = string.Empty;

    [Required(ErrorMessage = "Lastname is required")]
    [MaxLength(255, ErrorMessage = "Lastname must be less than 255 characters")]
    public string lastname { get; set; } = string.Empty;

    public int gender_id { get; set; }

    public DateTime birthdate { get; set; }

    public string phone_number { get; set; } = string.Empty;

    public string recovery_code { get; set; } = string.Empty;

    public DateTime? recovery_expiration { get; set; }

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }

    [Required(ErrorMessage = "User Status ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "User Status ID must be a valid ID")]
    public int user_status_id { get; set; }

    public bool is_deleted { get; set; } = false;
}
