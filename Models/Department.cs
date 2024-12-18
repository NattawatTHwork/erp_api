using System;
using System.ComponentModel.DataAnnotations;

public class Department
{
    [Key]
    public int department_id { get; set; }

    [MaxLength(10, ErrorMessage = "Department Code must be less than 10 characters")]
    public string department_code { get; set; } = string.Empty;

    [MaxLength(50, ErrorMessage = "Department Name must be less than 50 characters")]
    public string department { get; set; } = string.Empty;

    [MaxLength(255, ErrorMessage = "Description must be less than 255 characters")]
    public string description { get; set; } = string.Empty;

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
