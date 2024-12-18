using System.ComponentModel.DataAnnotations;

public class Rank
{
    [Key]
    public int rank_id { get; set; }

    public string rank_code { get; set; } = string.Empty;

    [MaxLength(255, ErrorMessage = "Full Rank must be less than 255 characters")]
    public string full_rank { get; set; } = string.Empty;

    [MaxLength(255, ErrorMessage = "Short Rank must be less than 255 characters")]
    public string short_rank { get; set; } = string.Empty;

    [Required(ErrorMessage = "Sequence is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Sequence must be greater than 0")]
    public int sequence { get; set; }

    public DateTime created_at { get; set; } = DateTime.UtcNow;

    public DateTime updated_at { get; set; } = DateTime.UtcNow;

    public int created_by { get; set; }

    public int updated_by { get; set; }
    
    public bool is_deleted { get; set; } = false;
}
