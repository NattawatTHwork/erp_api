public class UserRegisterRequest
{
    public string user_code { get; set; } = string.Empty;
    public string email { get; set; } = string.Empty;
    public string user_password { get; set; } = string.Empty;
    public string firstname { get; set; } = string.Empty;
    public string lastname { get; set; } = string.Empty;
    public int gender_id { get; set; }
    public int role_id { get; set; }
    public int department_id { get; set; }
    public int rank_id { get; set; }
    public int user_status_id { get; set; }
    public string phone_number { get; set; } = string.Empty;
    public DateTime birthdate { get; set; }
    public int created_by { get; set; }
}
