using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;

namespace erp_api.Services
{
    public class RankService
    {
        private readonly ErpDbContext _context;

        public RankService(ErpDbContext context)
        {
            _context = context;
        }

        public async Task<List<Rank>> GetAllRanks()
        {
            return await _context.tb_ranks
                .Where(r => !r.is_deleted)
                .ToListAsync();
        }

        public async Task<Rank?> GetRankById(int id)
        {
            return await _context.tb_ranks
                .FirstOrDefaultAsync(r => r.rank_id == id && !r.is_deleted);
        }

        public async Task<string> GenerateRankCode()
        {
            var latestRank = await _context.tb_ranks
                .OrderByDescending(r => r.rank_code)
                .FirstOrDefaultAsync();
            
            string newCode = "RAK0000001";
            if (latestRank != null && !string.IsNullOrEmpty(latestRank.rank_code))
            {
                var match = Regex.Match(latestRank.rank_code, @"\d+");
                if (match.Success)
                {
                    int latestNumber = int.Parse(match.Value);
                    newCode = $"RAK{(latestNumber + 1).ToString("D7")}";
                }
            }
            return newCode;
        }

        public async Task AddRank(Rank rank)
        {
            _context.tb_ranks.Add(rank);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateRank(Rank existingRank, Rank updatedRank, int userId)
        {
            existingRank.full_rank = updatedRank.full_rank;
            existingRank.short_rank = updatedRank.short_rank;
            existingRank.sequence = updatedRank.sequence;
            existingRank.updated_by = userId;
            existingRank.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }

        public async Task SoftDeleteRank(Rank rank, int userId)
        {
            rank.is_deleted = true;
            rank.updated_by = userId;
            rank.updated_at = DateTime.UtcNow;

            await _context.SaveChangesAsync();
        }
    }
}
