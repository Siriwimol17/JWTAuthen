using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
namespace JWTAuth.Models
{
    public class JWTAuthContext : IdentityDbContext<IdentityUser>
    {
        public JWTAuthContext(DbContextOptions<JWTAuthContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
