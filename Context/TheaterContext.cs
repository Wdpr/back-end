using Microsoft.EntityFrameworkCore;
using Laak.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace Laak.Context;

public class TheaterContext : IdentityDbContext
{
    public TheaterContext(DbContextOptions<TheaterContext> options) : base(options) { }

    public DbSet<Voorstelling> Voorstellingen { get; set; }
    public DbSet<Artiest> Artiesten { get; set; }
    public DbSet<Bezoeker> Bezoekers { get; set; }
    public DbSet<Medewerker> Medewerkers { get; set; }
    public DbSet<Reservering> Reserveringen { get; set; }
    public DbSet<Zaal> Zalen { get; set; }
    public DbSet<Donatie> Donaties { get; set; }
}

