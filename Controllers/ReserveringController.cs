using Laak.Context;
using Laak.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Laak.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ReserveringController : ControllerBase
{
    private  TheaterContext context;
    private IConfiguration configuration;

    public ReserveringController(TheaterContext context, IConfiguration configuration)
    {
        this.context = context;
        this.configuration = configuration;
    }

    [HttpGet]
    [Authorize]
    public IEnumerable<Reservering> GetReserveringen()
    {
        return context.Reserveringen.AsQueryable().Include(r => r.Stoelen).Include(r => r.Voorstelling);
    }

    [Authorize]
    [HttpGet("{id}")]
    public IActionResult Get(int id)
    {
        var reservering = context.Reserveringen.Find(id);
        if (reservering == null)
        {
            return NotFound();
        }
        return Ok(reservering);
    }

    [Authorize]
    [HttpPost]
    public IActionResult Post([FromBody] ReserveringModel reserveringModel)
    {
        var bezoeker = context.Bezoekers.SingleOrDefault(b => b.UserName == reserveringModel.BezoekerUserName);
        var voorstelling = context.Voorstellingen.Find(reserveringModel.VoorstellingId);
        if (voorstelling == null || bezoeker == null) return NotFound();

        var reservering = new Reservering
        {
            Voorstelling = voorstelling,
            Bezoeker = bezoeker,
            TotaalPrijs = reserveringModel.TotaalPrijs,
            Stoelen = reserveringModel.Stoelen
        };
        context.Reserveringen.Add(reservering);
        context.SaveChanges();
        return Ok(reservering);
    }

    [HttpPost]
    [Route("fakepay")]
    public IActionResult fakePay([FromForm] BetalingModel betalingModel)
    {
        Console.WriteLine("fakePay");
        Console.WriteLine(betalingModel.succes);
        Console.WriteLine(betalingModel.reference);
        return Redirect(configuration["ClientUrl"]);
    }

    public class ReserveringModel
    {
        public int VoorstellingId { get; set; }
        public string BezoekerUserName { get; set; }
        public int TotaalPrijs { get; set; }
        public List<Stoel> Stoelen { get; set; }
    }

    public class BetalingModel
    {
        public string account { get; set; }
        public string succes { get; set; }
        public string reference { get; set; }
    }
}