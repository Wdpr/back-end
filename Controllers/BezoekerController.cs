using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Laak.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Laak.Controllers;

[ApiController]
[Route("api/[controller]")]
public class BezoekerController : ControllerBase
{
    private UserManager<IdentityUser> userManager;
    private SignInManager<IdentityUser> signInManager;
    private IConfiguration configuration;

    public BezoekerController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.configuration = configuration;
    }

    [Authorize]
    [HttpGet("{id}")]
    public async Task<IActionResult> GetBezoekers(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user == null) return NotFound();
        return Ok(user);
    }

    [HttpPost]
    [Route("registreer")]
    public async Task<IActionResult> RegistreerBezoeker(RegistreerModel registreerModel)
    {
        var bezoeker = new Bezoeker
        {
            Email = registreerModel.Email,
            UserName = registreerModel.Gebruikersnaam,
            PasswordHash = registreerModel.Wachtwoord,
            Voorkeuren = "Komedie,Musical,Cabaret,Dans,Zang,Kindertheater,Drama"
        };
        var resultaat = await userManager.CreateAsync(bezoeker, bezoeker.PasswordHash);
        return resultaat.Succeeded ? StatusCode(201) : new BadRequestObjectResult(resultaat);
    }

    [HttpPost]
    [Route("registreer/medewerker")]
    public async Task<IActionResult> RegistreerMedewerker(RegistreerModel registreerModel)
    {
        var medewerker = new Medewerker
        {
            Email = registreerModel.Email,
            UserName = registreerModel.Gebruikersnaam,
            PasswordHash = registreerModel.Wachtwoord,
            Functie = registreerModel.Functie,
        };
        var resultaat = await userManager.CreateAsync(medewerker, medewerker.PasswordHash);
        return resultaat.Succeeded ? Ok() : new BadRequestObjectResult(resultaat);
    }


    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> login(LoginModel loginModel)
    {
        var _user = await userManager.FindByEmailAsync(loginModel.Email);
        if (_user != null)
            if (await userManager.CheckPasswordAsync(_user, loginModel.Wachtwoord))
            {
                var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));

                var signingCredentials = new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
                var claims = new List<Claim> { new Claim(ClaimTypes.Name, _user.UserName) };
                var roles = await userManager.GetRolesAsync(_user);
                foreach (var role in roles)
                    claims.Add(new Claim(ClaimTypes.Role, role));
                var tokenOptions = new JwtSecurityToken
                (
                    issuer: configuration["Jwt:Issuer"],
                    audience: configuration["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(100),
                    signingCredentials: signingCredentials
                );
                var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
                return Ok(new { token = token, gebruiker = _user });
            }
        return Unauthorized();
    }

    [HttpPost]
    [Route("update/email")]
    public async Task<IActionResult> UpdateBezoekerEmail(UpdateEmailModel updateModel)
    {
        var bezoeker = await userManager.FindByEmailAsync(updateModel.CurrentEmail);
        if (bezoeker == null)
        {
            return NotFound();
        }
        bezoeker.Email = updateModel.NewEmail;
        var result = await userManager.UpdateAsync(bezoeker);
        if (result.Succeeded)
            return NoContent();
        else
            return new BadRequestObjectResult(result);
    }

    public class UpdateEmailModel
    {
        public string CurrentEmail { get; set; }
        public string NewEmail { get; set; }
    }

    [HttpPost]
    [Route("voegVoorkeurenToe")]
    public async Task<IActionResult> VoegVoorkeurenToe(VoorkeurenModel voorkeurenModel)
    {
        var user = await userManager.FindByEmailAsync(voorkeurenModel.Email);
        Bezoeker bezoeker = (Bezoeker)user;
        if (bezoeker == null)
        {
            return NotFound();
        }
        bezoeker.Voorkeuren = voorkeurenModel.Voorkeuren;
        var result = await userManager.UpdateAsync(bezoeker);
        if (result.Succeeded)
            return Ok();
        else
            return new BadRequestObjectResult(result);
    }

    public class VoorkeurenModel
    {
        public string Email { get; set; }
        public string Voorkeuren { get; set; }
    }

    public class LoginModel
    {
        [Required(ErrorMessage = "Email is verplicht")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Wachtwoord is verplicht")]
        public string Wachtwoord { get; set; }
    }

    public class RegistreerModel
    {
        public string Gebruikersnaam { get; set; }
        public string Email { get; set; }
        public string Wachtwoord { get; set; }
        public string Functie { get; set; }
    }
}