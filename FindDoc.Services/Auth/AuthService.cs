using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using FindDoc.Common.Auth;
using FindDoc.Common.Dtos.UserDto;
using FindDoc.Data.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace FindDoc.Services.Auth
{
    public class AuthService: IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthResponse> LoginAsync(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                return new AuthResponse
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    Expiration = token.ValidTo,
                    User = new UserDto
                    {
                        Email = user.Email,
                        Name = user.UserName,
                        Id = user.Id
                    }
                };
            }

            throw new Exception("Unauthorized");
        }

        public async Task<AuthResponse> RegisterPatientAsync(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                throw new Exception("User already exists!");

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) {
                throw new Exception("User creation failed! Please check user details and try again.");
            }

            if (!await _roleManager.RoleExistsAsync(UserRoles.Patient))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Patient));

            if (await _roleManager.RoleExistsAsync(UserRoles.Patient))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Patient);
            }

            return new AuthResponse { Status = "Success", Message = "User created successfully!" };
        }

        public async Task<AuthResponse> RegisterDoctorAsync(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                throw new Exception("User already exists!");

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                throw new Exception("User creation failed! Please check user details and try again.");

            if (!await _roleManager.RoleExistsAsync(UserRoles.Doctor))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Doctor));
            
            if (await _roleManager.RoleExistsAsync(UserRoles.Doctor))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Doctor);
            }

            return new AuthResponse { Status = "Success", Message = "User created successfully!" };
        }
    }
}
