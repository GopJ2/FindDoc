using System;
using System.Threading.Tasks;
using FindDoc.Common.Auth;
using FindDoc.Common.Dtos.UserDto;
using FindDoc.Data.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

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

        public async Task<AuthResponse> RegisterPatientAsync(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new AuthResponse { Status = "Error", Message = "User already exists!" };

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded) {
                return new AuthResponse { Status = "Error", Message = "User creation failed! Please check user details and try again." };
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
                return new AuthResponse { Status = "Error", Message = "User already exists!" };

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new AuthResponse { Status = "Error", Message = "User creation failed! Please check user details and try again." };

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
