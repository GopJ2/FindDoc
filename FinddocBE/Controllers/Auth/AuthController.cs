using System;
using System.Threading.Tasks;
using FindDoc.Common.Auth;
using FindDoc.Common.Dtos.UserDto;
using FindDoc.Services.Auth;
using Microsoft.AspNetCore.Mvc;

namespace FinddocBE.Controllers.Auth
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController: ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost]
        [Route("registerPatient")]
        public async Task<IActionResult> RegisterPatientAsync(RegisterModel model)
        {
            try
            {
                return Ok(await _authService.RegisterPatientAsync(model));
            }catch(Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        [HttpPost]
        [Route("registerDoctor")]
        public async Task<IActionResult> RegisterDoctorAsync(RegisterModel model)
        {
            try
            {
                return Ok(await _authService.RegisterDoctorAsync(model));
            }catch(Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> LoginAsync(LoginModel model)
        {
            try
            {
                return Ok(await _authService.LoginAsync(model));
            }catch(Exception)
            {
                return Unauthorized();
            }
        }

    }
}
