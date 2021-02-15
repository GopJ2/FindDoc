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
        public async Task<AuthResponse> RegisterPatientAsync(RegisterModel model)
        {
            return await _authService.RegisterPatientAsync(model);
        }

        [HttpPost]
        [Route("registerDoctor")]
        public async Task<AuthResponse> RegisterDoctorAsync(RegisterModel model)
        {
            return await _authService.RegisterDoctorAsync(model);
        }
    }
}
