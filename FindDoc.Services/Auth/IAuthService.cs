using System;
using System.Threading.Tasks;
using FindDoc.Common.Auth;

namespace FindDoc.Services.Auth
{
    public interface IAuthService
    {
        public Task<AuthResponse> RegisterPatientAsync(RegisterModel model);
        public Task<AuthResponse> RegisterDoctorAsync(RegisterModel model);
    }
}
