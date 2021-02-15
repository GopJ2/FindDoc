﻿using System;
using FindDoc.Common.Dtos.UserDto;

namespace FindDoc.Common.Auth
{
    public class AuthResponse
    { 
        public string Status { get; set; }

        public string Message { get; set; }

        #nullable enable
        public string? Token { get; set; }

        public DateTime? Expiration { get; set; }

        public UserDto? User { get; set; }
    }
}
