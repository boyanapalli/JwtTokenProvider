using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtTokenProvider.Providers
{
    public static class JwtTokenProviderExtension
    {
        public static IApplicationBuilder UseJwtTokenProvider(this IApplicationBuilder builder, IOptions<JwtTokenProviderOptions> options)
        {
            return builder.UseMiddleware<JwtTokenProvider>(options);
        }
    }
}
