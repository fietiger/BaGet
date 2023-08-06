using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Text;

namespace BaGet
{
    public class BasicAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        public BasicAuthenticationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!BasicAuthenticationProvider.Authenticate(context, checkForSsl: false))
            {
                context.Response.StatusCode = 401;
                context.Response.Headers.Add("WWW-Authenticate", "Basic");
                return;
            }

            await _next(context);
        }

        private bool Authenticate(HttpContext context, bool checkForSsl)
        {
            if (context == null || context.Request == null || context.Request.Headers == null || context.Request.Headers.Keys == null || !context.Request.Headers.Keys.Contains("Authorization"))
            {
                return false;
            }
            string authHeader = context.Request.Headers["Authorization"];
            var tmp = ParseAuthHeader(authHeader);
            if (tmp[0] == "admin" && tmp[1] == "pass")
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Parses the auth header.
        /// </summary>
        /// <param name="authHeader">The auth header.</param>
        /// <returns></returns>
        private static string[] ParseAuthHeader(string authHeader)
        {
            if (authHeader == null || authHeader.Length == 0 || !authHeader.StartsWith("Basic"))
            {
                return null;
            }
            string base64Credentials = authHeader.Substring(6);
            string[] credentials = Encoding.ASCII.GetString(Convert.FromBase64String(base64Credentials)).Split(':');
            if (credentials.Length != 2 || string.IsNullOrEmpty(credentials[0]) || string.IsNullOrEmpty(credentials[1]))
            {
                return null;
            }
            return credentials;
        }

    }

    public static class BasicAuthenticationMiddlewareExtensions
    {
        public static IApplicationBuilder UseBasicAuthentication(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<BasicAuthenticationMiddleware>();
        }
    }
}
