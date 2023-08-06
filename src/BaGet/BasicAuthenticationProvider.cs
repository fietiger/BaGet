using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using System.Text;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.Xml;
using System.Text.Json;

namespace BaGet
{
    [Flags]
    public enum RoleDefine
    {
        User = 1,
        Admin = 2,
    }
    public class User
    {
        public string Name { get; set; }
        public string Password { get; set; }
        public RoleDefine Role { get; set; }
    }

    public class UserRepo
    {
        public List<User> Users { get; set; } = new List<User>();
    }


    public class BasicAuthenticationProvider
    {
        private const string C_USERCREDENTIALSLIST = "UserCredentialsList";

        /// <summary>
        /// Authenticates the specified context.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="checkForSsl">if set to <c>true</c> [check for SSL].</param>
        /// <returns>Authenticated?</returns>
        public static bool Authenticate(HttpContext context, bool checkForSsl)
        {
            List<User> userCredentials = null;
            if (userCredentials == null)
            {
                userCredentials = PopulateUserCredentials();
            }
            if (checkForSsl && !context.Request.IsHttps)
            {
                return false;
            }
            if (context == null || context.Request == null || context.Request.Headers == null || context.Request.Headers.Keys == null || !context.Request.Headers.Keys.Contains("Authorization"))
            {
                return false;
            }
            string authHeader = context.Request.Headers["Authorization"];
            if (TryGetPrincipal(userCredentials, authHeader, out var principal))
            {
                
                return true;
            }
            return false;
        }

        /// <summary>
        /// Populates the user credentials from file into the cache.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>The list which is put into the cache</returns>
        private static List<User> PopulateUserCredentials()
        {
            var store_file = "App_Data/UserCredentials.json";
            var userRepo = new UserRepo();
            if (!File.Exists(store_file))
            {
                if (!Directory.Exists("App_Data"))
                {
                    Directory.CreateDirectory("App_Data");
                }
                userRepo = new UserRepo();
                userRepo.Users.Add(new User() { Name = "admin",Password="admin", Role = RoleDefine.Admin});
                var options = new JsonSerializerOptions { WriteIndented = true };
                var jsonString = JsonSerializer.Serialize(userRepo, options);
                File.WriteAllText(store_file, jsonString);
            }else
            {
                var jsonString =  File.ReadAllText(store_file);
                userRepo = JsonSerializer.Deserialize<UserRepo>(jsonString);
            }
            return userRepo.Users;
        }

        /// <summary>
        /// Tries to get the principal.
        /// </summary>
        /// <param name="userCredentials">The user credentials.</param>
        /// <param name="authHeader">The auth header.</param>
        /// <param name="principal">The principal or null.</param>
        /// <returns>Is authenticated?</returns>
        private static bool TryGetPrincipal(List<User> userCredentials, string authHeader, out IPrincipal principal)
        {
            string[] creds = ParseAuthHeader(authHeader);
            if (creds != null && TryGetPrincipal(userCredentials, creds, out principal))
            {
                return true;
            }
            principal = null;
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

        /// <summary>
        /// Tries the get principal.
        /// </summary>
        /// <param name="userCredentials">The user credentials from file.</param>
        /// <param name="creds">The creds entered by the user.</param>
        /// <param name="principal">The principal to return or null.</param>
        /// <returns>login succeeded?</returns>
        private static bool TryGetPrincipal(List<User> userCredentials, string[] creds, out IPrincipal principal)
        {
            foreach (User userCredentialString in userCredentials)
            {
                string usernameEntered = creds[0];
                string passwordEntered = creds[1];
                if (usernameEntered.ToUpper() == userCredentialString.Name.ToUpper() && passwordEntered == userCredentialString.Password)
                {
                    string[] roles = userCredentialString.Role.ToString().Split(',');
                    principal = new GenericPrincipal(new GenericIdentity(userCredentialString.Name), roles);
                    return true;
                }
            }
            principal = null;
            return false;
        }
    }
}
