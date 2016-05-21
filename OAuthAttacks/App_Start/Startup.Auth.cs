using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using OAuthAttacks.Models;
using Microsoft.Owin.Security.Facebook;
using System.Net;
using System.IO;
using System.Web;
using System.Threading.Tasks;
using System.Runtime.Serialization.Json;
using Newtonsoft.Json.Linq;

namespace OAuthAttacks
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            var options =
              new FacebookAuthenticationOptions()
              {
                  AppId = "1779088025653772",
                  AppSecret = "2fa417eb090b2633b280ac38727fa8fa",
                  Provider = new MyFacebookAuthenticationProvider()
              };

            options.Scope.Add("user_birthday");
            options.Scope.Add("user_location");
            options.Scope.Add("user_relationships");
            options.Scope.Add("user_tagged_places");

            app.UseFacebookAuthentication(options);

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "548084605587-9jntgi4ulmatkptp8fa0j2o00ggp4517.apps.googleusercontent.com",
                ClientSecret = "CnIP3iqW4h7-KJpSG6A_a7l8"
            });
        }
    }

    public class MyFacebookAuthenticationProvider : FacebookAuthenticationProvider
    {
        public override void ApplyRedirect(FacebookApplyRedirectContext context)
        {
            base.ApplyRedirect(context);
        }

        public override Task Authenticated(FacebookAuthenticatedContext context)
        {
            // Retrieve the username
            string facebookUserName = context.UserName;

            // You can even retrieve the full JSON-serialized user
            var serializedUser = context.User;

            return base.Authenticated(context);
        }

        public override Task ReturnEndpoint(FacebookReturnEndpointContext context)
        {
            if (context.Identity == null)
            {
                var dr = context.Request.QueryString;
                string code = dr.Value.Split('&')[0].Split('=')[1];

                string endpoint = "https://graph.facebook.com/oauth/access_token";
                string url = string.Format("{0}?grant_type={1}&code={2}&redirect_uri={3}&client_id={4}&client_secret={5}", endpoint, "authorization_code", code, "https://localhost:44302/signin-facebook", "1779088025653772", "2fa417eb090b2633b280ac38727fa8fa");

                string result;
                using (WebResponse resp = WebRequest.Create(url).GetResponse())
                {
                    StreamReader reader = new StreamReader(resp.GetResponseStream());
                    result = reader.ReadToEnd();
                }

                string accessToken = result.Split('&')[0].Split('=')[1];

                InvokeGraphAPI(accessToken);
            }
            else
            {
                return base.ReturnEndpoint(context);
            }

            return Task.FromResult<object>(null);
        }

        private void InvokeGraphAPI(string accessToken)
        {
            string id = GeId(accessToken);

            HttpContext.Current.Session["id"] = id;
            HttpContext.Current.Session["accessToken"] = accessToken;
        }

        private string GeId(string accessToken)
        {
            HttpWebRequest request = WebRequest.Create("https://graph.facebook.com/v2.6/me?access_token=" + accessToken) as HttpWebRequest;
            using (HttpWebResponse response = request.GetResponse() as HttpWebResponse)
            {
                StreamReader reader = new StreamReader(response.GetResponseStream());
                JObject obj = JObject.Parse(reader.ReadToEnd());
                return obj["id"].ToString();
            }
        }
    }

    public class FBMe
    {
        public string Name { set; get; }
        public string Id { set; get; }
    }
}