using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OAuthAttacks.Startup))]
namespace OAuthAttacks
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
