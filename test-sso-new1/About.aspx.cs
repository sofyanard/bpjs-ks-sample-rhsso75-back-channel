using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace test_sso_new1
{
    public partial class About : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Request.IsAuthenticated)
            {
                Response.Redirect("~/Default.aspx");
            }

            // Show Login Info Here

            string properties = "";
            var userClaims = User.Identity as System.Security.Claims.ClaimsIdentity;
            foreach (var claim in userClaims.Claims)
            {
                properties += claim.Type;
                properties += " : ";
                properties += claim.Value;
                properties += "\r\n";
            }

            string nama = userClaims?.FindFirst("name")?.Value;
            Label1.Text = nama;
            Label2.Text = properties;
        }
    }
}