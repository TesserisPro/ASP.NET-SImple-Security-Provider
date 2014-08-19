using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace SampleProject.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        // GET: Account
        public ActionResult Index()
        {
            return View();
        }
    }
}