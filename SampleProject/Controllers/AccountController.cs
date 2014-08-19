using SampleProject.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Tesseris.Web.SimpleSecurity;

namespace SampleProject.Controllers
{
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(Login login, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                if (SimpleSecurityProvider.Current.Login(login.Name, login.Password, login.RememberMe, 1))
                {
                    return Redirect(returnUrl ?? "/");
                }

                ModelState.AddModelError("", "Invalid username or password.");
            }
            return View();
        }

        public ActionResult Logout()
        {
            SimpleSecurityProvider.Current.Logout();
            return Redirect("/");
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(User user)
        {
            if (ModelState.IsValid)
            {
                if (SimpleSecurityProvider.Current.Register(user.Name, user.Password, user.Roles))
                {
                    return RedirectToAction("Login");
                }

                ModelState.AddModelError("", "Using with such name already registered.");
            }

            return View();
        }

        public ActionResult Unregister()
        {
            SimpleSecurityProvider.Current.Unregister(User.Identity.Name);
            return Redirect("/");
        }
    }
}