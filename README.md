ASP.NET-SImple-Security-Provider
================================

Are you tired of overcomplicated membership or security providers that requires a spaceship to be configured to verify login/password? So am I. Please get these few classes register one HttpModule in web.config call SecurityContext.Initialize(new SimpleSecurityProvider("&lt;name of connection string>")) and be happy! DB will be created automatically. Will add more providers soon but will keep it simple…
