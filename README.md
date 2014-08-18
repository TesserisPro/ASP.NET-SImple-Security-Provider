ASP.NET Simple Security Provider
================================

Are you tired of overcomplicated membership or security providers that requires a spaceship to be configured to verify login/password? So am I. Please get these few classes register one HttpModule in web.config call `SecurityContext.Initialize(new SimpleSecurityProvider("name_of_connection_string"))` and be happy! DB will be created automatically. 

To add module in integrated mode use following
```
<system.webServer>
  <modules>
    <add name="SimpleSecurity" 
         type="Tesseris.Web.SimpleSecurity.SimpleSecurityModule, 
         Tesseris.Web.SimpleSecurity" />
  </modules>
</system.webServer>
```

Will add more providers and add sample soon but will keep it simple…


