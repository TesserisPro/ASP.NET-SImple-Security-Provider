﻿//// The MIT License (MIT)
//// 
//// Copyright (c) 2014 Tesseris Pro LLC
////     
//// Permission is hereby granted, free of charge, to any person obtaining a copy
//// of this software and associated documentation files (the "Software"), to deal
//// in the Software without restriction, including without limitation the rights
//// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//// copies of the Software, and to permit persons to whom the Software is
//// furnished to do so, subject to the following conditions:
////     
//// The above copyright notice and this permission notice shall be included in
//// all copies or substantial portions of the Software.
////     
//// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//// THE SOFTWARE.

using System.Security.Principal;

namespace Tesseris.Web.SimpleSecurity
{
    /// <summary>
    /// Not authenticated unknown user
    /// </summary>
    public class EmptyIdentity : IIdentity
    {
        /// <summary>
        /// Gets the type of authentication used.
        /// </summary>
        public string AuthenticationType
        {
            get { return string.Empty; }
        }

        /// <summary>
        /// Gets a value that indicates whether the user has been authenticated.
        /// </summary>
        public bool IsAuthenticated
        {
            get { return false; }
        }

        /// <summary>
        /// Gets the name of the current user.
        /// </summary>
        public string Name
        {
            get { return string.Empty; }
        }
    }
}
