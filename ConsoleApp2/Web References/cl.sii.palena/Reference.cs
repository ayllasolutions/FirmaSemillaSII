﻿//------------------------------------------------------------------------------
// <auto-generated>
//     Este código fue generado por una herramienta.
//     Versión de runtime:4.0.30319.42000
//
//     Los cambios en este archivo podrían causar un comportamiento incorrecto y se perderán si
//     se vuelve a generar el código.
// </auto-generated>
//------------------------------------------------------------------------------

// 
// Microsoft.VSDesigner generó automáticamente este código fuente, versión=4.0.30319.42000.
// 
#pragma warning disable 1591

namespace ConsoleApp2.cl.sii.palena {
    using System.Diagnostics;
    using System;
    using System.Xml.Serialization;
    using System.ComponentModel;
    using System.Web.Services.Protocols;
    using System.Web.Services;
    
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Web.Services.WebServiceBindingAttribute(Name="CrSeedSoapBinding", Namespace="http://DefaultNamespace")]
    public partial class CrSeedService : System.Web.Services.Protocols.SoapHttpClientProtocol {
        
        private System.Threading.SendOrPostCallback getVersionMayorOperationCompleted;
        
        private System.Threading.SendOrPostCallback getVersionPatchOperationCompleted;
        
        private System.Threading.SendOrPostCallback getVersionMenorOperationCompleted;
        
        private System.Threading.SendOrPostCallback getSeedOperationCompleted;
        
        private System.Threading.SendOrPostCallback getStateOperationCompleted;
        
        private bool useDefaultCredentialsSetExplicitly;
        
        /// <remarks/>
        public CrSeedService() {
            this.Url = global::ConsoleApp2.Properties.Settings.Default.ConsoleApp2_cl_sii_palena_CrSeedService;
            if ((this.IsLocalFileSystemWebService(this.Url) == true)) {
                this.UseDefaultCredentials = true;
                this.useDefaultCredentialsSetExplicitly = false;
            }
            else {
                this.useDefaultCredentialsSetExplicitly = true;
            }
        }
        
        public new string Url {
            get {
                return base.Url;
            }
            set {
                if ((((this.IsLocalFileSystemWebService(base.Url) == true) 
                            && (this.useDefaultCredentialsSetExplicitly == false)) 
                            && (this.IsLocalFileSystemWebService(value) == false))) {
                    base.UseDefaultCredentials = false;
                }
                base.Url = value;
            }
        }
        
        public new bool UseDefaultCredentials {
            get {
                return base.UseDefaultCredentials;
            }
            set {
                base.UseDefaultCredentials = value;
                this.useDefaultCredentialsSetExplicitly = true;
            }
        }
        
        /// <remarks/>
        public event getVersionMayorCompletedEventHandler getVersionMayorCompleted;
        
        /// <remarks/>
        public event getVersionPatchCompletedEventHandler getVersionPatchCompleted;
        
        /// <remarks/>
        public event getVersionMenorCompletedEventHandler getVersionMenorCompleted;
        
        /// <remarks/>
        public event getSeedCompletedEventHandler getSeedCompleted;
        
        /// <remarks/>
        public event getStateCompletedEventHandler getStateCompleted;
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapRpcMethodAttribute("", RequestNamespace="http://DefaultNamespace", ResponseNamespace="http://DefaultNamespace")]
        [return: System.Xml.Serialization.SoapElementAttribute("getVersionMayorReturn")]
        public string getVersionMayor() {
            object[] results = this.Invoke("getVersionMayor", new object[0]);
            return ((string)(results[0]));
        }
        
        /// <remarks/>
        public void getVersionMayorAsync() {
            this.getVersionMayorAsync(null);
        }
        
        /// <remarks/>
        public void getVersionMayorAsync(object userState) {
            if ((this.getVersionMayorOperationCompleted == null)) {
                this.getVersionMayorOperationCompleted = new System.Threading.SendOrPostCallback(this.OngetVersionMayorOperationCompleted);
            }
            this.InvokeAsync("getVersionMayor", new object[0], this.getVersionMayorOperationCompleted, userState);
        }
        
        private void OngetVersionMayorOperationCompleted(object arg) {
            if ((this.getVersionMayorCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.getVersionMayorCompleted(this, new getVersionMayorCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapRpcMethodAttribute("", RequestNamespace="http://DefaultNamespace", ResponseNamespace="http://DefaultNamespace")]
        [return: System.Xml.Serialization.SoapElementAttribute("getVersionPatchReturn")]
        public string getVersionPatch() {
            object[] results = this.Invoke("getVersionPatch", new object[0]);
            return ((string)(results[0]));
        }
        
        /// <remarks/>
        public void getVersionPatchAsync() {
            this.getVersionPatchAsync(null);
        }
        
        /// <remarks/>
        public void getVersionPatchAsync(object userState) {
            if ((this.getVersionPatchOperationCompleted == null)) {
                this.getVersionPatchOperationCompleted = new System.Threading.SendOrPostCallback(this.OngetVersionPatchOperationCompleted);
            }
            this.InvokeAsync("getVersionPatch", new object[0], this.getVersionPatchOperationCompleted, userState);
        }
        
        private void OngetVersionPatchOperationCompleted(object arg) {
            if ((this.getVersionPatchCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.getVersionPatchCompleted(this, new getVersionPatchCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapRpcMethodAttribute("", RequestNamespace="http://DefaultNamespace", ResponseNamespace="http://DefaultNamespace")]
        [return: System.Xml.Serialization.SoapElementAttribute("getVersionMenorReturn")]
        public string getVersionMenor() {
            object[] results = this.Invoke("getVersionMenor", new object[0]);
            return ((string)(results[0]));
        }
        
        /// <remarks/>
        public void getVersionMenorAsync() {
            this.getVersionMenorAsync(null);
        }
        
        /// <remarks/>
        public void getVersionMenorAsync(object userState) {
            if ((this.getVersionMenorOperationCompleted == null)) {
                this.getVersionMenorOperationCompleted = new System.Threading.SendOrPostCallback(this.OngetVersionMenorOperationCompleted);
            }
            this.InvokeAsync("getVersionMenor", new object[0], this.getVersionMenorOperationCompleted, userState);
        }
        
        private void OngetVersionMenorOperationCompleted(object arg) {
            if ((this.getVersionMenorCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.getVersionMenorCompleted(this, new getVersionMenorCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapRpcMethodAttribute("", RequestNamespace="http://DefaultNamespace", ResponseNamespace="http://DefaultNamespace")]
        [return: System.Xml.Serialization.SoapElementAttribute("getSeedReturn")]
        public string getSeed() {
            object[] results = this.Invoke("getSeed", new object[0]);
            return ((string)(results[0]));
        }
        
        /// <remarks/>
        public void getSeedAsync() {
            this.getSeedAsync(null);
        }
        
        /// <remarks/>
        public void getSeedAsync(object userState) {
            if ((this.getSeedOperationCompleted == null)) {
                this.getSeedOperationCompleted = new System.Threading.SendOrPostCallback(this.OngetSeedOperationCompleted);
            }
            this.InvokeAsync("getSeed", new object[0], this.getSeedOperationCompleted, userState);
        }
        
        private void OngetSeedOperationCompleted(object arg) {
            if ((this.getSeedCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.getSeedCompleted(this, new getSeedCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        [System.Web.Services.Protocols.SoapRpcMethodAttribute("", RequestNamespace="http://DefaultNamespace", ResponseNamespace="http://DefaultNamespace")]
        [return: System.Xml.Serialization.SoapElementAttribute("getStateReturn")]
        public string getState() {
            object[] results = this.Invoke("getState", new object[0]);
            return ((string)(results[0]));
        }
        
        /// <remarks/>
        public void getStateAsync() {
            this.getStateAsync(null);
        }
        
        /// <remarks/>
        public void getStateAsync(object userState) {
            if ((this.getStateOperationCompleted == null)) {
                this.getStateOperationCompleted = new System.Threading.SendOrPostCallback(this.OngetStateOperationCompleted);
            }
            this.InvokeAsync("getState", new object[0], this.getStateOperationCompleted, userState);
        }
        
        private void OngetStateOperationCompleted(object arg) {
            if ((this.getStateCompleted != null)) {
                System.Web.Services.Protocols.InvokeCompletedEventArgs invokeArgs = ((System.Web.Services.Protocols.InvokeCompletedEventArgs)(arg));
                this.getStateCompleted(this, new getStateCompletedEventArgs(invokeArgs.Results, invokeArgs.Error, invokeArgs.Cancelled, invokeArgs.UserState));
            }
        }
        
        /// <remarks/>
        public new void CancelAsync(object userState) {
            base.CancelAsync(userState);
        }
        
        private bool IsLocalFileSystemWebService(string url) {
            if (((url == null) 
                        || (url == string.Empty))) {
                return false;
            }
            System.Uri wsUri = new System.Uri(url);
            if (((wsUri.Port >= 1024) 
                        && (string.Compare(wsUri.Host, "localHost", System.StringComparison.OrdinalIgnoreCase) == 0))) {
                return true;
            }
            return false;
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    public delegate void getVersionMayorCompletedEventHandler(object sender, getVersionMayorCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class getVersionMayorCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal getVersionMayorCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string)(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    public delegate void getVersionPatchCompletedEventHandler(object sender, getVersionPatchCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class getVersionPatchCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal getVersionPatchCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string)(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    public delegate void getVersionMenorCompletedEventHandler(object sender, getVersionMenorCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class getVersionMenorCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal getVersionMenorCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string)(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    public delegate void getSeedCompletedEventHandler(object sender, getSeedCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class getSeedCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal getSeedCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string)(this.results[0]));
            }
        }
    }
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    public delegate void getStateCompletedEventHandler(object sender, getStateCompletedEventArgs e);
    
    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Web.Services", "4.8.9032.0")]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    public partial class getStateCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs {
        
        private object[] results;
        
        internal getStateCompletedEventArgs(object[] results, System.Exception exception, bool cancelled, object userState) : 
                base(exception, cancelled, userState) {
            this.results = results;
        }
        
        /// <remarks/>
        public string Result {
            get {
                this.RaiseExceptionIfNecessary();
                return ((string)(this.results[0]));
            }
        }
    }
}

#pragma warning restore 1591