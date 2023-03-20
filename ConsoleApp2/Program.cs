using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using System.Net;
using ConsoleApp2.ServiceReference;



namespace ConsoleApp2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)(0xc0 | 0x300 | 0xc00);

            cl.sii.palena.CrSeedService SiiServiceCeed = new cl.sii.palena.CrSeedService();
            string Sem = SiiServiceCeed.getSeed();
            
            
            Firma firma = new Firma(@"C:\git\15485048-1.p12", "password certificado");

            // xml no firmado
            string semilla = "<getToken><item><Semilla>095891399784</Semilla></item></getToken>";
            string unsignedXml = semilla;

            // xml firmado
            string signedXml = firma.Firmar(unsignedXml, referenceUri: "", addTransform: true);

            string hola = signedXml;

            cl.sii.palenatoken.GetTokenFromSeedService SiiServiceToken = new cl.sii.palenatoken.GetTokenFromSeedService();
            string response = SiiServiceToken.getToken(signedXml);


            Console.WriteLine(response);
        }
    }

    public class Firma
    {
            private X509Certificate2 certificado { get; set; }

            public Firma(string certificatePath, string password)
            {
                certificado = new X509Certificate2(certificatePath, password);
            }

            ///
            /// Se le pasa un xml en string y lo devuelve firmado
            /// 

            /// xml no firmado
            /// si se quiere firmar una parte del xml se debe poner el #id, si no: ""
            /// para firmar semilla se requiere, para firmar envioDTE y DTE no se requiere
            public string Firmar(string xml, string referenceUri, bool addTransform)
            {
                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.PreserveWhitespace = true;
                xmlDocument.LoadXml(xml);

                SignedXml signedXml = new SignedXml(xmlDocument);
                signedXml.SigningKey = certificado.PrivateKey;

                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new RSAKeyValue((RSA)certificado.PrivateKey));
                keyInfo.AddClause(new KeyInfoX509Data(certificado));

                Reference reference = new Reference();
                reference.Uri = referenceUri;

                if (addTransform)
                {
                    reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                }

                Signature signature = signedXml.Signature;
                signature.SignedInfo.AddReference(reference);
                signature.KeyInfo = keyInfo;

                // Generar firma
                signedXml.ComputeSignature();
       

                // Insertar la firma en xmlDocument
                xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(signedXml.GetXml(), true));

                return xmlDocument.InnerXml;
            }
    }
}
