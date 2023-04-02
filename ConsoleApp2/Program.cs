using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Net;

namespace ConsoleApp2
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Habilita el ambiente de desarrollo para consultar servicios Https
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)(0xc0 | 0x300 | 0xc00);

            // Instancio la referencia web del servicio de impuestos internos para obtener la semilla
            cl.sii.palena.CrSeedService SiiServiceCeed = new cl.sii.palena.CrSeedService();
            string Sem = SiiServiceCeed.getSeed();
            
            // Obtiene el certificado digital, necesario para firmar el xml. Este certificado debe tenerlo
            // todo contribuyente que emita documentos tributarios.
            // Junto con obtener el certificado(En el constructor de la clase), se esta instacionado un objeto de la clase Firma
            Firma firma = new Firma(@"C:\git\15485048-1.p12", "password certificado");

            // Se arma la primera parte del Xml segun la "especificacion(xd)" del servicio de impuestos internos.
            // Dicha especificacion se encuentra en este link:
            // https://www.sii.cl/factura_electronica/factura_mercado/autenticacion.pdf
            string semilla = "<getToken><item><Semilla>"+ Sem + "</Semilla></item></getToken>";
            
            // Se nombra variable como XMl no firmado
            string unsignedXml = semilla;

            // Se asigna la variable con el resultado del metodo Firmar del objeto firma
            string signedXml = firma.Firmar(unsignedXml, referenceUri: "", addTransform: true);

            
            // Una vez que el XML ya esta firmado, se instacia la referencia web del servicio obtener token tambien
            // perteneciente al servicio de impuestos internos.
            cl.sii.palenatoken.GetTokenFromSeedService SiiServiceToken = new cl.sii.palenatoken.GetTokenFromSeedService();
            
            //Se asigna el resultado de la llamada al servicio de obtencion de token, a la variable string. 
            //Esta variable contiene el token necesario, para autenticarse y consumir los demas servicios del SII.
            string response = SiiServiceToken.getToken(signedXml);

            //Se muestra por pantalla el resultado.
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
