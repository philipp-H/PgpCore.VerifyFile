using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace PgpCore.VerifyFile
{
    [TestClass]
    public class TestVerifyFile
    {
        [TestMethod]
        public void GenKeys()
        {
            Directory.CreateDirectory(@"C:\TEMP\Keys\");
            Directory.CreateDirectory(@"C:\TEMP\Content\");
            using (PGP pgp = new PGP())
            {
                pgp.GenerateKey(@"C:\TEMP\Keys\public.asc", @"C:\TEMP\Keys\private.asc", "email@email.com", "password");
            }
        }

        [TestMethod]
        public void WriteContentFile()
        {
            var plainLorem = @"Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et e";

            File.WriteAllText(@"C:\TEMP\Content\content.txt", plainLorem);
        }

        [TestMethod]
        public void SignFile()
        {
            //Load keys
            FileInfo privateKey = new FileInfo(@"C:\TEMP\Keys\private.asc");
            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, "password");

            // Reference input/output files
            FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\content.txt");
            FileInfo signedFile = new FileInfo(@"C:\TEMP\Content\signed.pgp");

            // Sign
            PGP pgp = new PGP(encryptionKeys);
            pgp.SignFile(inputFile, signedFile);
        }

        [TestMethod]
        public void VerifyFile()
        {
            // Load keys
            FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

            // Reference input
            FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signed.pgp");

            // Verify
            PGP pgp = new PGP(encryptionKeys);
            bool verified = pgp.VerifyFile(inputFile);
            Assert.IsTrue(verified);
        }

        [TestMethod]
        public void VerifyFile_BadContent()
        {
            // Load keys
            FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

            var data = File.ReadAllLines(@"C:\TEMP\Content\signed.pgp");

            var lastIndex = data[3].Length - 1;
            //var lastChar = data[lastIndex];
            data[3] = data[3].Substring(0, lastIndex - 1) + "x";
            File.WriteAllLines(@"C:\TEMP\Content\signed-with-bad-content.pgp", data);

            // Reference input
            FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signed-with-bad-content.pgp");

            // Verify
            PGP pgp = new PGP(encryptionKeys);
            bool verified = pgp.VerifyFile(inputFile);
            Assert.IsFalse(verified);
        }

        [TestMethod]
        public void VerifyFile_BadHeader()
        {
            // Load keys
            FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

            var data = File.ReadAllLines(@"C:\TEMP\Content\signed.pgp");
            data[0] = data[0].Remove(0, 1);
            File.WriteAllLines(@"C:\TEMP\Content\signed-with-bad-header.pgp", data);

            // Reference input
            FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signed-with-bad-header.pgp");

            // Verify
            PGP pgp = new PGP(encryptionKeys);
            bool verified = pgp.VerifyFile(inputFile);
            Assert.IsFalse(verified);
        }

        [TestMethod]
        public void VerifyFile_BadTrailing()
        {
            // Load keys
            FileInfo publicKey = new FileInfo(@"C:\TEMP\Keys\public.asc");
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);

            var data = File.ReadAllLines(@"C:\TEMP\Content\signed.pgp");
            var lastIndex = data.Length - 1;
            data[lastIndex] = data[lastIndex].Remove(0, 1);
            File.WriteAllLines(@"C:\TEMP\Content\signed-with-bad-trailing.pgp", data);

            // Reference input
            FileInfo inputFile = new FileInfo(@"C:\TEMP\Content\signed-with-bad-trailing.pgp");

            // Verify
            PGP pgp = new PGP(encryptionKeys);
            bool verified = pgp.VerifyFile(inputFile);
            Assert.IsFalse(verified);
        }
    }
}
