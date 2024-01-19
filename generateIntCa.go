/* 
  
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
---------------------
MIT License

Copyright (c) 2016 Jacob Hoffman-Andrews

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-----------------------------------------------------

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
-----------------
The MIT License (MIT)
Copyright (c) Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and 
associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT 
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
-----------------
https://medium.com/@Raulgzm/export-import-pem-files-in-go-67614624adc7
*/
package main
import (
   "flag"
   "os"
   "log"
   "encoding/pem"
   "crypto/x509"
   "runtime"
   "os/exec"
   "crypto"
   "crypto/x509/pkix"
   "encoding/asn1"
   "crypto/sha256"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "math/big"
   "time"
   "bytes"
   "encoding/base64"
   "fmt"
)

func main() {

   //command line args
   var rootCaPEMFileLoc = flag.String("rootCa", "rootCa.pem", "rootCa PEM location")
   var rootCaPrivKeyPEMFileLoc = flag.String("rootCaPrivKey", "rootCaPrivKey.pem", "rootCaPrivKey PEM location")
   flag.Parse()

   //fmt.Println(*rootCaPEMFileLoc)
   //fmt.Println(*rootCaPrivKeyPEMFileLoc)
   //open the rootCa using the previous command line args
   //rootCaPEMFile, err := os.Open(*rootCaPEMFileLoc)
   //rootCaPrivKeyPEMFile, err := os.Open(*rootCaPrivKeyPEMFileLoc)

   rootCaPEM, err := os.ReadFile(*rootCaPEMFileLoc)
   if err != nil {
      log.Fatal(err)
   }
   //os.Stdout.Write(rootCaPEM)
   rootCaPrivKeyPEM, err := os.ReadFile(*rootCaPrivKeyPEMFileLoc)
   if err != nil {
      log.Fatal(err)
   }
   //os.Stdout.Write(rootCaPrivKeyPEM)
   //read the file and close
   /*var rootCaPEM, rootCaPrivKeyPEM []byte
   _, err := rootCaPEMFile.Read(rootCaPEM)
   _, err := rootCaPrivKeyPEMFile.Read(rootCaPrivKeyPEM)
   rootCaPEMFile.Close()
   rootCaPrivKeyPEMFile.Close()*/

   //decode PEM file
   rootCaBlock, _ := pem.Decode(rootCaPEM)
   if rootCaBlock == nil || rootCaBlock.Type != "CERTIFICATE" {
      log.Fatal("failed to decode rootCa")
   }
   rootCaPrivKeyBlock, _ := pem.Decode(rootCaPrivKeyPEM)
   if rootCaPrivKeyBlock == nil || rootCaPrivKeyBlock.Type != "EC PRIVATE KEY" {
      log.Fatal("failed to decode rootCaPrivKey")
   }

   //parse certificate and private key
   rootCa, _ := x509.ParseCertificate(rootCaBlock.Bytes)
   rootCaPrivKey, _ := x509.ParseECPrivateKey(rootCaPrivKeyBlock.Bytes)

   //fmt.Println(rootCa, rootCaPrivKey)

   intCaPEM, intCaPrivKeyPEM, _ := generateIntCA(rootCa, rootCaPrivKey, nil)
   fmt.Println("here")

   //save intCa to a file
   intCaPEMFile, _ := os.Create("intCa.pem")
   _, _ = intCaPEMFile.Write(intCaPEM.Bytes())
   intCaPEMFile.Close()
   fmt.Println("here2")
   //_ = intCaPrivKeyPEM

   //save intCaPrivKey to a file
   intCaPrivKeyPEMFile, _ := os.Create("intCaPrivKey.pem")
   _, _ = intCaPrivKeyPEMFile.Write(intCaPrivKeyPEM.Bytes())
   intCaPrivKeyPEMFile.Close()
   fmt.Println("here2")

   //load rootCa to Windows Certificate list using cmd and Powershell  
   if runtime.GOOS == "windows" {
      windowsPwshAddCertificate(intCaPEM)
      fmt.Println("here3")
   }

   
}

func calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
   spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
   if err != nil {
      return nil, err
   }
   var spki struct {
      Algorithm        pkix.AlgorithmIdentifier
      SubjectPublicKey asn1.BitString
   }
   _, err = asn1.Unmarshal(spkiASN1, &spki)
   if err != nil {
      return nil, err
   }
   skidsha256sum := sha256.New()
   skidsha256sum.Write(spki.SubjectPublicKey.Bytes)
   skid := skidsha256sum.Sum(nil)
   return skid[:], err
}


func generateIntCA(rootCa *x509.Certificate, rootCaPrivKey *ecdsa.PrivateKey, intCaPrivKey *ecdsa.PrivateKey) (*bytes.Buffer, *bytes.Buffer, error) {
   var err error
   // create our private and public key
   if (intCaPrivKey == nil) {
      intCaPrivKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
      if err != nil {
         return nil, nil, err
      }  
   }
   intCaPrivKeyBytes, err := x509.MarshalECPrivateKey(intCaPrivKey)
   if err != nil {
      return nil, nil, err
   }
   intCaskid, err := calculateSKID(&intCaPrivKey.PublicKey)
   if err != nil {
      return nil, nil, err
   }

   // set up our root CA certificate
   intCa := &x509.Certificate{
      Version: 1,
      SerialNumber: big.NewInt(2024),
      Subject: pkix.Name{
         Country:       []string{"ID"},
         Organization:  []string{"Klinik Dokter Ananda's CA"},
         OrganizationalUnit: []string{"Klinik Dokter Ananda's Intermediate CA"},
         CommonName: "Klinik Dokter Ananda's Intermediate CA",
         Province:      []string{"JB"},
         Locality:      []string{"Depok"},
         StreetAddress: []string{"Kukusan Beji"},
         PostalCode:    []string{"16425"},
      },
      NotBefore:             time.Now(),
      NotAfter:              time.Now().AddDate(1, 1, 0),
      IsCA:                  true,
      SubjectKeyId: intCaskid,
      KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign |
      x509.KeyUsageCRLSign,
      BasicConstraintsValid: true,
   }

   // create the CA
   rootCaBytes, err := x509.CreateCertificate(rand.Reader, intCa, rootCa, &intCaPrivKey.PublicKey, rootCaPrivKey)
   if err != nil {
      return nil, nil, err
   }

   // pem encode cert public key
   intCaPEM := new(bytes.Buffer)
   pem.Encode(intCaPEM, &pem.Block{
      Type:  "CERTIFICATE",
      Bytes: rootCaBytes,
   })

   //pem encode private key
   intCaPrivKeyPEM := new(bytes.Buffer)
   pem.Encode(intCaPrivKeyPEM, &pem.Block{
      Type:  "EC PRIVATE KEY",
      Bytes: intCaPrivKeyBytes,
   })

   return intCaPEM, intCaPrivKeyPEM, err
}
func windowsPwshAddCertificate(intCaPEM *bytes.Buffer) {
   intCaBase64 := base64.StdEncoding.EncodeToString(intCaPEM.Bytes())
   fmt.Println(intCaBase64)
   cmd_intCa := exec.Command("powershell", "-command", 
      "$intca = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String(\""+ intCaBase64 +"\"));", 
      "$intstore = [System.Security.Cryptography.X509Certificates.X509Store]::new(\"CA\",\"CurrentUser\");",
      "$intstore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);",
      "$intstore.Add($intca)")
   _ = cmd_intCa.Run()
}