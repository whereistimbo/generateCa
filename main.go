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
   "crypto"
   "crypto/x509"
   "crypto/x509/pkix"
   "encoding/asn1"
   "crypto/sha256"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "time"
   "encoding/pem"
   "bytes"
   "encoding/base64"
   "os"
   "os/exec"
   "runtime"
)

func main() {
   rootCaPEM, rootCaPrivKeyPEM, _ := generateRootCA(nil)

   //save rootCa to a file
   rootCaPEMFile, err := os.Create("rootCa.pem")
   _, err = rootCaPEMFile.Write(rootCaPEM.Bytes())
   rootCaPEMFile.Close()

   /*
   //save rootCaPrivKey to a file
   rootCaPrivKeyPEMFile, err := os.Create("rootCa.pem")
   _, err = rootCaPrivKeyPEMFile.Write(rootCaPrivKeyPEM.Bytes())
   rootCaPEMFile.Close()
   */

   //load rootCa to Windows Certificate list using cmd and Powershell  
   if runtime.GOOS == "windows" {
      windowsPwshAddCertificate(rootCaPEM *Buffer)
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
   skid := sha256.Sum(spki.SubjectPublicKey.Bytes)
   return skid[:], err
}


func generateRootCA(rootCaPrivKey *PrivateKey) (byte[], byte[], err error) {
   
   // create our private and public key
   if (rootCaPrivKey == nil) {
      rootCaPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
      if err != nil {
         return nil, nil, err
      }  
   }
   rootCaPrivKeyBytes, err := x509.MarshalECPrivateKey(rootCaPrivKey)
   if err != nil {
      return nil, nil, err
   }
   rootCaskid, err := calculateSKID(&rootCaPrivKey.PublicKey)
   if err != nil {
      return nil, nil, err
   }

   // set up our root CA certificate
   rootCa := &x509.Certificate{
      Version: 1,
      SerialNumber: big.NewInt(2024),
      Subject: pkix.Name{
         Country:       []string{"ID"},
         Organization:  []string{"Klinik Dokter Ananda's Self Signed CA"},
         OrganizationalUnit: []string{"Klinik Dokter Ananda's Root CA"},
         CommonName: "Klinik Dokter Ananda's Self Signed Root CA",
         Province:      []string{"JB"},
         Locality:      []string{"Depok"},
         StreetAddress: []string{"Kukusan Beji"},
         PostalCode:    []string{"16425"},
      },
      NotBefore:             time.Now(),
      NotAfter:              time.Now().AddDate(1, 1, 0),
      IsCA:                  true,
      SubjectKeyId: rootCaskid,
      KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign |
      x509.KeyUsageCRLSign,
      BasicConstraintsValid: true,
   }

   // create the CA
   rootCaBytes, err := x509.CreateCertificate(rand.Reader, rootCa, rootCa, &rootCaPrivKey.PublicKey, rootCaPrivKey)
   if err != nil {
      return nil, nil, err
   }

   // pem encode cert public key
   rootCaPEM := new(bytes.Buffer)
   pem.Encode(rootCaPEM, &pem.Block{
      Type:  "CERTIFICATE",
      Bytes: rootCaBytes,
   })

   //pem encode private key
   rootCaPrivKeyPEM := new(bytes.Buffer)
   pem.Encode(rootCaPrivKeyPEM, &pem.Block{
      Type:  "EC PRIVATE KEY",
      Bytes: rootCaPrivKeyBytes,
   }

   return rootCaPEM, rootCaPrivKeyPEM
}
func windowsPwshAddCertificate(rootCaPEM *Buffer) {
   rootCaBase64 := base64.StdEncoding.EncodeToString(rootCaPEM.Bytes())
   
   cmd_rootCa := exec.Command("powershell", "-command", 
      "$rootca = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String(\""+ rootCaBase64 +"\"));", 
      "$rootstore = [System.Security.Cryptography.X509Certificates.X509Store]::new(\"Root\",\"CurrentUser\");",
      "$rootstore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);",
      "$rootstore.Add($rootca)")
   _ = cmd_rootCa.Run()

}