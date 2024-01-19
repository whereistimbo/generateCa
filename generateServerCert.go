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
   "crypto"
   "net"
   "crypto/x509/pkix"
   "encoding/asn1"
   "crypto/sha256"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/rand"
   "math/big"
   "time"
   "bytes"
)

func main() {

   //command line args
   var intCaPEMFileLoc = flag.String("intCa", "intCa.pem", "intCa PEM location")
   var intCaPrivKeyPEMFileLoc = flag.String("intCaPrivKey", "intCaPrivKey.pem", "intCaPrivKey PEM location")
   flag.Parse()

   //open the intCaPEM using the previous command line args
   intCaPEM, err := os.ReadFile(*intCaPEMFileLoc)
   if err != nil {
      log.Fatal(err)
   }
   intCaPrivKeyPEM, err := os.ReadFile(*intCaPrivKeyPEMFileLoc)
   if err != nil {
      log.Fatal(err)
   }

   //decode PEM file
   intCaBlock, _ := pem.Decode(intCaPEM)
   if intCaBlock == nil || intCaBlock.Type != "CERTIFICATE" {
      log.Fatal("failed to decode intCa")
   }
   intCaPrivKeyBlock, _ := pem.Decode(intCaPrivKeyPEM)
   if intCaPrivKeyBlock == nil || intCaPrivKeyBlock.Type != "EC PRIVATE KEY" {
      log.Fatal("failed to decode intCaPrivKey")
   }

   //parse certificate and private key
   intCa, _ := x509.ParseCertificate(intCaBlock.Bytes)
   intCaPrivKey, _ := x509.ParseECPrivateKey(intCaPrivKeyBlock.Bytes)

   serverCertPEM, serverCertPrivKeyPEM, _ := generateServerCert(intCa, intCaPrivKey, nil)

   //save intCa to a file
   serverCertPEMFile, _ := os.Create("serverCert.pem")
   _, _ = serverCertPEMFile.Write(serverCertPEM.Bytes())
   serverCertPEMFile.Close()

   //save intCaPrivKey to a file
   serverCertPrivKeyPEMFile, _ := os.Create("serverCertPrivKey.pem")
   _, _ = serverCertPrivKeyPEMFile.Write(serverCertPrivKeyPEM.Bytes())
   serverCertPrivKeyPEMFile.Close()
   
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


func generateServerCert(intCa *x509.Certificate, intCaPrivKey *ecdsa.PrivateKey, serverCertPrivKey *ecdsa.PrivateKey) (*bytes.Buffer, *bytes.Buffer, error) {
   var err error
   // create our private and public key
   if (serverCertPrivKey == nil) {
      serverCertPrivKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
      if err != nil {
         return nil, nil, err
      }  
   }
   serverCertPrivKeyBytes, err := x509.MarshalECPrivateKey(serverCertPrivKey)
   if err != nil {
      return nil, nil, err
   }
   serverCertskid, err := calculateSKID(&serverCertPrivKey.PublicKey)
   if err != nil {
      return nil, nil, err
   }

   // set up our root CA certificate
   serverCert := &x509.Certificate{
      Version: 1,
      SerialNumber: big.NewInt(2024),
      Subject: pkix.Name{
         Country:       []string{"ID"},
         Organization:  []string{"Klinik Dokter Ananda's WebApp"},
         OrganizationalUnit: []string{"Klinik Dokter Ananda's WebApp"},
         CommonName: "Klinik Dokter Ananda's WebApp",
         Province:      []string{"JB"},
         Locality:      []string{"Depok"},
         StreetAddress: []string{"Kukusan Beji"},
         PostalCode:    []string{"16425"},
      },    
      IPAddresses:  []net.IP{net.IPv4(172, 19, 11, 1), net.IPv6loopback},
      DNSNames: []string{"klinikdrananda.test", "klinikdrananda.localhost", "klinikdrananda.local"},
      NotBefore:             time.Now(),
      NotAfter:              time.Now().AddDate(0, 0, 7),
      IsCA:                  false,
      SubjectKeyId: serverCertskid,
      ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
      KeyUsage:              x509.KeyUsageDigitalSignature,
   }

   // create the serverCert
   serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCert, intCa, &serverCertPrivKey.PublicKey, intCaPrivKey)
   if err != nil {
      return nil, nil, err
   }

   // pem encode serverCert public key
   serverCertPEM := new(bytes.Buffer)
   pem.Encode(serverCertPEM, &pem.Block{
      Type:  "CERTIFICATE",
      Bytes: serverCertBytes,
   })

   //pem encode private key
   serverCertPrivKeyPEM := new(bytes.Buffer)
   pem.Encode(serverCertPrivKeyPEM, &pem.Block{
      Type:  "EC PRIVATE KEY",
      Bytes: serverCertPrivKeyBytes,
   })

   return serverCertPEM, serverCertPrivKeyPEM, err
}