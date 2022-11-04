/*
 * Copyright 2021 Typelevel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bobcats

import bobcats.{AsymmetricKeyAlg => Alg}

import java.security
import scala.util.Try

class PEMTestSuite extends munit.FunSuite {
  import util.{BouncyJavaPEMUtils => pemutils}

  HttpMessageSignaturesV07.keyExamples.foreach(testPEM)

  def testPEM(pem: TestKeyPair): Unit = {
    test(s"${pem.description}: test spec public key matches calculated spki key") {
      val pubkeyTry: Try[security.PublicKey] = pemutils.PEMToPublicKey(pem.publicKey)
//      pubkeyTry.foreach(key => println(s"${pem.description}:\n" + pemutils.toSPKI(key)))
      assert(pubkeyTry.isSuccess)
      val pubkey = pubkeyTry.get
      if (bobcats.AsymmetricKeyAlg.Ed25519_Key != pem.keyAlg) // see PEMNamesForKey
        assertEquals(pubkey.getAlgorithm, PEMNamesForKey(pem))
      assertEquals(pubkey.getFormat, "X.509")
      assertEquals(
        pemutils.toSPKI(pubkey).trim,
        pem.publicPk8Key,
        s"original key value was: " + pem.publicKey
      )

    }
    test(s"${pem.description}: test spec private key matches calculated pkcs8 key") {
      val privkeyTry: Try[security.PrivateKey] = pemutils.PEMtoPrivateKey(pem.privateKey)
//      privkeyTry.foreach(key => println(s"private key ${pem.description}:\n" + pemutils.toPKCS8(key)))
      assert(privkeyTry.isSuccess)
      val privkey = privkeyTry.get
      if (bobcats.AsymmetricKeyAlg.Ed25519_Key != pem.keyAlg) // see PEMNamesForKey fn
        assertEquals(privkey.getAlgorithm, PEMNamesForKey(pem))
      assertEquals(privkey.getFormat, "PKCS#8")
      assertEquals(
        pemutils.toPKCS8(privkey).trim,
        pem.privatePk8Key,
        s"original key value was: " + pem.privateKey
      )
    }
  }

  private def PEMNamesForKey(pem: TestKeyPair): String = {
    pem.keyAlg match {
      case _: Alg.EC => "ECDSA"
      case Alg.RSA_PSS_Key => "RSA"
      case Alg.Ed25519_Key => "Ed25519" // weird some platforms return "Ed25519_Key"
      case _: Alg.RSA => "RSA"
    }
  }
}
