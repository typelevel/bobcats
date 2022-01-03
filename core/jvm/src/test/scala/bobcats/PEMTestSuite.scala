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

  SigningHttpMessages.keyExamples.foreach(testPEM)

  def testPEM(pem: TestKeyPair): Unit = {
    test(s"${pem.description}: test spec public key matches calculated spki key") {
      val pubkeyTry: Try[security.PublicKey] = pemutils.PEMToPublicKey(pem.publicKey)
      assert(pubkeyTry.isSuccess)
      val pubkey = pubkeyTry.get
      assertEquals(pubkey.getAlgorithm, PEMNamesForKey(pem))
      assertEquals(pubkey.getFormat, "X.509")
      assertEquals(
        pemutils.toSPKI(pubkey).trim,
        pem.publicKeyNew,
        s"original key value was: " + pem.publicKey
      )

    }
    test(s"${pem.description}: test spec private key matches calculated pkcs8 key") {
      val privkeyTry: Try[security.PrivateKey] = pemutils.PEMtoPrivateKey(pem.privateKey)
      assert(privkeyTry.isSuccess)
      val privkey = privkeyTry.get
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
      case _: Alg.RSA => "RSA"
    }
  }
}
