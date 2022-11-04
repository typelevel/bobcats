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

///*
// * Copyright 2021 Typelevel
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// *     http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
//
package bobcats

import bobcats.util.WebCryptoPEMUtils
import munit.CatsEffectSuite

import scala.util.Success

//todo: thos test only makes sense for Java at present as BouncyCastle actually
// parses the content. Move to Java.
class JSBasicSignerSuite extends CatsEffectSuite {

  test("parse `test-key-rsa`") {
//		assertIO(IO(4),4)
    assertEquals(
      WebCryptoPEMUtils
        .getPrivateKeySpec(
          bobcats.HttpMessageSignaturesV07.`test-key-rsa`.privatePk8Key,
          bobcats.AsymmetricKeyAlg.RSA_PKCS_Key
        )
        .map(pk => pk.algorithm),
      Success(AsymmetricKeyAlg.RSA_PKCS_Key)
    )
  }

  test("parse `test-key-rsa-pss`") {
    assertEquals(
      WebCryptoPEMUtils
        .getPrivateKeySpec(
          bobcats.HttpMessageSignaturesV07.`test-key-rsa-pss`.privatePk8Key,
          AsymmetricKeyAlg.RSA_PSS_Key
        )
        .map(pk => pk.algorithm),
      Success(AsymmetricKeyAlg.RSA_PSS_Key)
    )
  }

  test("parse `test-key-ecc-p256`") {
    assertEquals(
      WebCryptoPEMUtils
        .getPrivateKeySpec(
          bobcats.HttpMessageSignaturesV07.`test-key-ecc-p256`.privatePk8Key,
          AsymmetricKeyAlg.ECKey(bobcats.AsymmetricKeyAlg.`P-256`)
        )
        .map(pk => pk.algorithm),
      Success(AsymmetricKeyAlg.ECKey(bobcats.AsymmetricKeyAlg.`P-256`))
    )
  }

}
