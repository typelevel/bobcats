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

import scala.util.Success

class PEMTestSuite extends munit.FunSuite {
	import util.{BouncyJavaPEMUtils => pemutils}

	SigningHttpMessages.keyExamples.foreach(testPEM)

	def testPEM(pem: TestKeys): Unit = {
		test(s"${pem.description}: test spec public key matches calculated spki key") {
			assertEquals(
				pemutils.PEMToPublicKey(pem.publicKey).map(pemutils.toSPKI).map(_.trim),
				Success(pem.publicKeyNew),
				s"original key value was: "+pem.publicKey
			)
		}
		test(s"${pem.description}: test spec priave key matches calculated pkcs8 key") {
			assertEquals(
				pemutils.PEMtoPrivateKey(pem.privateKey).map(pemutils.toPKCS8).map(_.trim),
				Success(pem.privatePk8Key),
				s"original key value was: "+pem.privateKey
			)
		}

	}

}
