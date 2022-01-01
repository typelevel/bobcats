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

import _root_.com.nimbusds.jose.jwk.JWK


class JWKCryptoSuite extends munit.FunSuite {

	test("transform PEM private to JWK") {
		val jwk = JWK.parseFromPEMEncodedObjects(
			SigningHttpMessages.`test-key-rsa-pss`.privateKey
		)
		println("Private key\n"+jwk.toJSONString)

	}

	test("transform PEM public to JWK") {
		val jwk = JWK.parseFromPEMEncodedObjects(
			SigningHttpMessages.`test-key-rsa-pss`.publicKey
		)
		println("Public key\n"+jwk.toJSONString)

	}
}
