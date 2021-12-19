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

import java.security.Signature

trait SignaturePlatform { self: bobcats.Algorithm =>

	def toJava: java.security.Signature = {
		// how could one get this to be added directly to the object?
		if (this == PKA.`rsa-pss-sha512`) {
			println("using sepecial rsa-pss-sha512 sig")
			// sig is not thread safe, so we can't reuse one

			// the paramters here have to be set manually as below
			// https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#section-3.3.1
			// we will need to have a function on the PKA.Signature objects that returns a signature.

			// from https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html
			// The signature algorithm that uses the RSASSA-PSS signature scheme as defined in
			// [PKCS #1 v2.2] (https://tools.ietf.org/html/rfc8017).
			// Note that this signature algorithm needs parameters such as a digesting algorithm, salt length and MGF1 algorithm, to be supplied before performing the RSA operation.
			val rsapss = Signature.getInstance("RSASSA-PSS")
			rsapss.setParameter(SignerCompanionPlatform.PSS_512_SPEC)
			rsapss
		} else {
			Signature.getInstance(self.toStringJava)
		}
	}
}
