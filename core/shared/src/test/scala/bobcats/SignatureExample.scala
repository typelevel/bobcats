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

import bobcats.SignatureExample.{Signature, SigningString}


object SignatureExample {
	type SigningString = String
	type Signature = String
	type PrivateKeyPEM = String
	type PublicKeyPEM = String
}

case class SignatureExample(
  description: String,
  sigtext: SigningString,
  signature: Signature,
  keys: TestKeys,
  signatureAlg: AsymmetricKeyAlg.Signature,
)
{
	//		def sigtest(keys: TestKeys, sig: PKA.Signature): SignatureTest =
	//			SignatureTest(sigtext, signature, keys.privateKeySpec, sig, keys.publicKeySpec, description)
}

trait SignatureExamples {
	def signatureExamples: Seq[SignatureExample]
}


//	case class SignatureTest(
//	  text: SignatureTest.SigningString,  sig: SignatureTest.Signature,
//	  privateKeySpec: Try[PrivateKeySpec[_]], alg: PKA.Signature,
//	  pubKeySpec: Try[PublicKeySpec[_]],
//	  description: String
//	)
//


object X {
//	lazy val privateKeySpec: Try[PrivateKeySpec[_]] = pem.getPrivateKeyFromPEM(privateKey)
//
//	lazy val publicKeySpec: Try[PublicKeySpec[_]] = pem.getPublicKeyFromPEM(publicKey)

}

/**
 * Public and Private keys from [[https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-04.html#section-b.1.1 Message Signatures §Appendix B.1.1]]
 * Obviously, these should not be used other than for test cases!
 * So place them here to make them available in other tests.
 **/
trait TestKeys {
	// the keys in the Signing HTTP messages Spec are PEM encoded.
	// One could transform the keys from PKCS#1 to PKCS#8 using
	// openssl pkcs8 -topk8 -inform PEM -in spec.private.pem -out private.pem -nocrypt
	// see https://stackoverflow.com/questions/6559272/algid-parse-error-not-a-sequence
	// but then it would not be easy to compare the keys used here with those in the
	// spec when debugging the tests, and it would make it more difficult to send in
	// feedback to the IETF HttpBis WG.

	def privateKey: SignatureExample.PrivateKeyPEM

	// PKCS8 version of the private key
	def privatePk8Key: SignatureExample.PrivateKeyPEM = privateKey

	def publicKey: SignatureExample.PublicKeyPEM

	def publicKeyNew: String = publicKey

	def keyAlg: AsymmetricKeyAlg
}
