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

object SignatureExample {
  type SigningString = String
  type Signature = String
  type Base64Bytes = String

  type PrivateKeyPEM = String
  type PublicKeyPEM = String
}

import SignatureExample.{Base64Bytes, Signature, SigningString}

sealed trait SigExample

/**
 * Collects a number of signatures for a given Key
 */
case class SignatureExample(
    description: String,
    sigtext: SigningString,
    signature: Signature,
    keypair: TestKeyPair,
    signatureAlg: AsymmetricKeyAlg.Signature
) extends SigExample

case class SymmetricSignatureExample(
    description: String,
    sigtext: SigningString,
    signature: Signature,
    key: TestSharedKey,
    signatureAlg: HmacAlgorithm
) extends SigExample

trait AsymmetricKeyExamples {
  def sigExamples: Seq[SignatureExample]
  def keyExamples: Set[TestKeyPair] = sigExamples.map(_.keypair).toSet
}

trait SymmetricKeyExamples {
  def symSignExamples: Seq[SymmetricSignatureExample]
  def sharedKeyExamples: Set[TestSharedKey] = symSignExamples.map(_.key).toSet
}

sealed trait TestKey {
  def description: String
}

/**
 * Public and Private keys grouped together as in
 * [[https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures HTTP Message Signatures §Appendix B.1]]
 * Obviously, these should not be used other than for test cases! So place them here to make
 * them available in other tests.
 */
trait TestKeyPair extends TestKey {
  import SignatureExample.{PrivateKeyPEM, PublicKeyPEM}

  // the keys in the Signing HTTP messages Spec are PEM encoded.
  // One could transform the keys from PKCS#1 to PKCS#8 using
  // openssl pkcs8 -topk8 -inform PEM -in spec.private.pem -out private.pem -nocrypt
  // see https://stackoverflow.com/questions/6559272/algid-parse-error-not-a-sequence
  // but then it would not be easy to compare the keys used here with those in the
  // spec when debugging the tests, and it would make it more difficult to send in
  // feedback to the IETF HttpBis WG.
  /**
   * here we put the key from the spec
   */
  def privateKey: PrivateKeyPEM

  // PKCS8 version of the private key
  // there have been problems with keys in JS explained
  // https://github.com/httpwg/http-extensions/issues/1867
  /**
   * place the pkcs8 equivalent key here
   */
  def privatePk8Key: PrivateKeyPEM = privateKey

  def publicKey: PublicKeyPEM

  def publicPk8Key: PublicKeyPEM = publicKey

  def keyAlg: AsymmetricKeyAlg
}

trait TestSharedKey extends TestKey {
  def sharedKey: Base64Bytes
}
